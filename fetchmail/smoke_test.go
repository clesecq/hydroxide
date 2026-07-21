package fetchmail

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// fakeSMTPServer is a minimal hand-rolled SMTP server good enough to
// exercise deliver()'s MAIL/RCPT/DATA sequence without STARTTLS/AUTH.
func fakeSMTPServer(t *testing.T, received chan<- string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		w := conn

		w.Write([]byte("220 fake.relay ESMTP\r\n"))

		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimRight(line, "\r\n") == "." {
					inData = false
					received <- data.String()
					w.Write([]byte("250 OK\r\n"))
					continue
				}
				data.WriteString(line)
				continue
			}

			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"):
				w.Write([]byte("250-fake.relay\r\n250 8BITMIME\r\n"))
			case strings.HasPrefix(upper, "MAIL FROM"):
				w.Write([]byte("250 OK\r\n"))
			case strings.HasPrefix(upper, "RCPT TO"):
				w.Write([]byte("250 OK\r\n"))
			case strings.HasPrefix(upper, "DATA"):
				inData = true
				w.Write([]byte("354 Go ahead\r\n"))
			case strings.HasPrefix(upper, "QUIT"):
				w.Write([]byte("221 Bye\r\n"))
				return
			default:
				w.Write([]byte("500 unrecognized\r\n"))
			}
		}
	}()

	return ln.Addr().String()
}

func TestDeliver(t *testing.T) {
	received := make(chan string, 1)
	addr := fakeSMTPServer(t, received)
	host, port, _ := net.SplitHostPort(addr)

	cfg := &Config{
		SMTPHost:     host,
		SMTPPort:     port,
		SMTPStartTLS: false,
	}

	body := []byte("Subject: test\r\n\r\nHello world\r\n")
	if err := deliver(cfg, "sender@example.com", []string{"rcpt@example.com"}, body); err != nil {
		t.Fatalf("deliver failed: %v", err)
	}

	got := <-received
	if !strings.Contains(got, "Hello world") {
		t.Fatalf("relay did not receive expected body, got: %q", got)
	}
}

func TestResolveFolders(t *testing.T) {
	labels, err := ResolveFolders(nil)
	if err != nil || len(labels) != 1 || labels[0] != "0" {
		t.Fatalf("expected default Inbox label, got %v, %v", labels, err)
	}

	labels, err = ResolveFolders([]string{"Archive", " sent "})
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %v", labels)
	}

	if _, err := ResolveFolders([]string{"NotAFolder"}); err == nil {
		t.Fatal("expected an error for an unknown folder name")
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := t.TempDir() + "/fetchids.json"

	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Messages) != 0 {
		t.Fatalf("expected empty state for missing file, got %v", s.Messages)
	}

	s.Messages["msg1"] = MessageState{Time: 100, ForwardedAt: 200}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	s2, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Messages["msg1"].ForwardedAt != 200 {
		t.Fatalf("state did not round-trip: %v", s2.Messages)
	}
}
