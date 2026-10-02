package smtp

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"

	"github.com/emersion/hydroxide/protonmail"
)

func newPublicKey(t *testing.T, email string, flags protonmail.PublicKeyFlags) (*protonmail.PublicKey, *openpgp.Entity) {
	t.Helper()

	e, err := openpgp.NewEntity("", "", email, nil)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return &protonmail.PublicKey{Flags: flags, PublicKey: b.String()}, e
}

func TestRecipientKey(t *testing.T) {
	active := protonmail.PublicKeyTrusted | protonmail.PublicKeyActive
	obsolete, _ := newPublicKey(t, "obsolete@example.org", protonmail.PublicKeyTrusted)
	current, currentEntity := newPublicKey(t, "current@example.org", active)

	t.Run("internal", func(t *testing.T) {
		pub, err := recipientKey(&protonmail.PublicKeyResp{
			RecipientType: protonmail.RecipientInternal,
			Keys:          []*protonmail.PublicKey{obsolete, current},
		})
		if err != nil {
			t.Fatal(err)
		}
		if pub == nil || pub.PrimaryKey.KeyId != currentEntity.PrimaryKey.KeyId {
			t.Errorf("got %v, want the first active key", pub)
		}
	})

	t.Run("internal without active key", func(t *testing.T) {
		_, err := recipientKey(&protonmail.PublicKeyResp{
			RecipientType: protonmail.RecipientInternal,
			Keys:          []*protonmail.PublicKey{obsolete},
		})
		if err == nil {
			t.Error("expected an error")
		}
	})

	for name, keys := range map[string][]*protonmail.PublicKey{
		"external":          nil,
		"external with WKD": {current},
	} {
		t.Run(name, func(t *testing.T) {
			pub, err := recipientKey(&protonmail.PublicKeyResp{
				RecipientType: protonmail.RecipientExternal,
				Keys:          keys,
			})
			if err != nil {
				t.Fatal(err)
			}
			if pub != nil {
				t.Error("external recipients must get cleartext")
			}
		})
	}
}

func addressStrings(addrs []*mail.Address) []string {
	var l []string
	for _, addr := range addrs {
		l = append(l, addr.Address)
	}
	return l
}

func TestSplitRecipients(t *testing.T) {
	to := []*mail.Address{
		{Name: "Alice", Address: "Alice@example.org"},
		{Address: "header-only@example.org"},
	}
	cc := []*mail.Address{
		{Address: "carol@example.org"},
		{Address: "alice@example.org"},
	}
	rcpt := []string{"alice@example.org", "bob@example.org", "carol@example.org", "BOB@example.org"}

	toList, ccList, bccList, dropped := splitRecipients(rcpt, to, cc)

	for _, tc := range []struct {
		name      string
		got, want []string
	}{
		{"to", addressStrings(toList), []string{"Alice@example.org"}},
		{"cc", addressStrings(ccList), []string{"carol@example.org"}},
		{"bcc", addressStrings(bccList), []string{"bob@example.org"}},
		{"dropped", addressStrings(dropped), []string{"header-only@example.org"}},
	} {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%v: got %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if toList[0].Name != "Alice" {
		t.Errorf("display name lost: %q", toList[0].Name)
	}
}

func TestWalkParts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		msg         string
		bodyType    string
		body        string
		attachments []string // Content-Type and content of each attachment
	}{
		{
			name:     "no Content-Type",
			msg:      "Subject: [PATCH] f: add b\r\n\r\n---\r\n+b\r\n",
			bodyType: "text/plain",
			body:     "---\r\n+b\r\n",
		},
		{
			name: "format-patch --inline",
			msg: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: text/plain; charset=UTF-8; format=fixed\r\n\r\nf: add b\r\n" +
				"--b\r\nContent-Type: text/x-patch; name=\"0001-f.patch\"\r\n" +
				"Content-Disposition: inline; filename=\"0001-f.patch\"\r\n\r\n+b\r\n" +
				"--b--\r\n",
			bodyType:    "text/plain",
			body:        "f: add b",
			attachments: []string{"text/x-patch: +b"},
		},
		{
			name: "format-patch --attach",
			msg: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nf: add b\r\n" +
				"--b\r\nContent-Type: text/x-patch\r\n" +
				"Content-Disposition: attachment; filename=\"0001-f.patch\"\r\n\r\n+b\r\n" +
				"--b--\r\n",
			bodyType:    "text/plain",
			body:        "f: add b",
			attachments: []string{"text/x-patch: +b"},
		},
		{
			name: "second text part",
			msg: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nfirst\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nsecond\r\n" +
				"--b--\r\n",
			bodyType:    "text/plain",
			body:        "first",
			attachments: []string{"text/plain: second"},
		},
		{
			name: "inline image first",
			msg: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\n\r\nPNG\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\ntext\r\n" +
				"--b--\r\n",
			bodyType:    "text/plain",
			body:        "text",
			attachments: []string{"image/png: PNG"},
		},
		{
			name: "alternative",
			msg: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/alternative; boundary=a\r\n\r\n" +
				"--a\r\nContent-Type: text/plain\r\n\r\nplain\r\n" +
				"--a\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n" +
				"--a--\r\n" +
				"--b\r\nContent-Type: application/pdf\r\n\r\nPDF\r\n" +
				"--b--\r\n",
			bodyType:    "text/html",
			body:        "<p>html</p>",
			attachments: []string{"application/pdf: PDF"},
		},
		{
			name:     "latin-1",
			msg:      "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nb =E9\r\n",
			bodyType: "text/plain",
			body:     "b é\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := message.Read(strings.NewReader(tc.msg))
			if err != nil {
				t.Fatal(err)
			}

			var bodyType, body string
			var attachments []string
			err = walkParts(e, func(t string, b []byte) {
				bodyType, body = t, string(b)
			}, func(h message.Header, r io.Reader) error {
				ct, _, _ := h.ContentType()
				b, err := io.ReadAll(r)
				attachments = append(attachments, ct+": "+string(b))
				return err
			})
			if err != nil {
				t.Fatal(err)
			}

			if bodyType != tc.bodyType || body != tc.body {
				t.Errorf("got body %v %q, want %v %q", bodyType, body, tc.bodyType, tc.body)
			}
			if !reflect.DeepEqual(attachments, tc.attachments) {
				t.Errorf("got attachments %q, want %q", attachments, tc.attachments)
			}
		})
	}
}
