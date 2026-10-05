package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"log"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/emersion/go-mbox"

	"github.com/emersion/hydroxide/exports"
	"github.com/emersion/hydroxide/imports"
	smtpbackend "github.com/emersion/hydroxide/smtp"
)

func runExportSecretKeys(args []string) {
	cmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	cmd.Parse(args)
	username := cmd.Arg(0)
	if username == "" {
		log.Fatal("usage: hydroxide export-secret-keys <username>")
	}

	_, privateKeys := authenticate(username)

	wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
	if err != nil {
		log.Fatal(err)
	}

	for _, key := range privateKeys {
		if err := key.SerializePrivate(wc, nil); err != nil {
			log.Fatal(err)
		}
	}

	if err := wc.Close(); err != nil {
		log.Fatal(err)
	}
}

func isMbox(br *bufio.Reader) (bool, error) {
	prefix := []byte("From ")
	b, err := br.Peek(len(prefix))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, prefix), nil
}

func runImportMessages(args []string) {
	cmd := flag.NewFlagSet("import-messages", flag.ExitOnError)
	cmd.Parse(args)
	username := cmd.Arg(0)
	archivePath := cmd.Arg(1)
	if username == "" {
		log.Fatal("usage: hydroxide import-messages <username> [file]")
	}

	f := os.Stdin
	if archivePath != "" {
		var err error
		f, err = os.Open(archivePath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
	}

	c, _ := authenticate(username)

	br := bufio.NewReader(f)
	if ok, err := isMbox(br); err != nil {
		log.Fatal(err)
	} else if ok {
		mr := mbox.NewReader(br)
		for {
			r, err := mr.NextMessage()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatal(err)
			}
			if err := imports.ImportMessage(c, r); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		if err := imports.ImportMessage(c, br); err != nil {
			log.Fatal(err)
		}
	}
}

func runExportMessages(args []string) {
	cmd := flag.NewFlagSet("export-messages", flag.ExitOnError)
	// TODO: allow specifying multiple IDs
	var convID, msgID string
	cmd.StringVar(&convID, "conversation-id", "", "conversation ID")
	cmd.StringVar(&msgID, "message-id", "", "message ID")
	cmd.Parse(args)
	username := cmd.Arg(0)
	if (convID == "" && msgID == "") || username == "" {
		log.Fatal("usage: hydroxide export-messages [-conversation-id <id>] [-message-id <id>] <username>")
	}

	c, privateKeys := authenticate(username)

	mboxWriter := mbox.NewWriter(os.Stdout)

	if convID != "" {
		if err := exports.ExportConversationMbox(c, privateKeys, mboxWriter, convID); err != nil {
			log.Fatal(err)
		}
	}
	if msgID != "" {
		if err := exports.ExportMessageMbox(c, privateKeys, mboxWriter, msgID); err != nil {
			log.Fatal(err)
		}
	}

	if err := mboxWriter.Close(); err != nil {
		log.Fatal(err)
	}
}

func runSendmail(args []string) {
	if len(args) < 2 || args[0] == "" || args[1] != "--" {
		log.Fatal("usage: hydroxide sendmail <username> -- <args...>")
	}
	username := args[0]

	// TODO: other sendmail flags
	cmd := flag.NewFlagSet("sendmail", flag.ExitOnError)
	var dotEOF bool
	cmd.BoolVar(&dotEOF, "i", false, "don't treat a line with only a . character as the end of input")
	cmd.Parse(args[2:])
	rcpt := cmd.Args()

	c, privateKeys := authenticate(username)

	u, err := c.GetCurrentUser()
	if err != nil {
		log.Fatal(err)
	}

	addrs, err := c.ListAddresses()
	if err != nil {
		log.Fatal(err)
	}

	if err := smtpbackend.SendMail(c, u, privateKeys, addrs, rcpt, os.Stdin); err != nil {
		log.Fatal(err)
	}
}
