// Package fetchmail implements a fetchmail-like feature for hydroxide:
// instead of serving IMAP, it detects newly arrived Proton Mail messages in
// one or more folders and delivers them as RFC822 mail to an external SMTP
// relay.
package fetchmail

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/emersion/hydroxide/exports"
	"github.com/emersion/hydroxide/protonmail"
)

// Config configures a single fetchmail run.
type Config struct {
	// Folders are the resolved Proton label IDs to poll. Use ResolveFolders
	// to build this from user-supplied folder names.
	Folders []string
	// All forwards every message in scope again, ignoring the dedup state
	// (fetchmail's -a/--fetchall).
	All bool
	// MarkSeen marks successfully forwarded messages as read in Proton.
	MarkSeen bool
	// DeleteAfterDays, if positive, deletes a message from Proton this many
	// days after it was forwarded. 0 disables deletion.
	DeleteAfterDays int

	// SMTPHost and SMTPPort address the outbound SMTP relay.
	SMTPHost, SMTPPort string
	// SMTPStartTLS attempts STARTTLS if the relay offers it.
	SMTPStartTLS bool
	// SMTPUser and SMTPPass are optional AUTH credentials for the relay.
	// These are unrelated to the Proton bridge password.
	SMTPUser, SMTPPass string

	// EnvelopeFrom overrides the SMTP envelope sender. If empty, the
	// message's own sender address is used.
	EnvelopeFrom string
	// Rcpt overrides the SMTP envelope recipients. If empty, the message's
	// own To/Cc/Bcc addresses are used.
	Rcpt []string
}

var folderLabels = map[string]string{
	"inbox":    protonmail.LabelInbox,
	"all":      protonmail.LabelAllMail,
	"allmail":  protonmail.LabelAllMail,
	"all mail": protonmail.LabelAllMail,
	"archive":  protonmail.LabelArchive,
	"drafts":   protonmail.LabelDraft,
	"draft":    protonmail.LabelDraft,
	"starred":  protonmail.LabelStarred,
	"spam":     protonmail.LabelSpam,
	"sent":     protonmail.LabelSent,
	"trash":    protonmail.LabelTrash,
}

// ResolveFolders maps user-supplied folder names (e.g. "Inbox", "Archive")
// to Proton label IDs. An empty names list resolves to the Inbox.
func ResolveFolders(names []string) ([]string, error) {
	if len(names) == 0 {
		return []string{protonmail.LabelInbox}, nil
	}

	labels := make([]string, 0, len(names))
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		label, ok := folderLabels[key]
		if !ok {
			return nil, fmt.Errorf("unknown folder %q", name)
		}
		labels = append(labels, label)
	}
	return labels, nil
}

// RunOnce performs a single fetchmail pass: for each configured folder, it
// lists messages, forwards any not already recorded in state, then (if
// configured) deletes messages that were forwarded more than
// cfg.DeleteAfterDays ago. It loads and saves the state file at statePath
// itself. Calling RunOnce repeatedly (e.g. from cron, or from a ticker loop
// for daemon mode) is safe and idempotent thanks to that state file.
func RunOnce(c *protonmail.Client, privateKeys openpgp.EntityList, statePath string, cfg *Config) error {
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}

	for _, label := range cfg.Folders {
		if err := forwardFolder(c, privateKeys, label, cfg, state); err != nil {
			return err
		}
	}

	if cfg.DeleteAfterDays > 0 {
		if err := sweepDeleteAfter(c, cfg, state); err != nil {
			return err
		}
	}

	return state.Save(statePath)
}

func forwardFolder(c *protonmail.Client, privateKeys openpgp.EntityList, label string, cfg *Config, state *State) error {
	filter := &protonmail.MessageFilter{
		PageSize: 150,
		Label:    label,
		Sort:     "ID",
		Asc:      true,
	}

	total := -1
	for {
		offset := filter.PageSize * filter.Page
		if total >= 0 && offset > total {
			break
		}

		var msgs []*protonmail.Message
		var err error
		total, msgs, err = c.ListMessages(filter)
		if err != nil {
			return fmt.Errorf("failed to list messages: %v", err)
		}

		for _, msg := range msgs {
			if _, ok := state.Messages[msg.ID]; ok && !cfg.All {
				continue
			}

			if err := forward(c, privateKeys, msg, cfg); err != nil {
				return fmt.Errorf("failed to forward message %s: %v", msg.ID, err)
			}

			// Only recorded after a successful forward: -deleteafter can
			// never delete a message that isn't confirmed forwarded.
			state.Messages[msg.ID] = MessageState{
				Time:        int64(msg.Time),
				ForwardedAt: time.Now().Unix(),
			}

			if cfg.MarkSeen {
				if err := c.MarkMessagesRead([]string{msg.ID}); err != nil {
					log.Printf("cannot mark message %s as read: %v", msg.ID, err)
				}
			}
		}

		filter.Page++
	}

	return nil
}

func sweepDeleteAfter(c *protonmail.Client, cfg *Config, state *State) error {
	cutoff := time.Now().Add(-time.Duration(cfg.DeleteAfterDays) * 24 * time.Hour).Unix()

	var ids []string
	for id, ms := range state.Messages {
		if ms.ForwardedAt > 0 && ms.ForwardedAt < cutoff {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}

	if err := c.DeleteMessages(ids); err != nil {
		return fmt.Errorf("failed to delete forwarded messages: %v", err)
	}

	for _, id := range ids {
		delete(state.Messages, id)
	}
	return nil
}

func forward(c *protonmail.Client, privateKeys openpgp.EntityList, msg *protonmail.Message, cfg *Config) error {
	var buf bytes.Buffer
	if err := exports.WriteMessage(c, privateKeys, &buf, msg); err != nil {
		return fmt.Errorf("failed to assemble message: %v", err)
	}

	from := cfg.EnvelopeFrom
	if from == "" && msg.Sender != nil {
		from = msg.Sender.Address
	}
	if from == "" {
		return errors.New("cannot determine envelope sender")
	}

	rcpt := cfg.Rcpt
	if len(rcpt) == 0 {
		rcpt = messageRecipients(msg)
	}
	if len(rcpt) == 0 {
		return errors.New("message has no recipients")
	}

	return deliver(cfg, from, rcpt, buf.Bytes())
}

func messageRecipients(msg *protonmail.Message) []string {
	var rcpt []string
	for _, addr := range msg.ToList {
		rcpt = append(rcpt, addr.Address)
	}
	for _, addr := range msg.CCList {
		rcpt = append(rcpt, addr.Address)
	}
	for _, addr := range msg.BCCList {
		rcpt = append(rcpt, addr.Address)
	}
	return rcpt
}

func deliver(cfg *Config, from string, rcpt []string, body []byte) error {
	addr := cfg.SMTPHost + ":" + cfg.SMTPPort

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP relay %s: %v", addr, err)
	}
	defer client.Close()

	if cfg.SMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost}); err != nil {
				return fmt.Errorf("STARTTLS failed: %v", err)
			}
		}
	}

	if cfg.SMTPUser != "" {
		auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP AUTH failed: %v", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	for _, to := range rcpt {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("RCPT TO %q failed: %v", to, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		w.Close()
		return fmt.Errorf("failed to write message body: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finish DATA: %v", err)
	}

	return client.Quit()
}
