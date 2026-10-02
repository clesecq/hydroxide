package smtp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/imports"
	"github.com/emersion/hydroxide/protonmail"
)

func toPMAddressList(addresses []*mail.Address) []*protonmail.MessageAddress {
	l := make([]*protonmail.MessageAddress, len(addresses))
	for i, addr := range addresses {
		l[i] = &protonmail.MessageAddress{
			Name:    addr.Name,
			Address: addr.Address,
		}
	}
	return l
}

func formatHeader(h mail.Header) string {
	var b bytes.Buffer
	fields := h.Fields()
	for fields.Next() {
		b.WriteString(fmt.Sprintf("%s: %s\r\n", fields.Key(), fields.Value()))
	}
	return b.String()
}

// splitRecipients matches the To and Cc header fields against the envelope
// recipients, which are the ones the message must be delivered to.
//
// The API delivers the message to every recipient of the draft, so header
// recipients missing from the envelope are dropped, and envelope recipients
// missing from the header become Bcc recipients. Addresses are compared
// case-insensitively and duplicates are removed.
func splitRecipients(rcpt []string, to, cc []*mail.Address) (toList, ccList, bccList, dropped []*mail.Address) {
	envelope := make(map[string]bool, len(rcpt))
	for _, addr := range rcpt {
		envelope[strings.ToLower(addr)] = true
	}

	seen := make(map[string]bool, len(rcpt))
	filter := func(addrs []*mail.Address) []*mail.Address {
		var l []*mail.Address
		for _, addr := range addrs {
			k := strings.ToLower(addr.Address)
			if !envelope[k] {
				dropped = append(dropped, addr)
			} else if !seen[k] {
				seen[k] = true
				l = append(l, addr)
			}
		}
		return l
	}
	toList = filter(to)
	ccList = filter(cc)

	for _, addr := range rcpt {
		k := strings.ToLower(addr)
		if !seen[k] {
			seen[k] = true
			bccList = append(bccList, &mail.Address{Address: addr})
		}
	}

	return toList, ccList, bccList, dropped
}

// replyParent returns the ID of the message the outgoing message replies to.
//
// The API ignores In-Reply-To and References from the submitted header: it
// generates them from the parent message instead. When the parent isn't in
// the mailbox (e.g. a mailing list post that was never received), a
// placeholder carrying its Message-Id and References is imported into the
// trash so that the API can generate both fields. In that case placeholder is
// true and the caller must delete the message once it has been sent.
func replyParent(c *protonmail.Client, addr *protonmail.Address, h mail.Header) (id string, placeholder bool, err error) {
	inReplyTo, err := h.MsgIDList("In-Reply-To")
	if err != nil {
		return "", false, fmt.Errorf("failed to parse In-Reply-To: %v", err)
	}
	if len(inReplyTo) == 0 {
		return "", false, nil
	}
	// The API supports a single parent
	parent := inReplyTo[0]

	_, msgs, err := c.ListMessages(&protonmail.MessageFilter{
		Limit:      1,
		ExternalID: parent,
		AddressID:  addr.ID,
	})
	if err != nil {
		return "", false, err
	}
	if len(msgs) > 0 {
		return msgs[0].ID, false, nil
	}

	refs, err := h.MsgIDList("References")
	if err != nil {
		return "", false, fmt.Errorf("failed to parse References: %v", err)
	}
	// The API appends the parent's Message-Id to its References
	if n := len(refs); n > 0 && refs[n-1] == parent {
		refs = refs[:n-1]
	}

	var ph mail.Header
	ph.SetDate(time.Now())
	ph.SetAddressList("From", []*mail.Address{{Address: addr.Email}})
	ph.SetSubject("hydroxide reply placeholder")
	ph.SetMessageID(parent)
	if len(refs) > 0 {
		ph.SetMsgIDList("References", refs)
	}
	ph.SetContentType("text/plain", map[string]string{"charset": "utf-8"})

	var b bytes.Buffer
	w, err := mail.CreateSingleInlineWriter(&b, ph)
	if err != nil {
		return "", false, err
	}
	io.WriteString(w, "Placeholder imported by hydroxide to send a reply to a message missing from the mailbox.\r\n")
	if err := w.Close(); err != nil {
		return "", false, err
	}

	log.Println("importing placeholder parent message")
	id, err = imports.Import(c, &b, addr, []string{protonmail.LabelTrash}, false)
	if err != nil {
		return "", false, fmt.Errorf("cannot import placeholder parent message: %v", err)
	}
	return id, true, nil
}

// recipientKey returns the key to encrypt the message to, or nil if the
// message must be sent in cleartext.
//
// External recipients get cleartext even when the API returns keys for them
// (e.g. published via WKD). Proton clients encrypt to these keys with
// PGP/MIME by default, which isn't supported here; and silently encrypting
// mail such as patches sent to a mailing list and its maintainers would be
// surprising anyway.
func recipientKey(resp *protonmail.PublicKeyResp) (*openpgp.Entity, error) {
	if resp.RecipientType != protonmail.RecipientInternal {
		return nil, nil
	}
	return resp.EncryptionKey()
}

// newPackageSet creates a package set holding body encrypted with a new
// session key.
func newPackageSet(attachmentKeys map[string]*packet.EncryptedKey, bodyType string, body []byte, privateKey *openpgp.Entity) (*protonmail.MessagePackageSet, error) {
	set := protonmail.NewMessagePackageSet(attachmentKeys)

	plaintext, err := set.Encrypt(bodyType, privateKey)
	if err != nil {
		return nil, err
	}
	if _, err := plaintext.Write(body); err != nil {
		plaintext.Close()
		return nil, err
	}
	if err := plaintext.Close(); err != nil {
		return nil, err
	}
	return set, nil
}

func SendMail(c *protonmail.Client, u *protonmail.User, privateKeys openpgp.EntityList, addrs []*protonmail.Address, rcpt []string, r io.Reader) error {
	// Parse the incoming MIME message header
	mr, err := mail.CreateReader(r)
	if err != nil {
		return err
	}

	subject, err := mr.Header.Subject()
	if err != nil {
		return fmt.Errorf("failed to parse Subject: %v", err)
	}
	fromList, err := mr.Header.AddressList("From")
	if err != nil {
		return fmt.Errorf("failed to parse From: %v", err)
	}
	headerTo, err := mr.Header.AddressList("To")
	if err != nil {
		return fmt.Errorf("failed to parse To: %v", err)
	}
	headerCc, err := mr.Header.AddressList("Cc")
	if err != nil {
		return fmt.Errorf("failed to parse Cc: %v", err)
	}

	// The envelope is authoritative: the Bcc header field must not be sent
	mr.Header.Del("Bcc")
	toList, ccList, bccList, dropped := splitRecipients(rcpt, headerTo, headerCc)
	if len(dropped) > 0 {
		log.Printf("removing recipients missing from the envelope: %v", dropped)
	}

	if len(fromList) != 1 {
		return errors.New("the From field must contain exactly one address")
	}
	if len(toList) == 0 && len(ccList) == 0 && len(bccList) == 0 {
		return errors.New("no recipient specified")
	}

	rawFrom := fromList[0]
	fromAddr, privateKey, err := protonmail.FindSendingAddress(addrs, rawFrom.Address, privateKeys)
	if err != nil {
		return err
	}

	msgID, err := mr.Header.MessageID()
	if err != nil {
		return fmt.Errorf("failed to parse Message-Id: %v", err)
	}

	msg := &protonmail.Message{
		ToList:     toPMAddressList(toList),
		CCList:     toPMAddressList(ccList),
		BCCList:    toPMAddressList(bccList),
		Subject:    subject,
		Header:     formatHeader(mr.Header),
		AddressID:  fromAddr.ID,
		ExternalID: msgID,
		Sender: &protonmail.MessageAddress{
			Address: fromAddr.Email,
			Name:    rawFrom.Name,
		},
	}

	// Create an empty draft
	log.Println("creating draft message")

	plaintext, err := msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return err
	}
	if err := plaintext.Close(); err != nil {
		return err
	}

	parentID, placeholder, err := replyParent(c, fromAddr, mr.Header)
	if err != nil {
		return err
	}
	if placeholder {
		defer func() {
			if err := c.DeleteMessages([]string{parentID}); err != nil {
				log.Printf("failed to delete placeholder parent message: %v", err)
			}
		}()
	}

	msg, err = c.CreateDraftMessage(msg, parentID)
	if err != nil {
		return fmt.Errorf("cannot create draft message: %v", err)
	}

	// Parse the incoming MIME message body
	// Save the message text into a buffer
	// Upload attachments

	var body *bytes.Buffer
	var bodyType string
	attachmentKeys := make(map[string]*packet.EncryptedKey)

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			t, _, err := h.ContentType()
			if err != nil {
				break
			}

			if body != nil && t != "text/html" {
				break
			}

			body = &bytes.Buffer{}
			bodyType = t
			if _, err := io.Copy(body, p.Body); err != nil {
				return err
			}
		case *mail.AttachmentHeader:
			t, _, err := h.ContentType()
			if err != nil {
				break
			}

			filename, err := h.Filename()
			if err != nil {
				break
			}

			att := &protonmail.Attachment{
				MessageID: msg.ID,
				Name:      filename,
				MIMEType:  t,
				ContentID: h.Get("Content-Id"),
				// TODO: Header
			}

			attKey, err := att.GenerateKey([]*openpgp.Entity{privateKey})
			if err != nil {
				return fmt.Errorf("cannot generate attachment key: %v", err)
			}

			log.Printf("uploading message attachment %q", filename)

			pr, pw := io.Pipe()

			go func() {
				cleartext, err := att.Encrypt(pw, privateKey)
				if err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := io.Copy(cleartext, p.Body); err != nil {
					pw.CloseWithError(err)
					return
				}
				pw.CloseWithError(cleartext.Close())
			}()

			att, err = c.CreateAttachment(att, pr)
			if err != nil {
				return fmt.Errorf("cannot upload attachment: %v", err)
			}

			attachmentKeys[att.ID] = attKey
		}
	}

	if body == nil {
		return errors.New("message doesn't contain a body part")
	}

	// Encrypt the body and update the draft
	log.Println("uploading message body")

	msg.MIMEType = bodyType
	plaintext, err = msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return err
	}
	if _, err := io.Copy(plaintext, bytes.NewReader(body.Bytes())); err != nil {
		return err
	}
	if err := plaintext.Close(); err != nil {
		return err
	}

	msg, err = c.UpdateDraftMessage(msg)
	if err != nil {
		return fmt.Errorf("cannot update draft message: %v", err)
	}

	// Split internal recipients and plaintext recipients

	recipients := make([]*mail.Address, 0, len(toList)+len(ccList)+len(bccList))
	recipients = append(recipients, toList...)
	recipients = append(recipients, ccList...)
	recipients = append(recipients, bccList...)

	var plaintextRecipients []string
	encryptedRecipients := make(map[string]*openpgp.Entity)
	for _, rcpt := range recipients {
		resp, err := c.GetPublicKeys(rcpt.Address)
		if err != nil {
			return fmt.Errorf("cannot get public key for address %q: %v", rcpt.Address, err)
		}

		pub, err := recipientKey(resp)
		if err != nil {
			return fmt.Errorf("cannot get public key for address %q: %v", rcpt.Address, err)
		}
		if pub == nil {
			plaintextRecipients = append(plaintextRecipients, rcpt.Address)
		} else {
			encryptedRecipients[rcpt.Address] = pub
		}
	}

	// Create and send the outgoing message
	log.Println("sending message")
	outgoing := &protonmail.OutgoingMessage{ID: msg.ID}

	if len(plaintextRecipients) > 0 {
		plaintextSet, err := newPackageSet(attachmentKeys, bodyType, body.Bytes(), privateKey)
		if err != nil {
			return err
		}

		for _, rcpt := range plaintextRecipients {
			pkg, err := plaintextSet.AddCleartext(rcpt)
			if err != nil {
				return err
			}

			// Don't sign plaintext messages by default
			// TODO: send inline singnature to opt-in contacts
			pkg.Signature = 0
		}

		outgoing.Packages = append(outgoing.Packages, plaintextSet)
	}

	if len(encryptedRecipients) > 0 {
		encryptedSet, err := newPackageSet(attachmentKeys, bodyType, body.Bytes(), privateKey)
		if err != nil {
			return err
		}

		for rcpt, pub := range encryptedRecipients {
			if _, err := encryptedSet.AddInternal(rcpt, pub); err != nil {
				return err
			}
		}

		outgoing.Packages = append(outgoing.Packages, encryptedSet)
	}

	_, _, err = c.SendMessage(outgoing)
	if err != nil {
		return fmt.Errorf("cannot send message: %v", err)
	}

	return nil
}

type session struct {
	be *backend

	c           *protonmail.Client
	u           *protonmail.User
	privateKeys openpgp.EntityList
	addrs       []*protonmail.Address

	allReceivers []string
}

var _ interface {
	smtp.Session
	smtp.AuthSession
} = (*session)(nil)

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *session) authPlain(username, password string) error {
	c, privateKeys, _, err := s.be.sessions.Auth(username, password)
	if err != nil {
		return err
	}

	u, err := c.GetCurrentUser()
	if err != nil {
		return err
	}

	addrs, err := c.ListAddresses()
	if err != nil {
		return err
	}

	// TODO: decrypt private keys in u.Addresses

	log.Printf("%s logged in", username)
	s.c = c
	s.u = u
	s.privateKeys = privateKeys
	s.addrs = addrs
	return nil
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if identity != "" && identity != username {
			return fmt.Errorf("invalid SASL PLAIN identity")
		}
		return s.authPlain(username, password)
	}), nil
}

func (s *session) Mail(from string, options *smtp.MailOptions) error {
	if s.c == nil {
		return smtp.ErrAuthRequired
	}
	return nil
}

func (s *session) Rcpt(to string, options *smtp.RcptOptions) error {
	if s.c == nil {
		return smtp.ErrAuthRequired
	}
	if to == "" {
		return nil
	}
	s.allReceivers = append(s.allReceivers, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if s.c == nil {
		return smtp.ErrAuthRequired
	}
	return SendMail(s.c, s.u, s.privateKeys, s.addrs, s.allReceivers, r)
}

func (s *session) Reset() {
	s.allReceivers = nil
}

func (s *session) Logout() error {
	*s = session{be: s.be}
	return nil
}

type backend struct {
	sessions *auth.Manager
}

func (be *backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &session{be: be}, nil
}

func New(sessions *auth.Manager) smtp.Backend {
	return &backend{sessions}
}
