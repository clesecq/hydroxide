package imports

import (
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/emersion/go-message/mail"

	"github.com/emersion/hydroxide/protonmail"
)

// ImportMessage imports a message into the inbox of the primary address.
func ImportMessage(c *protonmail.Client, r io.Reader) error {
	addrs, err := c.ListAddresses()
	if err != nil {
		return err
	}
	// TODO: choose address depending on message header
	var importAddr *protonmail.Address
	for _, addr := range addrs {
		if addr.Send == protonmail.AddressSendPrimary {
			importAddr = addr
			break
		}
	}
	if importAddr == nil {
		return fmt.Errorf("no primary address found")
	}

	_, err = Import(c, r, importAddr, []string{protonmail.LabelInbox}, true)
	return err
}

// Import imports a message into the mailbox of addr with the given labels and
// returns the ID of the created message.
func Import(c *protonmail.Client, r io.Reader, addr *protonmail.Address, labelIDs []string, unread bool) (string, error) {
	mr, err := mail.CreateReader(r)
	if err != nil {
		return "", err
	}
	defer mr.Close()

	// TODO: support attachments
	hdr := mr.Header
	var body io.Reader
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}

		if _, ok := p.Header.(*mail.InlineHeader); ok {
			if t := p.Header.Get("Content-Type"); t != "" {
				hdr.Set("Content-Type", t)
			}
			body = p.Body
			break
		}
	}
	if body == nil {
		return "", fmt.Errorf("message has no body")
	}

	publicKey, err := addr.Keys[0].Entity()
	if err != nil {
		return "", err
	}

	key := "0"
	var unreadFlag int
	if unread {
		unreadFlag = 1
	}
	metadata := map[string]*protonmail.Message{
		key: {
			Unread:    unreadFlag,
			LabelIDs:  labelIDs,
			Type:      protonmail.MessageInbox,
			AddressID: addr.ID,
		},
	}
	importer, err := c.Import(metadata)
	if err != nil {
		return "", err
	}

	w, err := importer.ImportMessage(key)
	if err != nil {
		return "", err
	}

	var ihdr mail.InlineHeader
	if hdr.Has("Content-Type") {
		ihdr.Set("Content-Type", hdr.Get("Content-Type"))
	}
	ihdr.Set("Content-Transfer-Encoding", "8bit")

	hdr.Del("Content-Type")
	hdr.Del("Content-Transfer-Encoding")
	hdr.Del("Content-Disposition")
	mwc, err := mail.CreateWriter(w, hdr)
	if err != nil {
		return "", err
	}
	defer mwc.Close()

	iwc, err := mwc.CreateSingleInline(ihdr)
	if err != nil {
		return "", err
	}

	awc, err := armor.Encode(iwc, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}
	defer awc.Close()
	ewc, err := openpgp.Encrypt(awc, []*openpgp.Entity{publicKey}, nil, nil, nil)
	if err != nil {
		return "", err
	}
	defer ewc.Close()

	if _, err := io.Copy(ewc, body); err != nil {
		return "", err
	}
	if err := ewc.Close(); err != nil {
		return "", err
	}
	if err := awc.Close(); err != nil {
		return "", err
	}
	if err := iwc.Close(); err != nil {
		return "", err
	}
	if err := mwc.Close(); err != nil {
		return "", err
	}

	result, err := importer.Commit()
	if err != nil {
		return "", err
	}
	if err := result.Err(); err != nil {
		return "", err
	}

	return result[key].MessageID, nil
}
