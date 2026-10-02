package protonmail

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

type PrivateKeyFlags int

const (
	PrivateKeyVerify  PrivateKeyFlags = 1
	PrivateKeyEncrypt PrivateKeyFlags = 2
)

type PrivateKey struct {
	ID          string
	Version     int
	Flags       PrivateKeyFlags
	PrivateKey  string
	Fingerprint string
	Primary     int
	Active      int
	Token       string
	Signature   string
	// TODO: Fingerprints, PublicKey, Activation
}

func (priv *PrivateKey) Entity() (*openpgp.Entity, error) {
	keyRing, err := openpgp.ReadArmoredKeyRing(strings.NewReader(priv.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}
	if len(keyRing) == 0 {
		return nil, errors.New("private key is empty")
	}
	return keyRing[0], nil
}

type RecipientType int

const (
	RecipientInternal RecipientType = 1
	RecipientExternal               = 2
)

type PublicKeyResp struct {
	RecipientType RecipientType
	MIMEType      string
	Keys          []*PublicKey
}

// EncryptionKey returns the first key that messages can be encrypted to.
func (resp *PublicKeyResp) EncryptionKey() (*openpgp.Entity, error) {
	for _, key := range resp.Keys {
		if key.Flags&PublicKeyActive != 0 {
			return key.Entity()
		}
	}
	return nil, errors.New("no active public key")
}

type PublicKeyFlags int

const (
	// The key isn't compromised: signatures made with it can be trusted
	PublicKeyTrusted PublicKeyFlags = 1 << iota
	// The key isn't obsolete: messages can be encrypted to it
	PublicKeyActive
)

type PublicKey struct {
	Flags     PublicKeyFlags
	PublicKey string
}

func (pub *PublicKey) Entity() (*openpgp.Entity, error) {
	keyRing, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pub.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %v", err)
	}
	if len(keyRing) == 0 {
		return nil, errors.New("public key is empty")
	}
	return keyRing[0], nil
}

// GetPublicKeys retrieves public keys for a user.
func (c *Client) GetPublicKeys(email string) (*PublicKeyResp, error) {
	v := url.Values{}
	v.Set("Email", email)
	// TODO: Fingerprint

	req, err := c.newRequest(http.MethodGet, "/keys?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		*PublicKeyResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.PublicKeyResp, nil
}
