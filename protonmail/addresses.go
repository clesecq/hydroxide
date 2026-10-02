package protonmail

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

type (
	AddressSend   int
	AddressStatus int
	AddressType   int
)

const (
	AddressSendDisabled AddressSend = iota
	AddressSendPrimary
	AddressSendSecondary
)

const (
	AddressDisabled AddressStatus = iota
	AddressEnabled
)

const (
	AddressOriginal AddressType = iota
	AddressAlias
	AddressCustom
)

type Address struct {
	ID          string
	DomainID    string
	Email       string
	Send        AddressSend
	Receive     int
	Status      AddressStatus
	Type        AddressType
	Order       int64
	DisplayName string
	Signature   string // HTML
	HasKeys     int
	Keys        []*PrivateKey
}

func (c *Client) ListAddresses() ([]*Address, error) {
	// TODO: Page, PageSize
	req, err := c.newRequest(http.MethodGet, "/addresses", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Addresses []*Address
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Addresses, nil
}

// FindSendingAddress looks up the address matching email and its decrypted
// private key. The match is case-insensitive, but the API checks the sender
// case-sensitively: callers must send as the returned Address.Email, not as
// the spelling they were given.
func FindSendingAddress(addrs []*Address, email string, privateKeys openpgp.EntityList) (*Address, *openpgp.Entity, error) {
	var addr *Address
	for _, a := range addrs {
		if strings.EqualFold(a.Email, email) {
			addr = a
			break
		}
	}
	if addr == nil {
		return nil, nil, errors.New("unknown sender address")
	}
	if len(addr.Keys) == 0 {
		return nil, nil, errors.New("sender address has no private key")
	}

	// TODO: get appropriate private key
	encryptedPrivateKey, err := addr.Keys[0].Entity()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse sender private key: %v", err)
	}

	for _, e := range privateKeys {
		if e.PrimaryKey.KeyId == encryptedPrivateKey.PrimaryKey.KeyId {
			return addr, e, nil
		}
	}
	return nil, nil, errors.New("sender address key hasn't been decrypted")
}
