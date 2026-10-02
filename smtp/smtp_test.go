package smtp

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

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
