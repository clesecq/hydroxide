package smtp

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
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
