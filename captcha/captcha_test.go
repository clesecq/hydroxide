package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

const testToken = "signed-challenge-token"

func hvError(methods ...string) *protonmail.APIError {
	details, err := json.Marshal(protonmail.HumanVerification{
		Methods: methods,
		Token:   testToken,
	})
	if err != nil {
		panic(err)
	}
	return &protonmail.APIError{
		Code:    protonmail.CodeHumanVerificationRequired,
		Message: "For security reasons, please complete CAPTCHA.",
		Details: details,
	}
}

// fakeClient records the human verification details of each attempt and
// replays canned results.
type fakeClient struct {
	results []error
	auths   []*protonmail.Auth
	hvSeen  []*protonmail.HumanVerification
}

func (c *fakeClient) AuthWithVerification(username, password string, info *protonmail.AuthInfo, hv *protonmail.HumanVerification) (*protonmail.Auth, error) {
	n := len(c.hvSeen)
	c.hvSeen = append(c.hvSeen, hv)
	if n >= len(c.results) {
		return nil, errors.New("unexpected authentication attempt")
	}
	var auth *protonmail.Auth
	if n < len(c.auths) {
		auth = c.auths[n]
	}
	return auth, c.results[n]
}

// browserOpts returns options whose "browser" completes the challenge as a
// human would: it loads the local page and confirms it.
func browserOpts(out *bytes.Buffer) Options {
	return Options{
		Mode:        ModeBrowser,
		ListenAddr:  "127.0.0.1:0",
		Timeout:     10 * time.Second,
		OpenBrowser: true,
		Output:      out,
		openURL:     fakeBrowser,
		// Tests never talk to Proton.
		checkChallenge: func(context.Context, *protonmail.HumanVerification, io.Writer) {},
	}
}

func TestAuthenticate_NoVerificationNeeded(t *testing.T) {
	want := &protonmail.Auth{UID: "uid"}
	c := &fakeClient{results: []error{nil}, auths: []*protonmail.Auth{want}}

	var out bytes.Buffer
	got, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&out))
	if err != nil {
		t.Fatalf("Authenticate() = %v", err)
	}
	if got != want {
		t.Errorf("Authenticate() = %v, want %v", got, want)
	}
	if len(c.hvSeen) != 1 {
		t.Errorf("%v authentication attempts, want 1", len(c.hvSeen))
	}
	if c.hvSeen[0] != nil {
		t.Error("human verification headers sent on a login that didn't need them")
	}
	if out.Len() != 0 {
		t.Errorf("unexpected user-facing output: %q", out.String())
	}
}

func TestAuthenticate_CaptchaThenSuccess(t *testing.T) {
	want := &protonmail.Auth{UID: "uid"}
	c := &fakeClient{
		results: []error{hvError("captcha", "email"), nil},
		auths:   []*protonmail.Auth{nil, want},
	}

	var out bytes.Buffer
	got, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&out))
	if err != nil {
		t.Fatalf("Authenticate() = %v", err)
	}
	if got != want {
		t.Errorf("Authenticate() = %v, want %v", got, want)
	}
	if len(c.hvSeen) != 2 {
		t.Fatalf("%v authentication attempts, want 2", len(c.hvSeen))
	}
	// The retry must carry the token the challenge produced, not the bare
	// challenge token, and name the single method that was solved.
	if c.hvSeen[1] == nil {
		t.Fatal("the second attempt carried no verification details")
	}
	if c.hvSeen[1].Token != solvedToken {
		t.Errorf("second attempt sent %q, want the solved challenge token", c.hvSeen[1].Token)
	}
	if c.hvSeen[1].SolvedMethod != protonmail.CaptchaMethod {
		t.Errorf("second attempt sent method %q, want %q", c.hvSeen[1].SolvedMethod, protonmail.CaptchaMethod)
	}
	if !strings.Contains(out.String(), "Proton requires human verification") {
		t.Errorf("missing instructions:\n%v", out.String())
	}
	if !strings.Contains(out.String(), "CAPTCHA accepted") {
		t.Errorf("missing confirmation:\n%v", out.String())
	}
	// The challenge token is only ever handed to the browser, never printed.
	if strings.Contains(out.String(), testToken) {
		t.Errorf("the challenge token was printed to the terminal:\n%v", out.String())
	}
}

func TestAuthenticate_RejectedAfterCompletion(t *testing.T) {
	c := &fakeClient{results: []error{hvError("captcha"), hvError("captcha")}}

	var out bytes.Buffer
	_, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&out))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("Authenticate() = %v, want ErrRejected", err)
	}
	if len(c.hvSeen) != 2 {
		t.Errorf("%v authentication attempts, want exactly 2 (one CAPTCHA-assisted retry)", len(c.hvSeen))
	}
}

func TestAuthenticate_InvalidTokenAfterCompletion(t *testing.T) {
	c := &fakeClient{results: []error{
		hvError("captcha"),
		&protonmail.APIError{Code: protonmail.CodeHumanVerificationInvalidToken, Message: "Invalid verification token"},
	}}

	var out bytes.Buffer
	_, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&out))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("Authenticate() = %v, want ErrRejected", err)
	}
}

func TestAuthenticate_Disabled(t *testing.T) {
	c := &fakeClient{results: []error{hvError("captcha")}}

	opts := browserOpts(&bytes.Buffer{})
	opts.Mode = ModeDisabled
	_, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", opts)
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("Authenticate() = %v, want ErrDisabled", err)
	}
	if len(c.hvSeen) != 1 {
		t.Errorf("%v authentication attempts, want 1", len(c.hvSeen))
	}
}

func TestAuthenticate_UnsupportedMethod(t *testing.T) {
	c := &fakeClient{results: []error{hvError("sms", "email")}}

	_, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&bytes.Buffer{}))
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("Authenticate() = %v, want ErrUnsupportedMethod", err)
	}
}

func TestAuthenticate_MalformedChallenge(t *testing.T) {
	c := &fakeClient{results: []error{&protonmail.APIError{
		Code:    protonmail.CodeHumanVerificationRequired,
		Message: "For security reasons, please complete CAPTCHA.",
	}}}

	_, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&bytes.Buffer{}))
	if err == nil {
		t.Fatal("Authenticate() = nil, want an error")
	}
	if len(c.hvSeen) != 1 {
		t.Errorf("%v authentication attempts, want 1", len(c.hvSeen))
	}
}

func TestAuthenticate_OtherErrorIsUnchanged(t *testing.T) {
	want := &protonmail.APIError{Code: 8002, Message: "Incorrect login credentials"}
	c := &fakeClient{results: []error{want}}

	_, err := Authenticate(context.Background(), c, "user@proton.me", "hunter2", browserOpts(&bytes.Buffer{}))
	if err != error(want) {
		t.Fatalf("Authenticate() = %v, want the original API error", err)
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"browser", "manual", "disabled"} {
		if _, err := ParseMode(s); err != nil {
			t.Errorf("ParseMode(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"", "auto", "BROWSER", "none"} {
		if _, err := ParseMode(s); err == nil {
			t.Errorf("ParseMode(%q) = nil error", s)
		}
	}
}

func TestDefaultsAreSafe(t *testing.T) {
	opts, err := Options{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Mode != ModeBrowser {
		t.Errorf("Mode = %v, want %v", opts.Mode, ModeBrowser)
	}
	if opts.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %v, want %v", opts.ListenAddr, DefaultListenAddr)
	}
	if opts.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", opts.Timeout, DefaultTimeout)
	}
	// The default listener must never be reachable from outside the machine.
	host, _, _ := strings.Cut(DefaultListenAddr, ":")
	if !isLoopback(host) {
		t.Errorf("default listen host %q is not a loopback address", host)
	}
}
