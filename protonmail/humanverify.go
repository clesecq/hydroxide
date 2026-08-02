package protonmail

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// API error codes related to human verification.
const (
	// CodeHumanVerificationRequired is returned when the API wants a human
	// to complete a challenge before the request can be replayed.
	CodeHumanVerificationRequired = 9001
	// CodeHumanVerificationInvalidToken is returned when a human verification
	// token is unknown, already consumed or expired.
	CodeHumanVerificationInvalidToken = 12087
)

// CaptchaMethod is the human verification method solved by a browser-based
// CAPTCHA challenge.
const CaptchaMethod = "captcha"

// HumanVerificationURL is the Proton-operated page on which challenges are
// solved. The challenge itself is served, rendered and validated by Proton:
// hydroxide only points the user's browser at it.
var HumanVerificationURL = "https://verify.proton.me/"

// CaptchaEndpoint is the API host serving the CAPTCHA challenge itself.
//
// It must be a host that serves both /core/v4/captcha and the widget's assets
// under /captcha/v1/assets/. Several Proton hosts serve the first but not the
// second, on which the challenge loads as an empty box.
//
// The challenge is served, rendered and scored by Proton throughout.
var CaptchaEndpoint = "https://mail-api.proton.me"

// CaptchaURL returns the Proton-operated CAPTCHA challenge for this token.
//
// On success the page posts a {"type": "pm_captcha", "token": ...} message to
// its embedder, where the token is the value the API expects back. See
// Captcha.tsx in ProtonMail/WebClients.
func (hv *HumanVerification) CaptchaURL() string {
	v := make(url.Values)
	v.Set("Token", hv.Token)
	v.Set("ForceWebMessaging", "1")
	return CaptchaEndpoint + "/core/v4/captcha?" + v.Encode()
}

// ErrNoHumanVerification is returned when an error doesn't carry a human
// verification challenge.
var ErrNoHumanVerification = errors.New("protonmail: not a human verification error")

// HumanVerification describes a challenge the API wants a human to complete.
//
// Token is a one-shot challenge identifier. It is not a credential, but it is
// never logged nor persisted by hydroxide.
type HumanVerification struct {
	Methods []string `json:"HumanVerificationMethods"`
	Token   string   `json:"HumanVerificationToken"`

	// SolvedMethod is the single method the user completed, e.g. "captcha".
	// The API expects one method name here, not the list it offered: see
	// getVerificationHeaders in ProtonMail/WebClients.
	SolvedMethod string `json:"-"`
}

// IsHumanVerificationRequired reports whether the API asked for a human
// verification challenge to be completed.
func (err *APIError) IsHumanVerificationRequired() bool {
	return err != nil && err.Code == CodeHumanVerificationRequired
}

// HumanVerification parses the challenge carried by a human verification
// error. It returns ErrNoHumanVerification if the error isn't one.
func (err *APIError) HumanVerification() (*HumanVerification, error) {
	if !err.IsHumanVerificationRequired() {
		return nil, ErrNoHumanVerification
	}
	if len(err.Details) == 0 {
		return nil, fmt.Errorf("protonmail: human verification required, but the API didn't return any challenge details")
	}

	var hv HumanVerification
	if jsonErr := json.Unmarshal(err.Details, &hv); jsonErr != nil {
		return nil, fmt.Errorf("protonmail: failed to parse human verification details: %v", jsonErr)
	}
	if hv.Token == "" {
		return nil, fmt.Errorf("protonmail: human verification required, but the API didn't return a challenge token")
	}
	return &hv, nil
}

// HasMethod reports whether the challenge can be solved with the given method.
func (hv *HumanVerification) HasMethod(method string) bool {
	for _, m := range hv.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// URL returns the Proton-operated page on which the challenge is presented to
// the user.
//
// The query is built exactly like Proton's own clients build it (see
// proton-bridge, internal/hv.FormatHvURL): the values are passed through
// as-is, without percent-encoding.
func (hv *HumanVerification) URL() string {
	return fmt.Sprintf("%v?methods=%v&token=%v",
		HumanVerificationURL,
		strings.Join(hv.Methods, ","),
		hv.Token)
}

// String implements fmt.Stringer without disclosing the challenge token.
func (hv *HumanVerification) String() string {
	if hv == nil {
		return "<nil>"
	}
	return fmt.Sprintf("HumanVerification{Methods: %v, Token: %v}", hv.Methods, redactedValue)
}

// setRequestHeaders marks a request as being replayed after the user completed
// the challenge. Proton validates the token server-side.
func (hv *HumanVerification) setRequestHeaders(req *http.Request) {
	if hv == nil {
		return
	}
	method := hv.SolvedMethod
	if method == "" {
		method = CaptchaMethod
	}
	req.Header.Set("x-pm-human-verification-token", hv.Token)
	req.Header.Set("x-pm-human-verification-token-type", method)
}
