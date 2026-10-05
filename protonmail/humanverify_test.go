package protonmail

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testHVToken = "signed-challenge-token-do-not-log"

// hvErrorBody is the shape of a real human verification error response.
const hvErrorBody = `{
	"Code": 9001,
	"Error": "For security reasons, please complete CAPTCHA.",
	"Details": {
		"HumanVerificationMethods": ["captcha", "email", "sms"],
		"HumanVerificationToken": "` + testHVToken + `"
	}
}`

const authInfoBody = `{
	"Code": 1000,
	"Version": 4,
	"Modulus": "test-modulus",
	"ServerEphemeral": "test-server-ephemeral",
	"Salt": "test-salt",
	"SRPSession": "test-srp-session"
}`

func newTestClient(h http.Handler) (*Client, *httptest.Server) {
	srv := httptest.NewServer(h)
	return &Client{RootURL: srv.URL, AppVersion: "Other"}, srv
}

func TestAuthInfo_NoHumanVerification(t *testing.T) {
	var gotHeaders http.Header
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(authInfoBody))
	}))
	defer srv.Close()

	info, err := c.AuthInfo("user@proton.me")
	if err != nil {
		t.Fatalf("AuthInfo() = %v", err)
	}
	if info.srpSession != "test-srp-session" {
		t.Errorf("srpSession = %q, want %q", info.srpSession, "test-srp-session")
	}

	// A login that doesn't need human verification must be unchanged: no
	// extra headers are sent.
	for _, k := range []string{"X-Pm-Human-Verification-Token", "X-Pm-Human-Verification-Token-Type"} {
		if v := gotHeaders.Get(k); v != "" {
			t.Errorf("unexpected header %v: %q", k, v)
		}
	}
}

func TestAuthInfo_HumanVerificationRequired(t *testing.T) {
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(hvErrorBody))
	}))
	defer srv.Close()

	_, err := c.AuthInfo("user@proton.me")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("AuthInfo() error = %T (%v), want *APIError", err, err)
	}
	if !apiErr.IsHumanVerificationRequired() {
		t.Fatalf("IsHumanVerificationRequired() = false, code = %v", apiErr.Code)
	}

	hv, err := apiErr.HumanVerification()
	if err != nil {
		t.Fatalf("HumanVerification() = %v", err)
	}
	if hv.Token != testHVToken {
		t.Errorf("Token = %q, want %q", hv.Token, testHVToken)
	}
	if want := []string{"captcha", "email", "sms"}; strings.Join(hv.Methods, ",") != strings.Join(want, ",") {
		t.Errorf("Methods = %v, want %v", hv.Methods, want)
	}
	if !hv.HasMethod(CaptchaMethod) {
		t.Error("HasMethod(captcha) = false")
	}
	if hv.HasMethod("ownership-email") {
		t.Error("HasMethod(ownership-email) = true")
	}
}

func TestHumanVerification_Errors(t *testing.T) {
	notHV := &APIError{Code: 8002, Message: "Incorrect login credentials"}
	if notHV.IsHumanVerificationRequired() {
		t.Error("IsHumanVerificationRequired() = true for code 8002")
	}
	if _, err := notHV.HumanVerification(); err != ErrNoHumanVerification {
		t.Errorf("HumanVerification() = %v, want ErrNoHumanVerification", err)
	}

	noDetails := &APIError{Code: CodeHumanVerificationRequired, Message: "captcha"}
	if _, err := noDetails.HumanVerification(); err == nil {
		t.Error("HumanVerification() with no details = nil error")
	}

	noToken := &APIError{
		Code:    CodeHumanVerificationRequired,
		Details: json.RawMessage(`{"HumanVerificationMethods":["captcha"]}`),
	}
	if _, err := noToken.HumanVerification(); err == nil {
		t.Error("HumanVerification() with no token = nil error")
	}

	badJSON := &APIError{Code: CodeHumanVerificationRequired, Details: json.RawMessage(`not json`)}
	if _, err := badJSON.HumanVerification(); err == nil {
		t.Error("HumanVerification() with invalid details = nil error")
	}
}

// TestHumanVerificationURL checks that the verification URL is formatted
// exactly like Proton's own clients format it.
func TestHumanVerificationURL(t *testing.T) {
	hv := &HumanVerification{Methods: []string{"captcha", "email", "sms"}, Token: testHVToken}

	want := "https://verify.proton.me/?methods=captcha,email,sms&token=" + testHVToken
	if got := hv.URL(); got != want {
		t.Errorf("URL() = %q, want %q", got, want)
	}
	if strings.Contains(hv.String(), hv.Token) {
		t.Errorf("String() = %q, leaks the token", hv.String())
	}
}

// TestCaptchaURL checks the challenge URL against the one Proton's web client
// builds (see Captcha.tsx in ProtonMail/WebClients).
func TestCaptchaURL(t *testing.T) {
	hv := &HumanVerification{Methods: []string{CaptchaMethod}, Token: "a token/+="}

	got := hv.CaptchaURL()
	want := CaptchaEndpoint + "/core/v4/captcha?ForceWebMessaging=1&Token=a+token%2F%2B%3D"
	if got != want {
		t.Errorf("CaptchaURL() = %q, want %q", got, want)
	}

	// The challenge must come from a host that lets a local page embed it.
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("CaptchaURL() = %q, want an HTTPS URL", got)
	}
}

// TestAuthWithVerification_DoesNotSpendTokenOnAuthInfo guards against sending
// the single-use challenge token on /auth/info: Proton would consume it there
// and reject the /auth request with error 12087.
func TestAuthWithVerification_DoesNotSpendTokenOnAuthInfo(t *testing.T) {
	var paths []string
	var infoHeaders http.Header
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/auth/info" {
			infoHeaders = r.Header.Clone()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(authInfoBody))
	}))
	defer srv.Close()

	hv := &HumanVerification{Methods: []string{CaptchaMethod}, Token: testHVToken}
	// SRP fails on the test modulus, which is fine: we only care about what
	// was sent to /auth/info.
	c.AuthWithVerification("user@proton.me", "hunter2", nil, hv)

	if len(paths) == 0 || paths[0] != "/auth/info" {
		t.Fatalf("requested %v, want /auth/info first", paths)
	}
	if got := infoHeaders.Get("x-pm-human-verification-token"); got != "" {
		t.Errorf("/auth/info carried the challenge token %q", got)
	}
	if got := infoHeaders.Get("x-pm-human-verification-token-type"); got != "" {
		t.Errorf("/auth/info carried the challenge token type %q", got)
	}
}

// TestAuthWithVerification_ReplaysAuthInfoWhenItAsks covers the case where
// /auth/info itself is the request that wants human verification.
func TestAuthWithVerification_ReplaysAuthInfoWhenItAsks(t *testing.T) {
	var tokens []string
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/info" {
			t.Errorf("unexpected request to %v", r.URL.Path)
			return
		}
		token := r.Header.Get("x-pm-human-verification-token")
		tokens = append(tokens, token)
		w.Header().Set("Content-Type", "application/json")
		if token == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(hvErrorBody))
			return
		}
		w.Write([]byte(authInfoBody))
	}))
	defer srv.Close()

	hv := &HumanVerification{Methods: []string{CaptchaMethod}, Token: testHVToken}
	c.AuthWithVerification("user@proton.me", "hunter2", nil, hv)

	if len(tokens) != 2 {
		t.Fatalf("%v requests to /auth/info, want 2", len(tokens))
	}
	if tokens[0] != "" {
		t.Errorf("the first /auth/info carried a token")
	}
	if tokens[1] != testHVToken {
		t.Errorf("the replayed /auth/info carried %q, want the challenge token", tokens[1])
	}
}

func TestAuthInfoWithVerification_SendsHeaders(t *testing.T) {
	var gotHeaders http.Header
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(authInfoBody))
	}))
	defer srv.Close()

	hv := &HumanVerification{Methods: []string{"captcha", "email"}, Token: testHVToken}
	if _, err := c.AuthInfoWithVerification("user@proton.me", hv); err != nil {
		t.Fatalf("AuthInfoWithVerification() = %v", err)
	}

	if got := gotHeaders.Get("x-pm-human-verification-token"); got != testHVToken {
		t.Errorf("token header = %q, want %q", got, testHVToken)
	}
	// The API takes a single method name, not the list it offered.
	if got := gotHeaders.Get("x-pm-human-verification-token-type"); got != CaptchaMethod {
		t.Errorf("token type header = %q, want %q", got, CaptchaMethod)
	}

	hv.SolvedMethod = "email"
	if _, err := c.AuthInfoWithVerification("user@proton.me", hv); err != nil {
		t.Fatalf("AuthInfoWithVerification() = %v", err)
	}
	if got := gotHeaders.Get("x-pm-human-verification-token-type"); got != "email" {
		t.Errorf("token type header = %q, want %q", got, "email")
	}
}

// TestDebugDoesNotLogSecrets makes sure debug logs never disclose credentials,
// session tokens, SRP material or human verification tokens.
func TestDebugDoesNotLogSecrets(t *testing.T) {
	const accessToken = "super-secret-access-token"
	const refreshToken = "super-secret-refresh-token"

	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"Code": 1000,
			"AccessToken": "` + accessToken + `",
			"RefreshToken": "` + refreshToken + `",
			"Details": {"HumanVerificationToken": "` + testHVToken + `"},
			"UID": "some-uid"
		}`))
	}))
	defer srv.Close()
	c.Debug = true

	var logs bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	}()

	hv := &HumanVerification{Methods: []string{CaptchaMethod}, Token: testHVToken}
	req, err := c.newJSONRequest(http.MethodPost, "/auth", &authReq{
		Username:        "user@proton.me",
		SRPSession:      "session",
		ClientEphemeral: "secret-client-ephemeral",
		ClientProof:     "secret-client-proof",
	})
	if err != nil {
		t.Fatal(err)
	}
	hv.setRequestHeaders(req)

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{
		accessToken, refreshToken, testHVToken,
		"secret-client-ephemeral", "secret-client-proof",
	} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("debug logs disclose %q:\n%v", secret, logs.String())
		}
	}
	if !strings.Contains(logs.String(), redactedValue) {
		t.Errorf("debug logs don't mention any redaction:\n%v", logs.String())
	}
	// Non-sensitive fields are still logged, otherwise debugging is useless.
	if !strings.Contains(logs.String(), "some-uid") {
		t.Errorf("debug logs dropped non-sensitive fields:\n%v", logs.String())
	}
}
