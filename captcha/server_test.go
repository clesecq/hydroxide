package captcha

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

func testChallenge() *protonmail.HumanVerification {
	return &protonmail.HumanVerification{
		Methods: []string{protonmail.CaptchaMethod, "email"},
		Token:   testToken,
	}
}

// solvedToken is what Proton's challenge posts back once the user solved it:
// the challenge token, a colon, and the response.
const solvedToken = testToken + ":solved-challenge-response"

// fakeBrowser plays the part of the user's browser: it opens the local page,
// stands in for the embedded challenge, and posts back the solved token.
func fakeBrowser(rawURL string) error {
	resp, err := http.Get(rawURL)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %v: %v", rawURL, resp.Status)
	}
	// The page must embed Proton's own challenge, and offer its verification
	// page as a fallback.
	if !strings.Contains(string(body), "/core/v4/captcha") {
		return fmt.Errorf("the page doesn't embed Proton's challenge")
	}
	if !strings.Contains(string(body), "verify.proton.me") {
		return fmt.Errorf("the page doesn't link to Proton's verification page")
	}

	resp, err = http.PostForm(rawURL+"/done", url.Values{"token": {solvedToken}})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %v/done: %v", rawURL, resp.Status)
	}
	return nil
}

func TestNewState(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		state, err := newState()
		if err != nil {
			t.Fatal(err)
		}
		b, err := base64.RawURLEncoding.DecodeString(state)
		if err != nil {
			t.Fatalf("state %q is not URL-safe base64: %v", state, err)
		}
		if len(b) != stateLen {
			t.Fatalf("state holds %v bytes, want %v", len(b), stateLen)
		}
		if seen[state] {
			t.Fatalf("state %q was generated twice", state)
		}
		seen[state] = true
	}
}

func TestSolve_BindsLoopbackAndShutsDown(t *testing.T) {
	var out bytes.Buffer
	var localURL string

	opts := browserOpts(&out)
	opts.openURL = func(rawURL string) error {
		localURL = rawURL
		return fakeBrowser(rawURL)
	}

	got, err := Solve(context.Background(), testChallenge(), opts)
	if err != nil {
		t.Fatalf("Solve() = %v", err)
	}
	if got != solvedToken {
		t.Errorf("Solve() = %q, want the solved challenge token", got)
	}

	u, err := url.Parse(localURL)
	if err != nil {
		t.Fatalf("invalid local URL %q: %v", localURL, err)
	}
	if !isLoopback(u.Hostname()) {
		t.Errorf("the helper listened on %q, which is not a loopback address", u.Hostname())
	}
	if !strings.Contains(out.String(), localURL) {
		t.Errorf("the local URL wasn't printed:\n%v", out.String())
	}
	if strings.Contains(out.String(), testToken) {
		t.Errorf("the challenge token was printed:\n%v", out.String())
	}

	// The server must be gone once Solve returned.
	if _, err := http.Get(localURL); err == nil {
		t.Error("the helper server is still listening after Solve() returned")
	}
}

func TestSolve_ManualModeDoesNotOpenBrowser(t *testing.T) {
	var out bytes.Buffer
	opened := false

	opts := browserOpts(&out)
	opts.Mode = ModeManual
	opts.Timeout = 200 * time.Millisecond
	opts.openURL = func(string) error {
		opened = true
		return nil
	}

	if _, err := Solve(context.Background(), testChallenge(), opts); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Solve() = %v, want ErrTimeout", err)
	}
	if opened {
		t.Error("a browser was launched in manual mode")
	}
	if !strings.Contains(out.String(), "Open this URL in your browser") {
		t.Errorf("the URL wasn't printed:\n%v", out.String())
	}
}

func TestSolve_BrowserFailureIsReported(t *testing.T) {
	var out bytes.Buffer
	opts := browserOpts(&out)
	opts.Timeout = 200 * time.Millisecond
	opts.openURL = func(string) error { return errors.New("no browser here") }

	if _, err := Solve(context.Background(), testChallenge(), opts); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Solve() = %v, want ErrTimeout", err)
	}
	if !strings.Contains(out.String(), "no browser here") {
		t.Errorf("the browser failure wasn't reported:\n%v", out.String())
	}
}

func TestSolve_TimeoutStopsServer(t *testing.T) {
	var out bytes.Buffer
	var localURL string

	opts := browserOpts(&out)
	opts.Timeout = 200 * time.Millisecond
	opts.openURL = func(rawURL string) error {
		localURL = rawURL
		return nil // the user never completes the challenge
	}

	start := time.Now()
	_, err := Solve(context.Background(), testChallenge(), opts)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Solve() = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Solve() took %v, want it to give up after the timeout", elapsed)
	}
	if _, err := http.Get(localURL); err == nil {
		t.Error("the helper server is still listening after the timeout")
	}
}

func TestSolve_CancelShutsEverythingDown(t *testing.T) {
	var out bytes.Buffer
	var localURL string

	ctx, cancel := context.WithCancel(context.Background())
	opts := browserOpts(&out)
	opts.openURL = func(rawURL string) error {
		localURL = rawURL
		cancel() // stands in for Ctrl+C
		return nil
	}

	_, err := Solve(ctx, testChallenge(), opts)
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Solve() = %v, want ErrCanceled", err)
	}
	if _, err := http.Get(localURL); err == nil {
		t.Error("the helper server is still listening after cancellation")
	}
}

func TestSolve_WrongStateIsRejected(t *testing.T) {
	var out bytes.Buffer
	opts := browserOpts(&out)
	opts.openURL = func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		base := u.Scheme + "://" + u.Host

		// An unsolicited callback, with no state at all.
		if resp, err := http.Post(base+"/captcha//done", "", nil); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return errors.New("a callback with no state was accepted")
			}
		}

		// A callback with the wrong state.
		if resp, err := http.Post(base+"/captcha/"+strings.Repeat("A", 43)+"/done", "", nil); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return errors.New("a callback with a wrong state was accepted")
			}
		}

		return fakeBrowser(rawURL)
	}

	if _, err := Solve(context.Background(), testChallenge(), opts); err != nil {
		t.Fatalf("Solve() = %v", err)
	}
}

func TestSolve_RootRedirectsToSession(t *testing.T) {
	var out bytes.Buffer
	opts := browserOpts(&out)
	opts.openURL = func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}

		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Get(u.Scheme + "://" + u.Host + "/")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			return fmt.Errorf("GET /: %v, want a redirect", resp.Status)
		}
		if got := resp.Header.Get("Location"); got != u.Path {
			return fmt.Errorf("GET / redirected to %q, want %q", got, u.Path)
		}
		return fakeBrowser(rawURL)
	}

	if _, err := Solve(context.Background(), testChallenge(), opts); err != nil {
		t.Fatalf("Solve() = %v", err)
	}
}

func TestSolve_Errors(t *testing.T) {
	opts := browserOpts(&bytes.Buffer{})

	opts.Mode = ModeDisabled
	if _, err := Solve(context.Background(), testChallenge(), opts); !errors.Is(err, ErrDisabled) {
		t.Errorf("Solve() = %v, want ErrDisabled", err)
	}

	opts.Mode = ModeBrowser
	if _, err := Solve(context.Background(), nil, opts); !errors.Is(err, ErrNoChallenge) {
		t.Errorf("Solve(nil) = %v, want ErrNoChallenge", err)
	}

	hv := &protonmail.HumanVerification{Methods: []string{"sms"}, Token: testToken}
	if _, err := Solve(context.Background(), hv, opts); !errors.Is(err, ErrUnsupportedMethod) {
		t.Errorf("Solve() = %v, want ErrUnsupportedMethod", err)
	}

	opts.ListenAddr = "127.0.0.1:1"
	if _, err := Solve(context.Background(), testChallenge(), opts); !errors.Is(err, ErrListen) {
		t.Errorf("Solve() on a privileged port = %v, want ErrListen", err)
	}

	opts.ListenAddr = "definitely not an address"
	if _, err := Solve(context.Background(), testChallenge(), opts); !errors.Is(err, ErrListen) {
		t.Errorf("Solve() on an invalid address = %v, want ErrListen", err)
	}
}

func newTestHandler() *handler {
	return newHandler("test-state", testChallenge(), time.Now().Add(time.Minute))
}

func TestHandler_StateChecks(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	// A wrong state is rejected.
	resp, err := http.Get(srv.URL + "/captcha/wrong-state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET with a wrong state = %v, want 404", resp.Status)
	}

	// The right state is accepted.
	resp, err = http.Get(srv.URL + "/captcha/test-state")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with the right state = %v, want 200", resp.Status)
	}
	if !strings.Contains(string(body), "verify.proton.me") {
		t.Error("the page doesn't link to Proton's verification page")
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}

	// Completing the challenge works exactly once.
	resp, err = http.Post(srv.URL+"/captcha/test-state/done", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST done = %v, want 200", resp.Status)
	}
	select {
	case <-h.done:
	default:
		t.Fatal("the session wasn't marked as completed")
	}

	// A replayed callback is rejected.
	resp, err = http.Post(srv.URL+"/captcha/test-state/done", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Errorf("replayed POST done = %v, want 410", resp.Status)
	}

	// So is a page reload.
	resp, err = http.Get(srv.URL + "/captcha/test-state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Errorf("GET after completion = %v, want 410", resp.Status)
	}
}

// TestHandler_PageLinksToChallenge checks the page the browser gets: it must
// send the user to Proton's own challenge and take back its result.
func TestHandler_PageLinksToChallenge(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/captcha/test-state")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)

	// The challenge URL is HTML-escaped, so compare against the escaped form.
	hv := testChallenge()
	wantHref := strings.ReplaceAll(hv.CaptchaURL(), "&", "&amp;")
	if !strings.Contains(page, wantHref) {
		t.Errorf("the page doesn't link to %v:\n%v", wantHref, page)
	}
	if !strings.Contains(page, "pm_captcha") {
		t.Error("the page doesn't hand out the listener for the challenge result")
	}
	if !strings.Contains(page, `name="token"`) {
		t.Error("the page has no field to paste the challenge result into")
	}
	if !strings.Contains(page, "/captcha/test-state/done") {
		t.Error("the page doesn't post back to its own session")
	}
	if t.Failed() {
		t.Logf("page:\n%v", page)
	}
}

func TestHandler_RejectsOversizedToken(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	huge := url.Values{"token": {strings.Repeat("A", maxTokenLen+1)}}
	resp, err := http.PostForm(srv.URL+"/captcha/test-state/done", huge)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST with an oversized token = %v, want 400", resp.Status)
	}
	select {
	case <-h.done:
		t.Error("an oversized token completed the session")
	default:
	}
	if h.token() != "" {
		t.Error("an oversized token was recorded")
	}
}

func TestHandler_ExpiredState(t *testing.T) {
	h := newTestHandler()
	h.expiresAt = time.Now().Add(-time.Second)
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/captcha/test-state"},
		{http.MethodPost, "/captcha/test-state/done"},
	} {
		r, err := http.NewRequest(req.method, srv.URL+req.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusGone {
			t.Errorf("%v %v = %v, want 410", req.method, req.path, resp.Status)
		}
	}

	select {
	case <-h.done:
		t.Error("an expired session was completed")
	default:
	}
}

func TestHandler_UnknownPathsAndMethods(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /robots.txt = %v, want 404", resp.Status)
	}

	resp, err = http.Get(srv.URL + "/captcha/test-state/done")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET done = %v, want 405", resp.Status)
	}
	select {
	case <-h.done:
		t.Error("a GET completed the session")
	default:
	}

	resp, err = http.Get(srv.URL + "/captcha/test-state/nope")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET an unknown action = %v, want 404", resp.Status)
	}
}

// TestPreflight checks the challenge pre-check against a stand-in for Proton,
// never the real API.
func TestPreflight(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/core/v4/captcha" {
			t.Errorf("requested %v, want /core/v4/captcha", got)
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()

	old := protonmail.CaptchaEndpoint
	protonmail.CaptchaEndpoint = srv.URL
	defer func() { protonmail.CaptchaEndpoint = old }()

	// A served challenge is silent.
	body = "<!DOCTYPE html><html><body>challenge</body></html>"
	var out bytes.Buffer
	preflight(context.Background(), testChallenge(), &out)
	if out.Len() != 0 {
		t.Errorf("a working challenge warned: %v", out.String())
	}

	// An API error is reported, without disclosing the token.
	body = `{"Code":404,"Error":"Path not found","Details":{}}`
	out.Reset()
	preflight(context.Background(), testChallenge(), &out)
	if !strings.Contains(out.String(), "Path not found") {
		t.Errorf("the API error wasn't reported: %v", out.String())
	}
	if strings.Contains(out.String(), testToken) {
		t.Errorf("the challenge token was disclosed: %v", out.String())
	}
}

func TestIsLoopbackAndWarning(t *testing.T) {
	loopback := []string{"127.0.0.1", "127.0.0.53", "::1", "localhost"}
	for _, host := range loopback {
		if !isLoopback(host) {
			t.Errorf("isLoopback(%q) = false", host)
		}
		var out bytes.Buffer
		warnIfNotLoopback(&out, host)
		if out.Len() != 0 {
			t.Errorf("warnIfNotLoopback(%q) warned: %v", host, out.String())
		}
	}

	exposed := []string{"0.0.0.0", "::", "192.168.0.151", "100.64.1.2", ""}
	for _, host := range exposed {
		if isLoopback(host) {
			t.Errorf("isLoopback(%q) = true", host)
		}
		var out bytes.Buffer
		warnIfNotLoopback(&out, host)
		if !strings.Contains(out.String(), "WARNING") {
			t.Errorf("warnIfNotLoopback(%q) didn't warn", host)
		}
	}
}

func TestDisplayHost(t *testing.T) {
	for host, want := range map[string]string{
		"0.0.0.0":       "127.0.0.1",
		"::":            "::1",
		"":              "127.0.0.1",
		"127.0.0.1":     "127.0.0.1",
		"192.168.0.151": "192.168.0.151",
	} {
		if got := displayHost(host); got != want {
			t.Errorf("displayHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestHostPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	host, port := hostPort(ln.Addr())
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", host)
	}
	if port == "" || port == "0" {
		t.Errorf("port = %q", port)
	}
}
