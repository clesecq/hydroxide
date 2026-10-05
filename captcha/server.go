package captcha

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

// stateLen is the length in bytes of the random, single-use session
// identifier included in the local URL.
const stateLen = 32

func newState() (string, error) {
	b := make([]byte, stateLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("captcha: failed to generate a random state: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Solve asks the user to complete Proton's challenge in their browser and
// waits for its result. It returns the solved challenge token, which is what
// the API expects back.
//
// A single-use HTTP server is started on a loopback address for the duration
// of the flow, and shut down before returning.
func Solve(ctx context.Context, hv *protonmail.HumanVerification, opts Options) (string, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return "", err
	}
	if opts.Mode == ModeDisabled {
		return "", ErrDisabled
	}
	if hv == nil || hv.Token == "" {
		return "", ErrNoChallenge
	}
	if !hv.HasMethod(protonmail.CaptchaMethod) {
		return "", fmt.Errorf("%w: it offered %v", ErrUnsupportedMethod, hv.Methods)
	}

	state, err := newState()
	if err != nil {
		return "", err
	}

	ln, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("%w on %v: %v", ErrListen, opts.ListenAddr, err)
	}
	defer ln.Close()

	host, port := hostPort(ln.Addr())
	warnIfNotLoopback(opts.Output, host)

	h := newHandler(state, hv, time.Now().Add(opts.Timeout))
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go srv.Serve(ln)
	defer shutdown(srv)

	opts.checkChallenge(ctx, hv, opts.Output)

	localURL := "http://" + net.JoinHostPort(displayHost(host), port) + "/captcha/" + state
	fmt.Fprintf(opts.Output, "\nProton requires human verification (methods offered: %v).\n\nOpen this URL in your browser:\n\n%v\n\n",
		strings.Join(hv.Methods, ", "), localURL)

	if opts.Mode == ModeBrowser && opts.OpenBrowser {
		if err := opts.openURL(localURL); err != nil {
			fmt.Fprintf(opts.Output, "warning: failed to open a browser (%v)\nOpen the URL above manually.\n\n", err)
		}
	}

	fmt.Fprintf(opts.Output, "Waiting for CAPTCHA completion (up to %v, press Ctrl+C to cancel)...\n", opts.Timeout)

	timer := time.NewTimer(opts.Timeout)
	defer timer.Stop()

	select {
	case <-h.done:
		fmt.Fprintf(opts.Output, "\nCAPTCHA accepted.\nContinuing authentication...\n")
		return h.token(), nil
	case <-timer.C:
		return "", fmt.Errorf("%w after %v", ErrTimeout, opts.Timeout)
	case <-ctx.Done():
		return "", fmt.Errorf("%w: %v", ErrCanceled, ctx.Err())
	}
}

// preflight checks that Proton serves the challenge for this token before the
// user is sent to it, so a broken challenge is reported here rather than as an
// empty box in the browser.
//
// It only ever reads the challenge page, and never reports the token itself.
func preflight(ctx context.Context, hv *protonmail.HumanVerification, out io.Writer) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hv.CaptchaURL(), nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "text/html")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(out, "warning: could not reach Proton's challenge at %v: %v\n", originOf(hv.CaptchaURL()), err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return
	}
	if strings.Contains(string(body), "<!DOCTYPE html") {
		return
	}

	// Proton answers with a JSON error, which the browser would render inside
	// the challenge box.
	fmt.Fprintf(out, "\nwarning: %v did not serve the challenge for this login:\n  %v\n"+
		"The challenge box will show this instead of a CAPTCHA. Try another host with -captcha-endpoint.\n",
		originOf(hv.CaptchaURL()), strings.TrimSpace(string(body)))
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		srv.Close()
	}
}

func hostPort(addr net.Addr) (host, port string) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), ""
	}
	return host, port
}

// displayHost returns the host to put in the URL shown to the user. A wildcard
// listener is displayed as loopback, as that's how the user reaches it.
func displayHost(host string) string {
	if host == "" {
		return "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return host
}

// isLoopback reports whether a listener bound to host is only reachable from
// the local machine.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const nonLoopbackWarning = `
!! WARNING: the CAPTCHA helper is listening on %v, which is reachable from
!! outside this machine. Anyone who can reach it can complete the verification
!! challenge on your behalf. Use a loopback address (%v) with SSH port
!! forwarding instead.

`

func warnIfNotLoopback(w io.Writer, host string) {
	if isLoopback(host) {
		return
	}
	shown := host
	if host == "" {
		shown = "all interfaces"
	} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		shown = "all interfaces"
	}
	fmt.Fprintf(w, nonLoopbackWarning, shown, DefaultListenAddr)
}

// handler serves the local, single-use verification page.
type handler struct {
	state      string
	captchaURL string
	verifyURL  string
	expiresAt  time.Time
	now        func() time.Time

	done chan struct{}

	mu     sync.Mutex
	used   bool
	result string // the solved challenge token, never logged nor stored
}

func newHandler(state string, hv *protonmail.HumanVerification, expiresAt time.Time) *handler {
	return &handler{
		state:      state,
		captchaURL: hv.CaptchaURL(),
		verifyURL:  hv.URL(),
		expiresAt:  expiresAt,
		now:        time.Now,
		done:       make(chan struct{}),
	}
}

// token returns the solved challenge token, if the page captured one.
func (h *handler) token() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.result
}

// checkState validates a state value in constant time and reports whether the
// session is still usable.
func (h *handler) checkState(state string) error {
	if len(state) != len(h.state) || subtle.ConstantTimeCompare([]byte(state), []byte(h.state)) != 1 {
		return errUnknownSession
	}

	h.mu.Lock()
	used := h.used
	h.mu.Unlock()

	if used {
		return errUsedSession
	}
	if !h.now().Before(h.expiresAt) {
		return errExpiredSession
	}
	return nil
}

// complete marks the session as used, recording the solved challenge token.
// It returns false if the session was already used.
func (h *handler) complete(token string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.used {
		return false
	}
	h.used = true
	h.result = token
	close(h.done)
	return true
}

var (
	errUnknownSession = fmt.Errorf("unknown verification session")
	errUsedSession    = fmt.Errorf("this verification session has already been completed")
	errExpiredSession = fmt.Errorf("this verification session has expired")
)

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Never leak the session state to Proton (or anyone else) through the
	// Referer header, and never let the page be embedded or cached.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")

	path := strings.TrimSuffix(r.URL.Path, "/")

	if path == "" {
		http.Redirect(w, r, "/captcha/"+h.state, http.StatusFound)
		return
	}

	rest, ok := strings.CutPrefix(path, "/captcha/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	state, action, _ := strings.Cut(rest, "/")

	if err := h.checkState(state); err != nil {
		status := http.StatusNotFound
		if err == errUsedSession || err == errExpiredSession {
			status = http.StatusGone
		}
		h.render(w, status, page{Title: "Verification unavailable", Error: err.Error()})
		return
	}

	switch action {
	case "":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.render(w, http.StatusMethodNotAllowed, page{Title: "Method not allowed", Error: "unexpected request method"})
			return
		}
		h.render(w, http.StatusOK, page{
			Title:      "Proton human verification",
			CaptchaURL: h.captchaURL,
			Snippet:    consoleSnippet,
			VerifyURL:  h.verifyURL,
			DoneURL:    "/captcha/" + h.state + "/done",
		})
	case "done":
		if r.Method != http.MethodPost {
			h.render(w, http.StatusMethodNotAllowed, page{Title: "Method not allowed", Error: "this step must be confirmed from the previous page"})
			return
		}
		// The solved token is the only thing this server ever accepts. Cap the
		// body: nothing legitimate comes close to this size.
		r.Body = http.MaxBytesReader(w, r.Body, maxTokenLen)
		if err := r.ParseForm(); err != nil {
			h.render(w, http.StatusBadRequest, page{Title: "Verification failed", Error: "the challenge result could not be read"})
			return
		}
		if !h.complete(r.PostFormValue("token")) {
			h.render(w, http.StatusGone, page{Title: "Verification unavailable", Error: errUsedSession.Error()})
			return
		}
		h.render(w, http.StatusOK, page{Title: "CAPTCHA accepted", Done: true})
	default:
		http.NotFound(w, r)
	}
}

// maxTokenLen bounds the challenge result the local page may post back.
const maxTokenLen = 8 << 10

type page struct {
	Title      string
	CaptchaURL string
	Snippet    string
	VerifyURL  string
	DoneURL    string
	Done       bool
	Error      string
}

// consoleSnippet listens for the message Proton's challenge posts once it is
// solved, and shows its result so the user can copy it.
//
// The challenge posts to window.parent, which in a normal tab is the tab
// itself, so this listener receives it.
// It listens on window.top rather than window, so it works whichever frame the
// browser console happens to be evaluating in: the challenge page and the
// puzzle it embeds are same-origin.
const consoleSnippet = `window.top.addEventListener('message', function (e) { ` +
	`if (!e.data || e.data.type !== 'pm_captcha') return; ` +
	`var d = window.top.document, t = d.createElement('textarea'); t.value = e.data.token; ` +
	`t.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:5rem;z-index:99999;font-size:16px'; ` +
	`d.body.appendChild(t); t.focus(); t.select(); ` +
	`console.error('HYDROXIDE TOKEN', e.data.token); });`

// originOf returns the scheme://host of a URL, used to check the origin of the
// messages the challenge posts back.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (h *handler) render(w http.ResponseWriter, status int, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	pageTmpl.Execute(w, p)
}

// pageTmpl is fully self-contained: it never loads remote resources, so
// opening it can't be used to profile the user.
var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}} — hydroxide</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }
a.button, button { display: inline-block; font: inherit; padding: .6rem 1rem; border: 1px solid #555; border-radius: .3rem; background: #f6f6f6; color: inherit; text-decoration: none; cursor: pointer; }
pre { white-space: pre-wrap; word-break: break-all; background: #f0f0f0; padding: .6rem; border-radius: .3rem; font-size: .85rem; }
input[type=text] { font: inherit; padding: .5rem; border: 1px solid #888; border-radius: .3rem; }
ol { padding-left: 1.2rem; }
li { margin-bottom: 1rem; }
details { margin-top: 1.5rem; }
summary { cursor: pointer; }
.error { color: #a00; }
.note { color: #555; font-size: .9rem; }
@media (prefers-color-scheme: dark) {
  body { background: #1b1b1b; color: #eee; }
  a { color: #8ab4f8; }
  a.button, button { background: #2c2c2c; border-color: #666; color: #eee; }
  .note { color: #aaa; }
  pre { background: #2c2c2c; }
  input[type=text] { background: #2c2c2c; color: #eee; border-color: #666; }
  .error { color: #f88; }
}
</style>
</head>
<body>
<h1>{{.Title}}</h1>
{{if .Error}}
<p class="error">{{.Error}}</p>
<p class="note">Go back to your terminal and start <code>hydroxide auth login</code> again.</p>
{{else if .Done}}
<p>Thanks. You can close this tab and go back to your terminal.</p>
{{else}}
<p>Proton asked for human verification before this login can continue. The
challenge is served and scored by Proton — hydroxide only carries its result
back to the login request.</p>

<p class="note">Proton only lets its own web apps embed the challenge, so it
can't be shown here. It has to run in its own tab, and its result has to be
copied back.</p>

<ol>
<li>
<p>Copy this line — you'll paste it into the browser console in step 3:</p>
<pre id="snippet">{{.Snippet}}</pre>
<button type="button" onclick="copySnippet()">Copy</button>
</li>
<li><p><a class="button" href="{{.CaptchaURL}}" target="_blank" rel="noopener noreferrer">Open Proton's challenge</a>
in a new tab.</p></li>
<li><p>In that tab, open the developer console (F12, then "Console") and paste
the line from step 1. Firefox and Chrome ask you to type <code>allow pasting</code>
first. Press Enter — it prints <code>undefined</code>, which is correct.</p>
<p>Now solve the CAPTCHA. A text box appears at the top of that tab with the
result already selected — copy it (Ctrl+C).</p></li>
<li>
<p>Paste the result here:</p>
<form method="post" action="{{.DoneURL}}">
<input type="text" name="token" size="40" autocomplete="off" spellcheck="false" required>
<button type="submit">Continue</button>
</form>
</li>
</ol>

<details>
<summary class="note">Other options</summary>
<p class="note">Proton's <a href="{{.VerifyURL}}" target="_blank" rel="noopener noreferrer">verification
page</a> shows the same challenge, but keeps its result to itself, so Proton
rejects the login afterwards. Confirming without a result is only useful for
diagnosing:</p>
<form method="post" action="{{.DoneURL}}">
<button type="submit">Continue without a result</button>
</form>
</details>

<p class="note">No password, session token or cookie is sent to this page. It is
single-use and expires shortly.</p>
<script>
function copySnippet() {
	var text = document.getElementById('snippet').textContent;
	navigator.clipboard.writeText(text);
}
</script>
{{end}}
</body>
</html>
`))
