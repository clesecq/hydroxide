// Package captcha implements Proton's interactive human verification flow.
//
// Proton sometimes answers authentication requests with API error 9001,
// asking for a CAPTCHA to be completed before the request can be replayed.
// hydroxide doesn't bypass, solve or weaken that challenge: it points the
// user's own browser at the Proton-operated verification page, waits for the
// user to complete it there, and then replays the authentication request with
// the human verification headers Proton expects.
//
// The flow implemented here mirrors the one used by Proton's own clients, see
// ProtonMail/go-proton-api (hv.go) and ProtonMail/proton-bridge (internal/hv).
package captcha

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

// Mode selects how the user is asked to complete a challenge.
type Mode string

const (
	// ModeBrowser starts the local helper and tries to open a browser on it.
	ModeBrowser Mode = "browser"
	// ModeManual starts the local helper but only prints its URL. Use this on
	// headless machines, together with SSH port forwarding.
	ModeManual Mode = "manual"
	// ModeDisabled turns human verification handling off: the original API
	// error is reported to the user instead.
	ModeDisabled Mode = "disabled"
)

// ParseMode parses a -captcha-mode flag value.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeBrowser:
		return ModeBrowser, nil
	case ModeManual:
		return ModeManual, nil
	case ModeDisabled:
		return ModeDisabled, nil
	default:
		return "", fmt.Errorf("captcha: invalid mode %q (want browser, manual or disabled)", s)
	}
}

// Defaults for Options.
const (
	DefaultListenAddr = "127.0.0.1:8765"
	DefaultTimeout    = 10 * time.Minute
)

// Options configures the interactive human verification flow.
type Options struct {
	// Mode selects how the user is asked to complete the challenge.
	Mode Mode
	// ListenAddr is the address of the local helper server. It should always
	// be a loopback address: anyone able to reach it can complete the
	// challenge on the user's behalf.
	ListenAddr string
	// Timeout bounds how long we wait for the user.
	Timeout time.Duration
	// OpenBrowser tries to launch a browser. Ignored unless Mode is
	// ModeBrowser.
	OpenBrowser bool
	// Output receives the user-facing instructions. Defaults to os.Stderr.
	Output io.Writer

	// openURL is a test hook standing in for the user's browser.
	openURL func(url string) error
	// checkChallenge is a test hook standing in for the preflight request to
	// Proton. Tests never reach the network.
	checkChallenge func(ctx context.Context, hv *protonmail.HumanVerification, out io.Writer)
}

// Errors reported by this package. They are always wrapped with more context,
// use errors.Is to test for them.
var (
	ErrDisabled          = errors.New("captcha: human verification is required, but CAPTCHA handling is disabled")
	ErrNoChallenge       = errors.New("captcha: the API response doesn't carry a challenge")
	ErrUnsupportedMethod = errors.New("captcha: the API doesn't offer the CAPTCHA verification method")
	ErrListen            = errors.New("captcha: failed to start the local verification server")
	ErrTimeout           = errors.New("captcha: timed out waiting for the challenge to be completed")
	ErrCanceled          = errors.New("captcha: canceled")
	ErrRejected          = errors.New("captcha: the challenge was rejected by Proton")
)

func (opts Options) withDefaults() (Options, error) {
	if opts.Mode == "" {
		opts.Mode = ModeBrowser
	} else if _, err := ParseMode(string(opts.Mode)); err != nil {
		return opts, err
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = DefaultListenAddr
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Output == nil {
		opts.Output = os.Stderr
	}
	if opts.openURL == nil {
		opts.openURL = openURL
	}
	if opts.checkChallenge == nil {
		opts.checkChallenge = preflight
	}
	return opts, nil
}

// Client is the subset of *protonmail.Client used to authenticate.
type Client interface {
	AuthWithVerification(username, password string, info *protonmail.AuthInfo, hv *protonmail.HumanVerification) (*protonmail.Auth, error)
}

// Authenticate performs SRP authentication, handling at most one human
// verification challenge.
//
// When Proton asks for human verification, the user is directed to Proton's
// own verification page; once they report having completed it, the
// authentication request is replayed exactly once with the human verification
// headers. Any further challenge is reported as an error instead of looping.
func Authenticate(ctx context.Context, c Client, username, password string, opts Options) (*protonmail.Auth, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}

	auth, err := c.AuthWithVerification(username, password, nil, nil)
	if err == nil {
		return auth, nil
	}

	hv, hvErr := challenge(err)
	if hv == nil {
		if hvErr != nil {
			// A human verification error we can't act on.
			return nil, hvErr
		}
		return nil, err
	}

	if opts.Mode == ModeDisabled {
		return nil, fmt.Errorf("%w: %v", ErrDisabled, err)
	}

	solved, err := Solve(ctx, hv, opts)
	if err != nil {
		return nil, err
	}
	hv.SolvedMethod = protonmail.CaptchaMethod
	if solved != "" {
		// The challenge result, "<challenge token>:<response>", is what the
		// API validates.
		fmt.Fprintf(opts.Output, "Challenge result received from Proton's page (%v bytes).\n", len(solved))
		hv.Token = solved
	} else {
		// The user confirmed without the challenge running locally: replay the
		// bare token and let the API decide. It usually says no.
		fmt.Fprintf(opts.Output, "warning: no challenge result was captured, only the bare challenge token can be replayed.\n"+
			"This happens when the challenge didn't load in hydroxide's page and the fallback button was used.\n")
	}

	auth, err = c.AuthWithVerification(username, password, nil, hv)
	if err == nil {
		return auth, nil
	}

	var apiErr *protonmail.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.IsHumanVerificationRequired():
			return nil, fmt.Errorf("%w: Proton asked for human verification again after the challenge was completed; "+
				"make sure the challenge was solved in the browser before continuing, then try again: %v", ErrRejected, err)
		case apiErr.Code == protonmail.CodeHumanVerificationInvalidToken:
			return nil, fmt.Errorf("%w: the challenge was not completed, already used or has expired. "+
				"Make sure Proton's page says the verification succeeded before confirming here, then try again: %v", ErrRejected, err)
		}
	}
	return nil, err
}

// challenge extracts a human verification challenge from an API error.
//
// It returns (nil, nil) when err isn't a human verification error, and
// (nil, err) when it is one we can't act on.
func challenge(err error) (*protonmail.HumanVerification, error) {
	var apiErr *protonmail.APIError
	if !errors.As(err, &apiErr) || !apiErr.IsHumanVerificationRequired() {
		return nil, nil
	}

	hv, parseErr := apiErr.HumanVerification()
	if parseErr != nil {
		return nil, parseErr
	}
	if !hv.HasMethod(protonmail.CaptchaMethod) {
		return nil, fmt.Errorf("%w: it offered %v; complete the verification in the Proton web app, then retry",
			ErrUnsupportedMethod, hv.Methods)
	}
	return hv, nil
}
