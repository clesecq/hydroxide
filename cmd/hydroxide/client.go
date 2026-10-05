package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/protonmail"
)

func makeHTTPClientFromProxy(proxyArg string) (*http.Client, error) {
	fmtProxy := ""
	if tor {
		un, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		// Tor requires socks5. To keep the same format as without tor, we allow
		// the user to specify socks5:// in the proxy URL.
		// But we remove it
		proxyArg = strings.TrimPrefix(proxyArg, "socks5://")
		fmtProxy = fmt.Sprintf("socks5://hydroxide_%s::@%s", un, proxyArg)
	} else {
		if !strings.Contains(proxyArg, "://") {
			// Assume socks5:// if no scheme is provided
			proxyArg = "socks5://" + proxyArg
		}
		fmtProxy = proxyArg
	}

	proxy, err := url.Parse(fmtProxy)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}
	return &http.Client{Transport: tr}, nil
}

func newClient() *protonmail.Client {
	// Proton's API hands out a session cookie on /auth/info and expects it
	// back on the requests that follow. Without a jar every request looks like
	// a brand new, sessionless client, which the API treats with suspicion.
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("failed to create cookie jar: %v", err)
	}

	httpClient := &http.Client{}
	if proxyURL != "" {
		httpClient, err = makeHTTPClientFromProxy(proxyURL)
		if err != nil {
			log.Fatal("Error creating proxied http.Client: ", err)
		}
	}
	httpClient.Jar = jar

	return &protonmail.Client{
		RootURL:    apiEndpoint,
		AppVersion: appVersion,
		Debug:      debug,
		HTTPClient: httpClient,
	}
}

func askPass(prompt string) ([]byte, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		// This can happen if stdin is used for piping data
		// TODO: the following assumes Unix
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	if err == nil {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return b, err
}

func askBridgePass() (string, error) {
	if v := os.Getenv("HYDROXIDE_BRIDGE_PASS"); v != "" {
		return v, nil
	}
	b, err := askPass("Bridge password")
	return string(b), err
}

// authenticate asks for the bridge password of a logged in user and returns
// an unlocked client, exiting on failure.
func authenticate(username string) (*protonmail.Client, openpgp.EntityList) {
	bridgePassword, err := askBridgePass()
	if err != nil {
		log.Fatal(err)
	}

	c, privateKeys, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
	if err != nil {
		log.Fatal(err)
	}
	return c, privateKeys
}
