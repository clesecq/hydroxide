package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-smtp"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/caldav"
	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/events"
	imapbackend "github.com/emersion/hydroxide/imap"
	"github.com/emersion/hydroxide/protonmail"
	smtpbackend "github.com/emersion/hydroxide/smtp"
)

// serveConfig holds the listen addresses of the servers. An empty address
// disables the corresponding server in "hydroxide serve".
type serveConfig struct {
	smtpAddr    string
	imapAddr    string
	carddavAddr string
	caldavAddr  string
	tlsConfig   *tls.Config
}

// tlsConfigFor returns a copy of the TLS configuration advertising the ALPN
// protocol of a given service (RFC 8314).
//
// The copy matters: the servers would otherwise share one config, and the HTTP
// server sets NextProtos on it for HTTP/2. Clients asking for "imap" or "smtp"
// then find no protocol in common and every connection is dropped.
func tlsConfigFor(tlsConfig *tls.Config, proto string) *tls.Config {
	if tlsConfig == nil {
		return nil
	}
	c := tlsConfig.Clone()
	c.NextProtos = []string{proto}
	return c
}

func listenAndServeSMTP(addr string, debug bool, authManager *auth.Manager, tlsConfig *tls.Config) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost" // TODO: make this configurable
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfigFor(tlsConfig, "smtp")
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("SMTP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfigFor(tlsConfig, "imap")
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("IMAP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("IMAP server listening on", s.Addr)
	return s.ListenAndServe()
}

// newDAVHandlerFunc creates the per-user handler of a DAV server, fed with the
// user's events.
type newDAVHandlerFunc func(c *protonmail.Client, privateKeys openpgp.EntityList, primaryKeyID uint64, username string, events <-chan *protonmail.Event) http.Handler

// davAuthHandler authenticates requests with HTTP basic auth and dispatches
// them to a handler created once per user.
func davAuthHandler(authManager *auth.Manager, eventsManager *events.Manager, newHandler newDAVHandlerFunc) http.Handler {
	var mu sync.Mutex
	handlers := make(map[string]http.Handler)

	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Set("WWW-Authenticate", "Basic")

		username, password, ok := req.BasicAuth()
		if !ok {
			resp.WriteHeader(http.StatusUnauthorized)
			io.WriteString(resp, "Credentials are required")
			return
		}

		c, privateKeys, primaryKeyID, err := authManager.Auth(username, password)
		if err != nil {
			if err == auth.ErrUnauthorized {
				resp.WriteHeader(http.StatusUnauthorized)
			} else {
				resp.WriteHeader(http.StatusInternalServerError)
			}
			io.WriteString(resp, err.Error())
			return
		}

		// Requests are served concurrently: the lock also keeps two first
		// requests from registering the same user twice.
		mu.Lock()
		h, ok := handlers[username]
		if !ok {
			ch := make(chan *protonmail.Event)
			eventsManager.Register(c, username, ch, nil)
			h = newHandler(c, privateKeys, primaryKeyID, username, ch)

			handlers[username] = h
		}
		mu.Unlock()

		h.ServeHTTP(resp, req)
	})
}

func listenAndServeCalDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: davAuthHandler(authManager, eventsManager, func(c *protonmail.Client, privateKeys openpgp.EntityList, _ uint64, username string, events <-chan *protonmail.Event) http.Handler {
			return caldav.NewHandler(c, privateKeys, username, events)
		}),
	}

	if s.TLSConfig != nil {
		log.Println("CalDAV server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	log.Println("CalDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCardDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: davAuthHandler(authManager, eventsManager, func(c *protonmail.Client, privateKeys openpgp.EntityList, primaryKeyID uint64, _ string, events <-chan *protonmail.Event) http.Handler {
			return carddav.NewHandler(c, privateKeys, primaryKeyID, events)
		}),
	}

	if s.TLSConfig != nil {
		log.Println("CardDAV server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	log.Println("CardDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func runServe(cfg serveConfig) {
	authManager := auth.NewManager(newClient)
	eventsManager := events.NewManager()

	done := make(chan error, 4)
	if cfg.smtpAddr != "" {
		go func() {
			done <- listenAndServeSMTP(cfg.smtpAddr, debug, authManager, cfg.tlsConfig)
		}()
	}
	if cfg.imapAddr != "" {
		go func() {
			done <- listenAndServeIMAP(cfg.imapAddr, debug, authManager, eventsManager, cfg.tlsConfig)
		}()
	}
	if cfg.carddavAddr != "" {
		go func() {
			done <- listenAndServeCardDAV(cfg.carddavAddr, authManager, eventsManager, cfg.tlsConfig)
		}()
	}
	if cfg.caldavAddr != "" {
		go func() {
			done <- listenAndServeCalDAV(cfg.caldavAddr, authManager, eventsManager, cfg.tlsConfig)
		}()
	}
	log.Fatal(<-done)
}
