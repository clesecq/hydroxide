package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/config"
	"github.com/emersion/hydroxide/events"
)

const (
	defaultAPIEndpoint = "https://mail.proton.me/api"
	torAPIEndpoint     = "https://mail.protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/api"
	defaultAppVersion  = "Other"
)

var (
	debug       bool
	apiEndpoint string
	appVersion  string
	proxyURL    string
	tor         bool
)

const usage = `usage: hydroxide [options...] <command>
Commands:
	auth <command> [flags]		Manage authentication
	carddav			Run hydroxide as a CardDAV server
	caldav			Run hydroxide as a CalDAV server
	export-secret-keys <username> Export secret keys
	imap			Run hydroxide as an IMAP server
	import-messages <username> [file]	Import messages
	export-messages [options...] <username>	Export messages
	fetchmail [options...] <username>	Forward newly detected mail to an SMTP server
	sendmail <username> -- <args...>	sendmail(1) interface
	serve			Run all servers
	smtp			Run hydroxide as an SMTP server
	version			Print hydroxide version

AUTH COMMANDS
	login:       Log in to a Proton account
	logout:      Log out of a Proton account
	status:      View all logged in accounts

Options for "auth login":
	-captcha-mode browser|manual|disabled
		How to complete Proton's human verification challenge when it is
		requested, defaults to browser
	-captcha-listen 127.0.0.1:8765
		Address of the local, loopback-only CAPTCHA helper server
	-captcha-timeout 10m
		Maximum time to wait for the challenge to be completed
	-no-open-browser
		Print the CAPTCHA URL instead of trying to launch a browser
	-captcha-endpoint https://mail-api.proton.me
		API host serving the CAPTCHA challenge. It must serve both
		/core/v4/captcha and the widget's assets under /captcha/v1/assets/

Environment variables:
	HYDROXIDE_BRIDGE_PASS	Don't prompt for the bridge password, use this variable instead
	HYDROXIDE_FETCHMAIL_SMTP_PASS	Don't prompt for the fetchmail outbound SMTP relay password, use this variable instead (unrelated to HYDROXIDE_BRIDGE_PASS)
`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.StringVar(&apiEndpoint, "api-endpoint", defaultAPIEndpoint, "ProtonMail API endpoint")
	flag.StringVar(&appVersion, "app-version", defaultAppVersion, "ProtonMail app version")
	flag.StringVar(&proxyURL, "proxy-url", "", "HTTP proxy URL (e.g. socks5://127.0.0.1:1080)")
	flag.BoolVar(&tor, "tor", false, "If set, connect to ProtonMail over Tor")

	listenHost := flag.String("host", "", "Hostname on which all servers listen, overridden by the per-server -*-host options (default 127.0.0.1)")

	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which hydroxide listens, defaults to 1025")
	disableSMTP := flag.Bool("disable-smtp", false, "Disable SMTP for hydroxide serve")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which hydroxide listens, defaults to 1143")
	disableIMAP := flag.Bool("disable-imap", false, "Disable IMAP for hydroxide serve")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which hydroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which hydroxide listens, defaults to 8080")
	disableCardDAV := flag.Bool("disable-carddav", false, "Disable CardDAV for hydroxide serve")

	caldavHost := flag.String("caldav-host", "127.0.0.1", "Allowed CalDAV email hostname on which hydroxide listens, defaults to 127.0.0.1")
	caldavPort := flag.String("caldav-port", "8081", "CalDAV port on which hydroxide listens, defaults to 8081")
	disableCalDAV := flag.Bool("disable-caldav", false, "Disable CalDAV for hydroxide serve")

	tlsCert := flag.String("tls-cert", "", "Path to the certificate to use for incoming connections")
	tlsCertKey := flag.String("tls-key", "", "Path to the certificate key to use for incoming connections")
	tlsClientCA := flag.String("tls-client-ca", "", "If set, clients must provide a certificate signed by the given CA")

	configHome := flag.String("config-home", "", "Path to the directory where hydroxide stores its configuration")

	flag.Usage = func() {
		fmt.Print(usage)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *listenHost != "" {
		explicit := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) {
			explicit[f.Name] = true
		})
		for name, host := range map[string]*string{
			"smtp-host":    smtpHost,
			"imap-host":    imapHost,
			"carddav-host": carddavHost,
			"caldav-host":  caldavHost,
		} {
			if !explicit[name] {
				*host = *listenHost
			}
		}
	}

	if tor && proxyURL == "" {
		log.Fatal("Need -proxy-url to connect to ProtonMail over Tor")
	}

	if tor {
		log.Println("Connecting to ProtonMail over Tor")
		apiEndpoint = torAPIEndpoint
	}

	tlsConfig, err := config.TLS(*tlsCert, *tlsCertKey, *tlsClientCA)
	if err != nil {
		log.Fatal(err)
	}

	if *configHome != "" {
		config.SetConfigHome(*configHome)
	}

	serve := serveConfig{
		smtpAddr:    *smtpHost + ":" + *smtpPort,
		imapAddr:    *imapHost + ":" + *imapPort,
		carddavAddr: *carddavHost + ":" + *carddavPort,
		caldavAddr:  *caldavHost + ":" + *caldavPort,
		tlsConfig:   tlsConfig,
	}

	cmd := flag.Arg(0)
	args := flag.Args()
	if len(args) > 0 {
		args = args[1:]
	}
	switch cmd {
	case "auth":
		runAuth(args)
	case "export-secret-keys":
		runExportSecretKeys(args)
	case "import-messages":
		runImportMessages(args)
	case "export-messages":
		runExportMessages(args)
	case "smtp":
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(serve.smtpAddr, debug, authManager, tlsConfig))
	case "imap":
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(serve.imapAddr, debug, authManager, eventsManager, tlsConfig))
	case "caldav":
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCalDAV(serve.caldavAddr, authManager, eventsManager, tlsConfig))
	case "carddav":
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(serve.carddavAddr, authManager, eventsManager, tlsConfig))
	case "serve":
		if *disableSMTP {
			serve.smtpAddr = ""
		}
		if *disableIMAP {
			serve.imapAddr = ""
		}
		if *disableCardDAV {
			serve.carddavAddr = ""
		}
		if *disableCalDAV {
			serve.caldavAddr = ""
		}
		runServe(serve)
	case "sendmail":
		runSendmail(args)
	case "version":
		fmt.Println(versionString())
	case "fetchmail":
		runFetchmail(args)
	default:
		fmt.Print(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
