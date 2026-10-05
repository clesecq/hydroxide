package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/emersion/hydroxide/config"
	"github.com/emersion/hydroxide/fetchmail"
)

func runFetchmail(args []string) {
	cmd := flag.NewFlagSet("fetchmail", flag.ExitOnError)
	var folders, rcpt, idfile, smtpHost, smtpPort, smtpUser, envelopeFrom string
	var all, markSeen, smtpStartTLS, lmtp bool
	var deleteAfterDays int
	var daemonInterval time.Duration

	cmd.StringVar(&folders, "folder", "Inbox", "comma-separated list of Proton folders to poll")
	cmd.BoolVar(&all, "all", false, "forward all messages in scope, ignoring the dedup state")
	cmd.StringVar(&idfile, "idfile", "", "path to the fetchmail state file (default: <config dir>/<username>-fetchids.json)")
	cmd.BoolVar(&markSeen, "markseen", false, "mark forwarded messages as read in Proton")
	cmd.IntVar(&deleteAfterDays, "deleteafter", 0, "delete messages from Proton this many days after they were forwarded (0 disables)")
	cmd.StringVar(&smtpHost, "smtp-host", "", "outbound relay hostname (required)")
	cmd.StringVar(&smtpPort, "smtp-port", "25", "outbound relay port")
	cmd.BoolVar(&smtpStartTLS, "smtp-starttls", true, "use STARTTLS with the outbound relay if offered (SMTP only, no effect with -lmtp)")
	cmd.StringVar(&smtpUser, "smtp-user", "", "username for outbound relay authentication (optional, unrelated to the bridge password)")
	cmd.BoolVar(&lmtp, "lmtp", false, "deliver via LMTP instead of SMTP to the relay at -smtp-host/-smtp-port (no STARTTLS support in this mode)")
	cmd.StringVar(&envelopeFrom, "envelope-from", "", "override the SMTP envelope sender (default: the message's own sender)")
	cmd.StringVar(&rcpt, "rcpt", "", "comma-separated list of recipients (default: the message's own To/Cc/Bcc)")
	cmd.DurationVar(&daemonInterval, "daemon", 0, "run continuously, polling every interval (e.g. 1m); default runs once and exits")
	cmd.Parse(args)

	username := cmd.Arg(0)
	if username == "" || smtpHost == "" {
		log.Fatal("usage: hydroxide fetchmail -smtp-host <host> [options...] <username>")
	}

	labels, err := fetchmail.ResolveFolders(strings.Split(folders, ","))
	if err != nil {
		log.Fatal(err)
	}

	if idfile == "" {
		idfile, err = config.Path(username + "-fetchids.json")
		if err != nil {
			log.Fatal(err)
		}
	}

	var rcptList []string
	if rcpt != "" {
		rcptList = strings.Split(rcpt, ",")
	}

	// The outbound SMTP relay password is a separate secret from the
	// Proton bridge password below: it authenticates to whatever relay
	// -smtp-host points at, and is only needed if -smtp-user is set.
	var smtpPass string
	if smtpUser != "" {
		if v := os.Getenv("HYDROXIDE_FETCHMAIL_SMTP_PASS"); v != "" {
			smtpPass = v
		} else {
			pass, err := askPass("SMTP relay password")
			if err != nil {
				log.Fatal(err)
			}
			smtpPass = string(pass)
		}
	}

	// The Proton bridge password is always required, regardless of
	// whether the SMTP relay needs authentication.
	c, privateKeys := authenticate(username)

	cfg := &fetchmail.Config{
		Folders:         labels,
		All:             all,
		MarkSeen:        markSeen,
		DeleteAfterDays: deleteAfterDays,
		SMTPHost:        smtpHost,
		SMTPPort:        smtpPort,
		SMTPStartTLS:    smtpStartTLS,
		SMTPUser:        smtpUser,
		SMTPPass:        smtpPass,
		LMTP:            lmtp,
		EnvelopeFrom:    envelopeFrom,
		Rcpt:            rcptList,
	}

	if daemonInterval <= 0 {
		// Cron mode: run a single pass and exit. The state file at
		// idfile makes repeated invocations (e.g. from cron) safe.
		if err := fetchmail.RunOnce(c, privateKeys, idfile, cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	log.Printf("fetchmail running as a daemon, polling every %v", daemonInterval)
	for {
		if err := fetchmail.RunOnce(c, privateKeys, idfile, cfg); err != nil {
			log.Println("fetchmail pass failed:", err)
		}
		time.Sleep(daemonInterval)
	}
}
