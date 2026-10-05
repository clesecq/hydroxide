package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/captcha"
	"github.com/emersion/hydroxide/protonmail"
)

func runAuth(args []string) {
	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	var captchaMode, captchaListen string
	var captchaTimeout time.Duration
	var noOpenBrowser bool
	authCmd.StringVar(&captchaMode, "captcha-mode", string(captcha.ModeBrowser), "CAPTCHA behavior: browser, manual or disabled")
	authCmd.StringVar(&captchaListen, "captcha-listen", captcha.DefaultListenAddr, "Local CAPTCHA callback address")
	authCmd.DurationVar(&captchaTimeout, "captcha-timeout", captcha.DefaultTimeout, "Maximum time to wait for the CAPTCHA to be completed")
	authCmd.BoolVar(&noOpenBrowser, "no-open-browser", false, "Print the CAPTCHA URL without trying to launch a browser")
	captchaEndpoint := authCmd.String("captcha-endpoint", protonmail.CaptchaEndpoint, "API host serving the CAPTCHA challenge")
	authCmd.Parse(args)

	switch authCmd.Arg(0) {
	case "":
		fmt.Println("hydroxide auth")
		fmt.Println()
		fmt.Println("USAGE")
		fmt.Println("  hydroxide auth <command> [flags]")
		fmt.Println()
		fmt.Println("AVAILABLE COMMANDS")
		fmt.Println("  login       Log in to a Proton account")
		fmt.Println("  logout      Log out of a Proton account")
		fmt.Println("  status      View all logged in accounts")
	case "status":
		runAuthStatus()
	case "logout":
		runAuthLogout(authCmd.Arg(1))
	case "login":
		// Accept options after the subcommand too, e.g.
		// "hydroxide auth login -captcha-mode manual <username>"
		authCmd.Parse(authCmd.Args()[1:])
		protonmail.CaptchaEndpoint = *captchaEndpoint
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide auth login [options...] <username>")
		}

		mode, err := captcha.ParseMode(captchaMode)
		if err != nil {
			log.Fatal(err)
		}
		runAuthLogin(username, captcha.Options{
			Mode:        mode,
			ListenAddr:  captchaListen,
			Timeout:     captchaTimeout,
			OpenBrowser: !noOpenBrowser,
			Output:      os.Stderr,
		})
	default:
		log.Fatal("usage: hydroxide auth <command>")
	}
}

func runAuthStatus() {
	usernames, err := auth.ListUsernames()
	if err != nil {
		log.Fatal(err)
	}

	if len(usernames) == 0 {
		fmt.Printf("No logged in user.\n")
	} else {
		fmt.Printf("%v logged in user(s):\n", len(usernames))
		for _, u := range usernames {
			fmt.Printf("- %v\n", u)
		}
	}
}

func runAuthLogout(username string) {
	if username == "" {
		log.Fatal("usage: hydroxide auth logout <username>")
	}

	if err := auth.RemoveUser(username); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Logged out user: %v\n", username)
}

func runAuthLogin(username string, captchaOpts captcha.Options) {
	// Make sure Ctrl+C tears down the CAPTCHA server cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := newClient()

	pass, err := askPass("Password")
	if err != nil {
		log.Fatal(err)
	}
	loginPassword := string(pass)

	a, err := captcha.Authenticate(ctx, c, username, loginPassword, captchaOpts)
	if err != nil {
		log.Fatal(err)
	}

	if a.TwoFactor.Enabled != 0 {
		if a.TwoFactor.TOTP != 1 {
			log.Fatal("Only TOTP is supported as a 2FA method")
		}

		scanner := bufio.NewScanner(os.Stdin)
		fmt.Printf("2FA TOTP code: ")
		scanner.Scan()
		code := scanner.Text()

		scope, err := c.AuthTOTP(code)
		if err != nil {
			log.Fatal(err)
		}
		a.Scope = scope

		// After 2FA the pre-2FA access token is rejected by the API; the
		// /auth/2fa response carries only the elevated scope, not a new token.
		// Refresh to obtain a usable full-scope token (and a rotated refresh token).
		a, err = c.AuthRefresh(a)
		if err != nil {
			log.Fatal(err)
		}
	}

	var mailboxPassword string
	if a.PasswordMode == protonmail.PasswordSingle {
		mailboxPassword = loginPassword
	}
	if mailboxPassword == "" {
		prompt := "Password"
		if a.PasswordMode == protonmail.PasswordTwo {
			prompt = "Mailbox password"
		}
		pass, err := askPass(prompt)
		if err != nil {
			log.Fatal(err)
		}
		mailboxPassword = string(pass)
	}

	keySalts, err := c.ListKeySalts()
	if err != nil {
		log.Fatal(err)
	}

	if _, _, err := c.Unlock(a, keySalts, mailboxPassword); err != nil {
		log.Fatal(err)
	}

	secretKey, bridgePassword, err := auth.GeneratePassword()
	if err != nil {
		log.Fatal(err)
	}

	err = auth.EncryptAndSave(&auth.CachedAuth{
		Auth:            *a,
		LoginPassword:   loginPassword,
		MailboxPassword: mailboxPassword,
		KeySalts:        keySalts,
	}, username, secretKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Bridge password:", bridgePassword)
}
