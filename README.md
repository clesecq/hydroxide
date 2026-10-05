# hydroxide

[![Casual Maintenance Intended](https://casuallymaintained.tech/badge.svg)](https://casuallymaintained.tech/)

A third-party, open-source ProtonMail bridge. For power users only, designed to
run on a server.

> ### About this fork
>
> This is [clesecq/hydroxide](https://github.com/clesecq/hydroxide), a fork of
> [hydroxide](https://codeberg.org/emersion/hydroxide) (upstream, now hosted on
> Codeberg). It combines patches from these forks:
>
> * [Kin69/hydroxide-captcha-fix](https://github.com/Kin69/hydroxide-captcha-fix):
>   Proton now answers many logins with a CAPTCHA challenge, which upstream
>   hydroxide can't complete — `hydroxide auth` just fails. This adds an
>   interactive flow for it, described under [Human verification](#human-verification).
>   It also fixes TLS ALPN negotiation for the IMAP and SMTP servers (they
>   shared the HTTP server's config, so clients offering `imap`/`smtp` were
>   dropped during the handshake) and stops `-debug` from printing passwords,
>   SRP proofs, session tokens and private keys to the log.
> * [acheong08/ferroxide](https://github.com/acheong08/ferroxide): CalDAV
>   support, proxy and Tor support (`-proxy-url`, `-tor`) and a custom
>   configuration directory (`-config-home`).
> * [kelno/hydroxide](https://github.com/kelno/hydroxide): attachment
>   signatures ([emersion/hydroxide#323](https://github.com/emersion/hydroxide/pull/323)),
>   CardDAV contacts encrypted with the user key instead of the address key, so
>   Proton's clients can decrypt them ([emersion/hydroxide#327](https://github.com/emersion/hydroxide/pull/327)),
>   and a Dockerfile.
> * [kLeZ/hydroxide](https://github.com/kLeZ/hydroxide): refresh the access
>   token after the 2FA step, so logins with two-factor authentication no longer
>   fail with `[401] Invalid access token` (emersion/hydroxide#345).
> * [BMGY396/hydroxide](https://github.com/BMGY396/hydroxide): consume Proton
>   event notifications in the CalDAV backend. Without this, the first event
>   blocked the user's event receiver, and IMAP and CardDAV stopped getting
>   updates under `hydroxide serve`.
> * [cjroth/hydroxide](https://github.com/cjroth/hydroxide): CalDAV fixes from
>   its port of [emersion/hydroxide#282](https://github.com/emersion/hydroxide/pull/282)
>   (time-range queries, events with no author, consistent ETags after PUT,
>   MKCALENDAR answered with 501) and event attendees: invitations and RSVP
>   status.

hydroxide supports CardDAV, CalDAV, IMAP and SMTP.

Rationale:

* No GUI, only a CLI (so it runs in headless environments)
* Standard-compliant (we don't care about Microsoft Outlook)
* Fully open-source

Feel free to join the IRC channel: #emersion on Libera Chat.

## How does it work?

hydroxide is a server that translates standard protocols (SMTP, IMAP, CardDAV, CalDAV)
into ProtonMail API requests. It allows you to use your preferred e-mail clients
and `git-send-email` with ProtonMail.

    +-----------------+             +-------------+  ProtonMail  +--------------+
    |                 | IMAP, SMTP  |             |     API      |              |
    |  E-mail client  <------------->  hydroxide  <-------------->  ProtonMail  |
    |                 |             |             |              |              |
    +-----------------+             +-------------+              +--------------+

## Setup

### Go

hydroxide is implemented in Go. Head to [Go website](https://golang.org) for
setup information.

### Installing

Start by installing hydroxide:

```shell
git clone https://github.com/clesecq/hydroxide.git
cd hydroxide
go build ./cmd/hydroxide
```

Then you'll need to login to ProtonMail via hydroxide, so that hydroxide can
retrieve e-mails from ProtonMail. You can do so with this command:

```shell
hydroxide auth login <username>
```

Once you're logged in, a "bridge password" will be printed. Don't close your
terminal yet, as this password is not stored anywhere by hydroxide and will be
needed when configuring your e-mail client.

Your ProtonMail credentials are stored on disk encrypted with this bridge
password (a 32-byte random password generated when logging in).

To list logged in accounts, run `hydroxide auth status`. To log out of an
account and remove its stored credentials, run `hydroxide auth logout <username>`.

### Human verification

Proton often answers `hydroxide auth login` with a CAPTCHA challenge (API error 9001)
before it will accept a login. hydroxide does not solve, bypass or weaken that
challenge — it is served, rendered and scored by Proton throughout. hydroxide
only points you at it and carries its result back to the login request.

When a challenge comes up, `hydroxide auth login` starts a single-use helper server on
`127.0.0.1:8765`, opens your browser on it, and waits. The page walks you
through four steps:

1. Copy the one-line snippet it shows you.
2. Open Proton's challenge in a new tab, using the button on the page.
3. In that tab, open the developer console (<kbd>F12</kbd> → "Console") and
   paste the snippet. Firefox and Chrome make you type `allow pasting` first.
   Press <kbd>Enter</kbd> — it prints `undefined`, which is correct. Now solve
   the CAPTCHA; a text box appears at the top of the tab with the result already
   selected. Copy it.
4. Paste that result back into the hydroxide page and press "Continue".

The console step is needed because Proton only lets its own web apps embed the
challenge, so it can't be shown inline and its result has to be moved by hand.

Once you confirm, authentication is replayed with the challenge result and the
login continues as usual. The helper server shuts down immediately afterwards.

#### Headless servers

There's no browser on a server, so forward the helper's port over SSH and use
`manual` mode, which prints the URL instead of trying to launch anything:

```shell
ssh -L 8765:127.0.0.1:8765 you@your-server
hydroxide auth login -captcha-mode manual <username>
```

Then open the printed URL on your local machine.

Don't bind the helper to a public address to avoid the tunnel. Anyone who can
reach it can complete the verification on your behalf, and hydroxide will warn
you loudly if you do.

#### Options

These apply to `hydroxide auth login` only:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-captcha-mode` | `browser` | `browser` opens the helper page, `manual` only prints its URL, `disabled` reports the API error instead |
| `-captcha-listen` | `127.0.0.1:8765` | Address of the helper server. Keep it on loopback |
| `-captcha-timeout` | `10m` | How long to wait for you to finish |
| `-no-open-browser` | | Print the URL without trying to launch a browser |
| `-captcha-endpoint` | `https://mail-api.proton.me` | API host serving the challenge |

`-captcha-endpoint` is worth knowing about: the host must serve both
`/core/v4/captcha` and the widget's assets under `/captcha/v1/assets/`. Several
Proton hosts serve the first but not the second, and the challenge then loads as
an empty box. hydroxide checks this before sending you to it and tells you if
the host looks wrong.

Verification can only be completed interactively, so a long-running `hydroxide
imap`/`smtp`/`carddav` process that hits a challenge while refreshing its
session can't resolve it on its own. It will tell you to run `hydroxide auth login`
again.

## Usage

hydroxide can be used in multiple modes.

> Don't start hydroxide multiple times, instead you can use `hydroxide serve`.
> This requires ports 1025 (smtp), 1143 (imap), 8080 (carddav) and 8081 (caldav).

### SMTP

To run hydroxide as an SMTP server:

```shell
hydroxide smtp
```

Once the bridge is started, you can configure your e-mail client with the
following settings:

* Hostname: `localhost`
* Port: 1025
* Security: none
* Username: your ProtonMail username
* Password: the bridge password (not your ProtonMail password)

### CardDAV

You must setup an HTTPS reverse proxy to forward requests to `hydroxide`.

```shell
hydroxide carddav
```

Tested on GNOME (Evolution) and Android (DAVDroid).

### CalDAV

```shell
hydroxide caldav
```

Tested on GNOME (Evolution), Thunderbird, KOrganizer.

### IMAP

⚠️  **Warning**: IMAP support is work-in-progress. Here be dragons.

For now, it only supports unencrypted local connections.

```shell
hydroxide imap
```

## Docker

Build the image from a checkout:

```shell
docker build --build-arg VERSION=$(git describe --tags --always) -t hydroxide .
```

Credentials are stored in `/root/.config/hydroxide`, so keep that directory in a
volume. Log in interactively first, then run the servers:

```shell
docker run --rm -it -v hydroxide:/root/.config/hydroxide hydroxide auth login <username>
docker run -d -v hydroxide:/root/.config/hydroxide -p 127.0.0.1:1025:1025 -p 127.0.0.1:1143:1143 \
	hydroxide -smtp-host 0.0.0.0 -imap-host 0.0.0.0 serve
```

Inside the container, hydroxide must listen on `0.0.0.0` for the published ports
to reach it. Publish them on `127.0.0.1` only, unless you also set up TLS.

## Contributing

Upstream is [casually maintained]: pull requests are welcome, but the maintainer
is busy with lots of other things and will be slow to respond. Also see
[CONTRIBUTING.md].

For the changes specific to this fork, open an issue or a pull request here.

## Support

If this fork saved you some time, you can buy me a coffee:
[ko-fi.com/kin69_](https://ko-fi.com/kin69_)

## License

MIT

[casually maintained]: https://casuallymaintained.tech/
[CONTRIBUTING.md]: https://github.com/emersion/.github/blob/main/CONTRIBUTING.md
