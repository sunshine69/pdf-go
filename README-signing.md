# Running the signing service

`signsrv` is the service; `pdf-go` is the CLI that prepares documents and
drives the service. Both are one static binary, embedding the two web apps.

## Development

```sh
go build -o /tmp/signsrv ./cmd/signsrv
/tmp/signsrv checkconfig -config /tmp/signsrv-dev.conf   # must say "config ok"
SIGNSRV_ADMIN_PASSWORD=change-me /tmp/signsrv serve -config /tmp/signsrv-dev.conf
curl -s localhost:8090/healthz
```

Dev mode (`dev=true`) is allowed only on a loopback listener: SMTP is
disabled and every message is written as a `.eml` file into `outbox_dir`, so
you can read the invitation and click the link. `checkconfig` prints the
effective configuration with every secret masked as a digest.

The two apps are served from the binary: signers at `/s/<token>`, admins at
`/admin/`, their assets under `/assets/spa/` and `/assets/admin/`.

## Configuration

`config.example.env` documents every key. A key is read from `SIGNSRV_<KEY>`
in the environment first, then from the file given with `-config`; the
environment wins. Secrets (`keystore_pass`, `admin_password`, `smtp_pass`)
are never logged and never appear in `checkconfig` output.

Outside dev mode the service refuses to start when:

- `public_url` is missing or not `https://` — the signing link *is* the
  credential, so it must not travel in clear text;
- `smtp_host` or `mail_from` is missing;
- `keystore_pass` is missing — it encrypts the signing CA key;
- `admin_password` is missing — it seeds the admin account at first start.

## Production

- Run it behind TLS (Caddy/nginx). `public_url` must match what signers see.
- Set `SIGNSRV_KEYSTORE_PASS`, `SIGNSRV_ADMIN_PASSWORD` and `SIGNSRV_SMTP_PASS`
  in the environment, not in the file: the file then needs no secret.
- Serve with the `signsrv` user, `UMask=0027` (systemd unit in `deploy/`).
  The first start creates the keystore, the JWT key and the database.
- `admin_password` is only used once, to create the admin account. After
  that, change the password in the app; the value in the config is inert.
- Log to `log_path` as JSON, rotated with copytruncate (`deploy/logrotate.conf`).

## First run

```sh
signsrv serve -config /etc/signsrv/signsrv.env &   # starts the API, apps, worker
# sign in at /admin/, create a machine client, copy its token once
pdf-go envelope create --server https://sign.example.org --title "NDA" \
     --field name="Ann Miller" --party 1=ann@x.com --party 2=bob@y.com --send
signsrv audit-verify -config ... # re-verify every completed document
```

## Troubleshooting

- `signsrv: unknown config key "x"` — typo in the config file; see
  `config.example.env` for the accepted names.
- `dev mode is only allowed on a loopback listener` — `dev=true` with a
  public `listen`. Remove `dev` or bind to 127.0.0.1.
- A signing link shows "link is not valid" — the token was used, expired,
  reissued, or the envelope was cancelled. An admin can reissue links.
- Mail sits in `outbox_dir` — you are in dev mode by design.
- Every request has an `X-Request-Id` header, present in the log line for
  that request; quote it when reporting problems. Tokens and secrets never
  appear in the log.
