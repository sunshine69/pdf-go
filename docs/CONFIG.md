# Configuration reference

Every setting `signsrv` reads, taken from `cmd/signsrv/config.go` and
`cmd/signsrv/casubject.go` — not from memory or from another doc.

## The two ways to set anything

For each key there is exactly one config-file name and one environment variable,
related by a single mechanical rule:

```
config key      SIGNSRV_ + UPPER(key)
smtp_starttls -> SIGNSRV_SMTP_STARTTLS
keystore_pass -> SIGNSRV_KEYSTORE_PASS
```

The environment wins over the file. Nothing else transforms a name, and there are
no aliases except one (`db_path`, see below). That means one list of keys, and the
env var is always derived, never remembered.

```sh
# Both of these are the same setting.
echo 'log_level=debug' >> /etc/signsrv/signsrv.env
export SIGNSRV_LOG_LEVEL=debug
```

## The file

`signsrv.env` is `key=value` per line, and the parser is strict on purpose:

- `#` starts a comment; blank lines are skipped.
- A line with no `=` is a hard error (`expected KEY=value`).
- Keys are lower-cased, and a leading `signsrv_` is **stripped**, so
  `SIGNSRV_LOG_LEVEL=debug` in the file works the same as `log_level=debug`. The
  env var needs the prefix; the file does not care.
- Surrounding single or double quotes on a value are trimmed. A value is otherwise
  taken literally to the end of the line, so **do not quote secrets that contain
  spaces or `#`** — a `#` mid-value is not a comment here, but leading/trailing
  spaces are lost.
- An **unknown key is a fatal error**, not a warning. If you typo
  `listen_addres=…`, the service will not start. This is deliberate: a setting that
  silently does nothing is worse than a refused start. The error names the line.

There is no second file for secrets in the code — one file can hold everything. The
shipped deb splits it into `signsrv.env` + `secrets.env` only so the part with
passphrases can be `0600 root` while the rest is world-readable; see
"Two things that will bite you".

```sh
signsrv -config /etc/signsrv/signsrv.env serve
```

`-config` must come before a subcommand or immediately after it; both
`signsrv -config f serve` and `signsrv serve -config f` are accepted. Omit it and
every value falls back to its default plus the environment.

## Every setting

Required = the service refuses to start without it **when `dev=false`**. Under
`dev=true` the validation block is skipped entirely and missing secrets are
generated at start.

### Where it listens

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `listen` | `SIGNSRV_LISTEN` | `127.0.0.1:8080` | no | Bind address. Plain HTTP — a public site needs a TLS proxy in front. Binding outside loopback prints a warning. |
| `public_url` | `SIGNSRV_PUBLIC_URL` | — | **yes** | The external `https://` origin. It builds every signing link, so an invitation is unusable if this is wrong. Must start with `https://` when `dev=false`. |
| `trust_proxy` | `SIGNSRV_TRUST_PROXY` | `false` | no | Trust `X-Forwarded-For` for the client address. **Set to `true` behind any proxy**, or every rate limit binds to the proxy and all your users share one bucket. |

### State on disk

Paths relative to the working directory are resolved by systemd to the service
`User=`'s home, so a deb install gets `/var/lib/signsrv/...` and a manual run gets
whatever `WorkingDirectory` was. Prefer absolute paths.

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `db` | `SIGNSRV_DB` | `var/signsrv.db` | no | SQLite file, or a `postgres://` / `postgresql://` URL. Also accepted as `db_path` (deprecated alias; `db` wins if both are set). |
| `storage_dir` | `SIGNSRV_STORAGE_DIR` | `var/storage` | no | Signed PDFs and their delivery receipts. |
| `keystore_dir` | `SIGNSRV_KEYSTORE_DIR` | `var/keystore` | no | The CA: `ca.key` (encrypted with `keystore_pass`) and `ca.pem`. If you set this, the directory must already exist — the service will not create a path you named. |
| `outbox_dir` | `SIGNSRV_OUTBOX_DIR` | `var/outbox` | no | Where `.eml` files are written when `dev=true` instead of being mailed. |
| `audit_dir` | `SIGNSRV_AUDIT_DIR` | `var/audit` | no | The append-only hash log backing `audit-verify`. |
| `downloads_dir` | `SIGNSRV_DOWNLOADS_DIR` | `""` | no | Optional. Set to keep a copy of each document a party downloaded. |
| `jwt_secret_file` | `SIGNSRV_JWT_SECRET_FILE` | `var/jwt.ed25519.key` | no | Ed25519 key signing access tokens. **Created on first start** if absent — do not generate it yourself, the loader expects its own encoding and refuses a PEM. Must be `0600`. Losing it invalidates every signed-in session. |

### Secrets

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `keystore_pass` | `SIGNSRV_KEYSTORE_PASS` | — | **yes** | Encrypts `ca.key`. **Cannot be changed or regenerated after the CA exists** — a wrong passphrase means the service starts and every signature issued so far reads as invalid. Back this up with the keystore. |
| `admin_password` | `SIGNSRV_ADMIN_PASSWORD` | — | **yes** | Only the password the *seeding step* uses. **It does not create an account** — the one exception is `dev=true`, which seeds `dev@localhost` into an otherwise empty database. See `docs/DEPLOY-DOCKER.md` → *Accounts*. |
| `smtp_pass` | `SIGNSRV_SMTP_PASS` | `""` | no | Relay password. Empty means an unauthenticated relay. |

### Mail

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `smtp_host` | `SIGNSRV_SMTP_HOST` | — | **yes** | Relay host. Unset with `dev=false` is fatal; with `dev=true` mail is written to `outbox_dir`. |
| `smtp_port` | `SIGNSRV_SMTP_PORT` | `587` | no | Relay port. |
| `smtp_user` | `SIGNSRV_SMTP_USER` | `""` | no | Relay username. |
| `smtp_starttls` | `SIGNSRV_SMTP_STARTTLS` | **`true`** | no | Note the default: a relay that does not advertise STARTTLS needs `false`, or every invitation fails with something that reads like a network fault. |
| `mail_from` | `SIGNSRV_MAIL_FROM` | — | **yes** | Envelope sender on every invitation. |

### Signing policy

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `link_ttl` | `SIGNSRV_LINK_TTL` | `168h` | no | Signing-link lifetime. Go duration, max `720h`. |
| `max_pdf_mb` | `SIGNSRV_MAX_PDF_MB` | `25` | no | Upload ceiling. 1–200. |
| `tsa_url` | `SIGNSRV_TSA_URL` | `https://freetsa.org/tsr` | no | RFC 3161 timestamp authority. Empty uses the default. Over `http://` warns: the timestamp is the one field a forged document needs, and it would be unauthenticated. |
| `worker_interval` | `SIGNSRV_WORKER_INTERVAL` | `15s` | no | How often the queue is drained. |

### CA subject (only matters at first CA creation)

All optional, all empty by default; `signsrv` fills a sensible default subject for
this host when they are unset. Changing them **after** the CA exists does nothing to
the existing certificate.

| Key | Env var |
| --- | --- |
| `ca_common_name` | `SIGNSRV_CA_COMMON_NAME` |
| `ca_org` | `SIGNSRV_CA_ORG` |
| `ca_unit` | `SIGNSRV_CA_UNIT` |
| `ca_locality` | `SIGNSRV_CA_LOCALITY` |
| `ca_province` | `SIGNSRV_CA_PROVINCE` |
| `ca_street` | `SIGNSRV_CA_STREET` |
| `ca_postal` | `SIGNSRV_CA_POSTAL` |
| `ca_country` | `SIGNSRV_CA_COUNTRY` |
| `ca_email` | `SIGNSRV_CA_EMAIL` |

### Logging

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `log_level` | `SIGNSRV_LOG_LEVEL` | `info` | no | `debug`, `info`, `warn`/`warning`, `error`. |
| `log_path` | `SIGNSRV_LOG_PATH` | `var/log/signsrv.jsonl` | no | JSON-lines log file. |
| `dev` | `SIGNSRV_DEV` | `false` | no | Off the ground: skips validation, generates missing secrets, writes mail to `outbox_dir`, and seeds `dev@localhost` with the admin password (ephemeral, printed to the log, when the config has none). **Never `true` in production** — it is the one mode that creates an account by itself. |

## Environment variables that are not settings

Four variables are read by a *command*, once, instead of being config keys. They
look like settings and are not, which is the main trap in this scheme:

| Variable | Read by | Purpose |
| --- | --- | --- |
| `SIGNSRV_ADMIN_PASSWORD` | `admin add`, `admin passwd` | The password for the account being created or rotated. Falls back to a terminal prompt if unset. Also a config key (above). |
| `SIGNSRV_USER_PASSWORD` | `user add` | Password/secret for an SPA user account. **Not a config key** — setting it in the file does nothing. |
| `SIGNSRV_KEYSTORE_PASS` | `firstboot`, `checkconfig` | Seed value for the passphrase. Also a config key. |
| `SIGNSRV_SMTP_PASS` | `firstboot` | Seed value for the relay password. Also a config key. |

## Two things that will bite you

**`source` does not export.** If a secrets file is loaded by hand, `source` makes
shell variables the Go process never sees:

```sh
source /etc/signsrv/secrets.env      # invisible to signsrv
set -a; . /etc/signsrv/secrets.env   # exported, and visible
```

systemd does not have this problem — `EnvironmentFile=` exports — which is why a
service works and the same command in your shell does not.

**Some subcommands validate the whole server config.** `admin list`, `admin add`,
`client`, `user`, `dbstatus` only need the database path, but they run the same
validation as `serve`. So on a `dev=false` host with the passphrase in a separate
file, `admin list` fails with `keystore_pass is required` while the service is
serving traffic happily. That is a defect, not a requirement; it is fixed by passing
the secrets in the same environment the service has.

## Checking a config

```sh
signsrv -config /etc/signsrv/signsrv.env checkconfig
```

Exits non-zero on anything `serve` would refuse, and prints warnings it would run
anyway. Never prints a secret value. Run it before every start, and after any edit.

## A complete production file

```sh
# /etc/signsrv/signsrv.env   mode 0600, root:signsrv
listen=127.0.0.1:8080
public_url=https://signsrv.example.org
trust_proxy=true

db=/var/lib/signsrv/signsrv.db
storage_dir=/var/lib/signsrv/storage
keystore_dir=/var/lib/signsrv/keystore
outbox_dir=/var/lib/signsrv/outbox
audit_dir=/var/lib/signsrv/audit
jwt_secret_file=/var/lib/signsrv/jwt.ed25519.key

mail_from=signer@example.org
smtp_host=smtp.example.org
smtp_port=587
smtp_user=signer@example.org
smtp_starttls=true

keystore_pass=<backup this before anything else>
admin_password=<used only to seed; no account is created by it>

link_ttl=168h
max_pdf_mb=25
tsa_url=https://freetsa.org/tsr
worker_interval=15s

log_level=info
log_path=/var/log/signsrv/signsrv.jsonl
dev=false
```

Then, because no account exists yet, `admin add` before you try `/admin/`:

```sh
signsrv -config /etc/signsrv/signsrv.env admin add you@example.org
```
