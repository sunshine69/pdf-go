# Configuration reference

Every setting `signsrv` reads, taken from `cmd/signsrv/config.go` and
`cmd/signsrv/casubject.go` — not from memory or from another doc.

## The two ways to set anything

For each key there is exactly one config-file name and one environment variable,
related by a single mechanical rule:

```
config key       + UPPER(key)
smtp_starttls -> SMTP_STARTTLS
keystore_pass -> KEYSTORE_PASS
```

The environment wins over the file. Nothing else transforms a name, and there are
no aliases except one (`db_path`, see below). That means one list of keys, and the
env var is always derived, never remembered.

```sh
# Both of these are the same setting.
echo 'log_level=debug' >> /etc/signsrv/signsrv.env
export LOG_LEVEL=debug
```

## The file

`signsrv.env` is `key=value` per line, and the parser is strict on purpose:

- `#` starts a comment; blank lines are skipped.
- A line with no `=` is a hard error (`expected KEY=value`).
- Keys are lower-cased. **One name per setting**: the key as it is, lowercased,
  in the file, and the same name uppercased in the environment. There is no
  product prefix to remember and no second spelling to fall back to —
  `LOG_LEVEL` and `log_level` name the same setting, and `SIGNSRV_LOG_LEVEL`
  names nothing, so it is ignored.
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
| `listen` | `LISTEN` | `127.0.0.1:8080` | no | Bind address. Plain HTTP — a public site needs a TLS proxy in front. Binding outside loopback prints a warning. |
| `public_url` | `PUBLIC_URL` | — | **yes** | The external `https://` origin. It builds every signing link, so an invitation is unusable if this is wrong. Must start with `https://` when `dev=false`. |
| `trust_proxy` | `TRUST_PROXY` | `false` | no | Trust `X-Forwarded-For` for the client address. **Set to `true` behind any proxy**, or every rate limit binds to the proxy and all your users share one bucket. |

### State on disk

Paths relative to the working directory are resolved by systemd to the service
`User=`'s home, so a deb install gets `/var/lib/signsrv/...` and a manual run gets
whatever `WorkingDirectory` was. Prefer absolute paths.

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `db` | `DB` | `var/signsrv.db` | no | SQLite file, or a `postgres://` / `postgresql://` URL. Also accepted as `db_path` (deprecated alias; `db` wins if both are set). |
| `storage_dir` | `STORAGE_DIR` | `var/storage` | no | Signed PDFs and their delivery receipts. |
| `keystore_dir` | `KEYSTORE_DIR` | `var/keystore` | no | The CA: `ca.key` (encrypted with `keystore_pass`) and `ca.pem`. If you set this, the directory must already exist — the service will not create a path you named. |
| `outbox_dir` | `OUTBOX_DIR` | `var/outbox` | no | Where `.eml` files are written when `dev=true` instead of being mailed. |
| `audit_dir` | `AUDIT_DIR` | `var/audit` | no | The append-only hash log backing `audit-verify`. |
| `downloads_dir` | `DOWNLOADS_DIR` | `""` | no | Optional. Set to keep a copy of each document a party downloaded. |
| `jwt_secret_file` | `JWT_SECRET_FILE` | `var/jwt.ed25519.key` | no | Ed25519 key signing access tokens. **Created on first start** if absent — do not generate it yourself, the loader expects its own encoding and refuses a PEM. Must be `0600`. Losing it invalidates every signed-in session. |

### Secrets

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `keystore_pass` | `KEYSTORE_PASS` | — | **yes** | Encrypts `ca.key`. **Cannot be changed or regenerated after the CA exists** — a wrong passphrase means the service starts and every signature issued so far reads as invalid. Back this up with the keystore. |
| `admin_password` | `ADMIN_PASSWORD` | — | **yes** | Only the password the *seeding step* uses. **It does not create an account** — the one exception is `dev=true`, which seeds `dev@localhost` into an otherwise empty database. See `docs/DEPLOY-DOCKER.md` → *Accounts*. |
| `smtp_pass` | `SMTP_PASS` | `""` | no | Relay password. Empty means an unauthenticated relay. |

### Mail

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `smtp_host` | `SMTP_HOST` | — | **yes** | Relay host. Unset with `dev=false` is fatal; with `dev=true` mail is written to `outbox_dir`. |
| `smtp_port` | `SMTP_PORT` | `587` | no | Relay port. |
| `smtp_user` | `SMTP_USER` | `""` | no | Relay username. |
| `smtp_starttls` | `SMTP_STARTTLS` | **`true`** | no | Note the default: a relay that does not advertise STARTTLS needs `false`, or every invitation fails with something that reads like a network fault. |
| `mail_from` | `MAIL_FROM` | — | **yes** | Envelope sender on every invitation. |

### Signing policy

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `link_ttl` | `LINK_TTL` | `168h` | no | Signing-link lifetime. Go duration, max `720h`. |
| `max_pdf_mb` | `MAX_PDF_MB` | `25` | no | Upload ceiling. 1–200. |
| `tsa_url` | `TSA_URL` | `https://freetsa.org/tsr` | no | RFC 3161 timestamp authority. Empty uses the default. Over `http://` warns: the timestamp is the one field a forged document needs, and it would be unauthenticated. |
| `worker_interval` | `WORKER_INTERVAL` | `15s` | no | How often the queue is drained. |

### Rate limits

Every budget is a setting now. Each key is optional — an instance with no
`rate_limit_` lines runs exactly the limits it ran with before these keys
existed. A **negative value switches that bucket off.**

| Key | Env var | Default | Counted against | Meaning |
| --- | --- | --- | --- | --- |
| `rate_limit_login` | `RATE_LIMIT_LOGIN` | `5` | address | Every attempt runs argon2id, so this is the CPU guard. Also covers `token` and `refresh`. |
| `rate_limit_claim` | `RATE_LIMIT_CLAIM` | `10` | address | Claiming a signing link. |
| `rate_limit_consent` | `RATE_LIMIT_CONSENT` | `10` | **envelope** | Consent and decline. Per envelope, so a party cannot farm consent from a second address and neighbours behind one office IP cannot starve each other. |
| `rate_limit_link` | `RATE_LIMIT_LINK` | `60` | address | Reading the envelope and the document behind a link — what a forwarded link saturates. |
| `rate_limit_create` | `RATE_LIMIT_CREATE` | `20` | address | A create costs a fill, a certification signature and a TSA round trip: the most expensive call in the service. |
| `rate_limit_send` | `RATE_LIMIT_SEND` | `30` | address | Also the bucket for `cancel`, `reissue`, `sign`, `sweep` and `audit-write`. |
| `rate_limit_api` | `RATE_LIMIT_API` | `600` | address | Any other authenticated call. |
| `rate_limit_remind` | `RATE_LIMIT_REMIND` | `2` | **envelope** | Over `rate_limit_remind_window`, not the standard one. |
| `rate_limit_mail_test` | `RATE_LIMIT_MAIL_TEST` | `6` | address | The admin "send a test mail" button. |
| `rate_limit_window` | `RATE_LIMIT_WINDOW` | `1m` | — | The span every bucket counts, Go duration. |
| `rate_limit_remind_window` | `RATE_LIMIT_REMIND_WINDOW` | `10m` | — | The remind bucket's own span. |

Three things worth knowing before you tune them:

- **In memory, per process.** Two replicas double every budget; a restart clears every counter. A network-level limiter in front is a deployment detail, not a substitute for these.
- **A refused call answers `429` with `Retry-After`**, set to how long until the oldest hit in the window ages out. `signsrv` and the SDK both honour it.
- **`trust_proxy` decides who the address is.** Behind a proxy with `trust_proxy=false`, every visitor is the proxy, so a single aggressive client exhausts the login bucket for everyone. That is the most common way these limits cause an outage.

The effective set is printed at start and by `signsrv configcheck`, as one line:

```
rate_limits=login=5 claim=10 consent=10 link=60 create=20 send=30 api=600 remind=2/10m0s mail_test=6 window=1m0s
```

### CA subject (only matters at first CA creation)

All optional, all empty by default; `signsrv` fills a sensible default subject for
this host when they are unset. Changing them **after** the CA exists does nothing to
the existing certificate.

| Key | Env var |
| --- | --- |
| `ca_common_name` | `CA_COMMON_NAME` |
| `ca_org` | `CA_ORG` |
| `ca_unit` | `CA_UNIT` |
| `ca_locality` | `CA_LOCALITY` |
| `ca_province` | `CA_PROVINCE` |
| `ca_street` | `CA_STREET` |
| `ca_postal` | `CA_POSTAL` |
| `ca_country` | `CA_COUNTRY` |
| `ca_email` | `CA_EMAIL` |


**Filling in the CA subject.** These keys apply only when the keystore is created
(both `ca.key` and `ca.crt` absent). They become permanent once written: editing
them later does nothing, and re-creating the CA invalidates every signature issued
so far, so anyone who imported the old `ca.crt` by fingerprint has to re-import.
Print the result with `signsrv-utils checkconfig` before the first start, and
confirm the DN with `openssl x509 -in var/keystore/ca.crt -noout -subject`.

If you need to produce the pair by hand (air-gapped bootstrap, or a CSR to a
real CA), openssl must reproduce what the service expects, or startup refuses
the key:

    cd var/keystore   # must be empty; the service will not overwrite either file
    openssl ecparam -genkey -name prime256v1 -noout -out ca.plain.key  # P-256, not RSA
    openssl req -new -x509 -key ca.plain.key -out ca.crt -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=Example Labs/OU=Signing/CN=Example Signing CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
        -addext "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign,cRLSign" \
        -addext "extendedKeyUsage=1.3.6.1.5.5.7.3.36"
    chmod 644 ca.crt
    openssl pkcs8 -topk8 -nocrypt -in ca.plain.key -out ca.plain.der
    rm ca.plain.key

`ca.plain.der` is PKCS8 DER, which is what the service seals into `ca.key`
with `keystore_pass` — that envelope format is private, so the supported way
to install a hand-made key is to seal it on a machine that has the service
(`signsrv` on an empty keystore dir), not to hand-write the file.

What actually matters in that command, and what does not:

- `keyUsage=digitalSignature` is enforced: the verifier builds a context with
  `RequireDigitalSignature(true)`, so a CA without it fails at signature time.
- `extendedKeyUsage=1.3.6.1.5.5.7.3.36` (Document Signing, RFC 9336) is
  *emitted* by the service but not checked by it — this project's verifier looks at
  key usage, not EKU. Keep it anyway: it is what tells a third-party reader
  (Adobe, `crypttools`) that the certificate is for signing documents rather than
  for TLS or code signing.
- Use `keyCertSign`, not `keyCertification` or `certSign`: openssl only accepts
  the former, and it is the same bit Go's `KeyUsageCertSign` writes.
- `-days 3650` matches the 10-year CA the service creates. A shorter life is
  not refused, but startup stops when the certificate expires, so make sure the
  number is the one you intend to maintain.
### Logging

| Key | Env var | Default | Required | Meaning |
| --- | --- | --- | --- | --- |
| `log_level` | `LOG_LEVEL` | `info` | no | `debug`, `info`, `warn`/`warning`, `error`. |
| `log_path` | `LOG_PATH` | `var/log/signsrv.jsonl` | no | JSON-lines log file. |
| `dev` | `DEV` | `false` | no | Off the ground: skips validation, generates missing secrets, writes mail to `outbox_dir`, and seeds `dev@localhost` with the admin password (ephemeral, printed to the log, when the config has none). **Never `true` in production** — it is the one mode that creates an account by itself. |

## Environment variables that are not settings

Four variables are read by a *command*, once, instead of being config keys. They
look like settings and are not, which is the main trap in this scheme:

| Variable | Read by | Purpose |
| --- | --- | --- |
| `ADMIN_PASSWORD` | `admin add`, `admin passwd` | The password for the account being created or rotated. Falls back to a terminal prompt if unset. Also a config key (above). |
| `USER_PASSWORD` | `user add` | Password/secret for an SPA user account. **Not a config key** — setting it in the file does nothing. |
| `KEYSTORE_PASS` | `firstboot`, `checkconfig` | Seed value for the passphrase. Also a config key. |
| `SMTP_PASS` | `firstboot` | Seed value for the relay password. Also a config key. |

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
