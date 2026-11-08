# Running signsrv in Docker — v0.0.1

The image contains one binary. The SPA, the admin console, the mail templates
and the PDF signing code are embedded at build time, so there is nothing to
mount besides state, and no runtime interpreter or libc.

This document covers: build, first run, the process itself, the settings, the
state volume and backups, upgrades and rollbacks. For the systemd path, see
`runbook.md` and `deploy/signsrv.service`; the two are interchangeable and share
one on-disk layout.

---

## 1. Build

```sh
docker build -t signsrv:v0.0.1 -f deploy/Dockerfile .
docker run --rm signsrv:v0.0.1 version     # → signsrv 0.0.1
```

Two things the build does that are easy to miss:

- **There is no `vendor/` tree.** `go.mod` is the dependency list and `go.sum`
  verifies every module. The first build on a clean machine reaches the network;
  later ones use the module cache. A pinned, offline build is `docker build` with
  `GOFLAGS=-mod=mod GOPROXY=off` and a warmed cache, which the release image does
  not need.
- **The dependency `github.com/digitorus/pdfsign` is replaced** (`go.mod`) with
  the fork `github.com/sunshine69/pdfsign`. The fork carries the page-reference
  fix; without it every signature the library adds fails its own DocMDP check.
  If the replace is dropped, signatures break in a way only verification notices.
  `scripts/acceptance-04.sh` asserts the replace is present. `patches/` are the
  same edits expressed against `vendor/`; the fork carries them in source, so
  the `vendor/` flow is not needed and nothing runs a patch at build time.

The binary is static (`CGO_ENABLED=0`; the SQLite driver is pure Go), so the
runtime image is Alpine plus `ca-certificates` and `sqlite`. The CA bundle
matters: signing calls the timestamp authority over HTTPS, and without the
bundle the chain cannot be verified and signatures land undated.

---

## 2. First run

Everything the service writes lives under `/var/lib/signsrv`: the database, the
document store, the keystore, the JWT key, the audit files and the mail outbox.
**Mount a volume there or the data dies with the container.**

```sh
docker volume create signsrv-data

# Secrets come from the environment, never from a file baked into the image.
export SIGNSRV_KEYSTORE_PASS="$(openssl rand -hex 32)"   # write this down NOW
export SIGNSRV_ADMIN_PASSWORD="$(openssl rand -base64 24)"

docker run -d --name signsrv \
  --network host \
  -v signsrv-data:/var/lib/signsrv \
  -e SIGNSRV_LISTEN=127.0.0.1:8080 \
  -e SIGNSRV_PUBLIC_URL=https://pdfsign.example.org \
  -e SIGNSRV_TRUST_PROXY=1 \
  -e SIGNSRV_MAIL_FROM=signer@example.org \
  -e SIGNSRV_SMTP_HOST=smtp.example.org \
  -e SIGNSRV_SMTP_PORT=587 \
  -e SIGNSRV_KEYSTORE_PASS \
  -e SIGNSRV_ADMIN_PASSWORD \
  signsrv:v0.0.1 serve
```

Before it starts serving for real, ask it what it thinks the configuration is:

```sh
docker run --rm -v signsrv-data:/var/lib/signsrv \
  -e SIGNSRV_PUBLIC_URL=https://pdfsign.example.org \
  -e SIGNSRV_MAIL_FROM=signer@example.org \
  -e SIGNSRV_SMTP_HOST=smtp.example.org \
  -e SIGNSRV_KEYSTORE_PASS -e SIGNSRV_ADMIN_PASSWORD \
  signsrv:v0.0.1 checkconfig
```

`checkconfig` prints every effective value, with secrets shown as set/unset, and
exits non-zero on a combination it considers unsafe. It is the gate that refuses
a non-loopback listener, a `public_url` that is not `https` when `dev=0`, and a
missing `smtp_host` outside dev mode. Read it before the first `serve`; it is
also the first thing to run after any change.

### Accounts, after the first start

```sh
docker exec signsrv signsrv admin add you@example.org                     # password from SIGNSRV_ADMIN_PASSWORD
docker exec signsrv signsrv client add batch envelope:write envelope:read # prints the key ONCE
docker exec signsrv signsrv user add ops                                  # SPA login; prints the JWT secret
docker exec signsrv signsrv dbstatus                                      # schema version + row counts
```

`admin passwd` stamps the credential epoch, which ends every access token and
deletes the refresh chain — the action to take when a token is stolen.

### Why `--network host`

The service refuses to serve on anything but a loopback listener: the signing
link carries a token, and a token must not travel over a plain path someone on
the route can read. `checkconfig` rejects a `0.0.0.0` bind outside dev mode.
A container's `127.0.0.1` belongs to that container alone, so a bridge network
would leave the proxy unable to reach it. Two supported answers:

1. **host networking** (above, and what `deploy/docker-compose.yml` does) — the
   listener stays loopback, the proxy reaches it, nothing is exposed outward.
2. **a user-defined bridge** — then the listener has to be `0.0.0.0:8080`, which
   means the container network itself is the boundary: do not publish the port,
   and keep the proxy in the same network. This works but trades the guardrail
   for a firewall rule you have to maintain.

TLS is terminated in front of the service in both cases. See `deploy/Caddyfile`.

---

## 3. Settings

Every key has an `SIGNSRV_`-prefixed environment variable; with `-config FILE`
the same names work un-prefixed in the file, and **the environment wins**.
The compose file and the systemd unit set the same values by different means,
which is deliberate — the behaviour must not depend on which you chose.

| key | default | note |
|---|---|---|
| `listen` | `127.0.0.1:8080` | must be loopback outside dev mode |
| `public_url` | — | **required.** Base of every signing link. A mismatch gives links that look real and go nowhere, and no check catches it |
| `trust_proxy` | `false` | set `1` when a proxy in front sets `X-Forwarded-For`. Without it the rate limits bind to the proxy's address and every visitor shares one bucket |
| `dev` | `false` | mail goes to `outbox_dir` as `.eml` files instead of the relay. Only allowed on a loopback listener |
| `db` | `var/signsrv.db` | SQLite, WAL |
| `storage_dir` | `var/storage` | uploaded and signed PDFs |
| `keystore_dir` | `var/keystore` | the CA. Created on first start, mode 0750 |
| `keystore_pass` | — | **required.** Decrypts the CA. See §6 |
| `admin_password` | — | **required** at first start, seeds the admin. After that the DB hash is the truth |
| `smtp_host` | — | required when `dev=0` |
| `smtp_port` / `smtp_starttls` | `587` / `true` | |
| `smtp_user` / `smtp_pass` | — | leave unset for an unauthenticated relay. `SIGNSRV_SMTP_PASS` for the password |
| `mail_from` | — | the From address |
| `jwt_secret_file` | `var/jwt.ed25519.key` | API tokens. Created on first start, 0600. Replacing it drops every API session; signing links are unaffected |
| `link_ttl` | `168h` | signing link lifetime |
| `worker_interval` | `15s` | how often the in-process worker drains the queues |
| `max_pdf_mb` | `25` | upload cap; the edge proxy should cap earlier (Caddyfile: 24 MB) |
| `tsa_url` | `https://freetsa.org/tsr` | timestamp authority |
| `outbox_dir` | `var/outbox` | mail spool in dev; also where undelivered mail lands |
| `log_path` | `var/log/signsrv.jsonl` | JSON lines, written to a file — never a TTY |
| `audit_dir` | `var/audit` | daily audit files, written by `signsrv audit-write` |
| `log_level` | `info` | |

Secrets never live in the image, and `checkconfig` never prints their values.

---

## 4. The process

`ENTRYPOINT` is `signsrv`, `CMD` is `serve`. It is a **single process**: the HTTP
API, the SPA, the admin console and the queue worker all run inside it. There is
no sidecar for mail and no separate worker container — `worker_interval` drives
the drain loop in-process. Scaling out to more than one instance means the
queues are shared through SQLite and one instance's worker drains them, so
**run one instance**. The database is a file.

Subcommands worth knowing inside a container (`docker exec signsrv signsrv …`):

```
serve | checkconfig | migrate | dbstatus | sweep
admin add|list|passwd        client add|list|revoke      user add|list|rotate|revoke
secrets init                 audit-write [DAY]           audit-verify
sign | sign-selftest | checkpdf | mail-test | version
```

`sweep` is the nightly chore (expire links, drop spent refresh tokens); wire it
as cron or a timer, not as a long-lived second container.
`audit-write` appends the new events to today's audit file; the chain is checked
with `audit-verify`.

### Health

`GET /healthz` answers `{"status":"ok","version":"..."}` — it does not touch the
database, so it answers even when the disk is full.

```sh
docker exec signsrv wget -qO- http://127.0.0.1:8080/healthz
```

Health alone is not readiness for signing. The honest probe is
`signsrv sign-selftest`, which certifies, signs three parties and verifies the
result, exiting non-zero only when the finished document is valid — it exercises
the keystore passphrase and the TSA call as well. It needs the sample PDFs,
which are not in the image, so run it against a mounted `testdata`:

```sh
# start it with:  -v "$PWD/testdata":/testdata:ro
docker exec signsrv signsrv sign-selftest /testdata/sample1.pdf /tmp/out.pdf
```

An undated signature is the failure mode this catches and `/healthz` never will:
the TSA call fails quietly and the document still signs.

One trap. In dev mode `keystore_pass` defaults to a value **generated at each
start**, so a `docker exec` that loads the config again picks a passphrase
different from the one the running server used to seal the keystore, and the
selftest reports `keystore passphrase is wrong` against a perfectly healthy
instance. Pass the same value the server has:

```sh
docker exec -e SIGNSRV_KEYSTORE_PASS="$SIGNSRV_KEYSTORE_PASS" \
  signsrv signsrv sign-selftest /testdata/sample1.pdf /tmp/out.pdf
```

Outside dev mode there is no default — `keystore_pass` is required, so every
process agrees on it and the trap disappears. If you see that error on a
production container, the passphrase really is wrong, and the fix is the
passphrase, not the keystore.

### Logs

```sh
docker logs signsrv                                  # stdout/stderr
docker exec signsrv tail -n 50 /var/lib/signsrv/log/signsrv.jsonl
```

The structured log is the JSONL file, not stdout. The access log records the
request line only — the signing token in the URL is written as `[token]`, and
credentials are never logged; `scripts/verify-release.sh` greps the log for key
material as a release gate.

### Shutdown

Send SIGTERM (`docker stop`). In-flight requests are allowed to finish, then the
listener closes. Give it time: a signature in flight waits on the TSA and can
take 90 seconds. A queue item is not lost by a restart — a claimed row keeps its
`next_at` and is retried after the lease expires. That is also why the mail
queue, not the envelope status, is the truth about whether an invitation left.

---

## 5. Migrations

`serve` migrates on start, in a transaction, and stamps `PRAGMA user_version`.
Version 6 (this release) adds `envelopes.notify_email` and `recipient` and
`detail` on `mail_queue` — three `ALTER TABLE`s, and every existing row lands
NULL. That is the whole point: a NULL `notify_email` means "nobody asked to be
told", so a decline on an old envelope sends no mail and raises no error, and a
NULL `recipient` keeps the old rule of addressing the row to its party. No rows
are rewritten, so the migration is cheap on a large database.

A database from an older image migrates forward automatically. There is no down
migration: **to go back, restore the backup** (§6).

To watch it happen: `docker exec signsrv signsrv dbstatus` — the first line is
`schema version`. Before starting on a copy of production, `signsrv migrate` on
that copy shows the same result without serving.

---

## 6. Backups and the one unrecoverable secret

```sh
docker stop signsrv                        # the DB must not be written during the copy
docker run --rm -v signsrv-data:/src -v "$PWD":/dst alpine \
  tar czf /dst/signsrv-backup-$(date +%F).tgz -C /src .
docker start signsrv
```

Back up the whole volume. The pieces are not independent: the database's
signatures reference documents in `storage_dir`, and the keystore needs the
passphrase to be usable.

`keystore_pass` is the one secret with no recovery. The CA private key is
encrypted with it; the service keeps no copy. Lose it and every signature already
made still verifies (each carries its own certificate chain) but no new
signature can be made — you need a new CA and must tell verifiers the new
certificate. Keep it offline, with the key file, and not in the compose file.

To replace the CA: back up `keystore/ca.key` and `ca.crt` offline, move them
out of the directory, restart; the service creates a new CA on first start.

---

## 7. Upgrade and rollback

```sh
docker build -t signsrv:v0.0.2 -f deploy/Dockerfile .
docker stop signsrv && docker rm signsrv
docker run -d --name signsrv --network host -v signsrv-data:/var/lib/signsrv \
  --env-file /etc/signsrv/env signsrv:v0.0.2 serve
docker exec signsrv signsrv dbstatus        # schema version 6
```

The image tag is the deployment record. Note the tag before the new one, so
rollback is a `docker run` of the old tag — which is why migrations are
forward-only and the backup in §6 is not optional.

Verify a candidate image against a copy of the production volume before it
serves:

```sh
docker run --rm -v cand-data:/var/lib/signsrv -v "$PWD":/src alpine \
  cp /src/prod-copy.db /var/lib/signsrv/signsrv.db   # or the whole tarball
docker run --rm --network host -v cand-data:/var/lib/signsrv \
  --env-file /etc/signsrv/env signsrv:v0.0.2 checkconfig
```

Then run the release gate. `scripts/release-gate-dev.sh` builds the candidate
code, starts a throwaway instance on a free port, seeds the operator and machine
client the gate needs, runs `scripts/verify-release.sh` against it, and tears the
instance down. The gate itself is the checklist — upload, fill, create, send,
claim, consent, sign, deliver, the path-traversal and scope probes, and a grep of
the log for leaked credentials — and it drives whatever instance you point it at:

```sh
sh scripts/release-gate-dev.sh                       # self-contained, dev mode
sh scripts/verify-release.sh ./tmp/bin https://host.example \
     "$KEY" /etc/signsrv/config.env                  # against a real instance
```

`scripts/prod-sign-run.sh` is the same walk against the real instance, and is
idempotent. Use it before pointing an alias at a new image.

---

## 8. Local development in a container

```sh
docker run --rm --network host -v "$PWD/var":/var/lib/signsrv \
  -e SIGNSRV_DEV=1 -e SIGNSRV_PUBLIC_URL=http://127.0.0.1:8080 \
  signsrv:v0.0.1 serve
```

`dev=1` is what makes this safe: mail is written to `outbox_dir` as `.eml`
files instead of reaching a relay, and a dev-mode listener on loopback is the
only listener `checkconfig` accepts in that mode. Open
`http://127.0.0.1:8080/healthz`, and read the invitation out of `var/outbox`.
Never start a container with `dev=1` on a machine that answers for a real
host name; the same flag also relaxes the admin bootstrap.
