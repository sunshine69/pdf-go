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
export KEYSTORE_PASS="$(openssl rand -hex 32)"   # write this down NOW
export ADMIN_PASSWORD="$(openssl rand -base64 24)"

# CA identity: first start only. Read *The signing CA* below before running this.
export CA_COMMON_NAME="Example.org Document Signing CA"
export CA_ORG="Example Ltd"
export CA_UNIT="Trust Services"
export CA_EMAIL="signing@example.org"
export CA_STREET="1 Example Street"
export CA_LOCALITY="Example City"
export CA_PROVINCE="Example County"
export CA_POSTAL="EX1 2AB"
export CA_COUNTRY=GB

docker run -d --name signsrv \
  --network host \
  -v signsrv-data:/var/lib/signsrv \
  -e LISTEN=127.0.0.1:8080 \
  -e PUBLIC_URL=https://pdfsign.example.org \
  -e TRUST_PROXY=1 \
  -e MAIL_FROM=signer@example.org \
  -e SMTP_HOST=smtp.example.org \
  -e SMTP_PORT=587 \
  -e KEYSTORE_PASS \
  -e ADMIN_PASSWORD \
  -e CA_COMMON_NAME -e CA_ORG -e CA_UNIT \
  -e CA_EMAIL -e CA_STREET -e CA_LOCALITY \
  -e CA_PROVINCE -e CA_POSTAL -e CA_COUNTRY \
  signsrv:v0.0.1 serve
```

### The signing CA — read this before the first start

The service generates its own signing CA on first start: an ECDSA P-256 key
pair, sealed into `var/keystore/ca.key` with `keystore_pass`, and a self-signed
certificate at `var/keystore/ca.crt`. There is no separate generate command and
no certificate to import, so **the first start is the only moment the CA's
identity can be set.** Afterwards the `ca_*` fields are ignored completely:
honouring them would mean re-issuing a CA that already has signatures pointing at
it, which invalidates them.

Set them before that first start, or the CA is named `signsrv CA / O=signsrv` and
every signer you issue inherits `O=signsrv`. All nine are optional; unset ones are
left out of the distinguished name entirely rather than appearing as empty
fields. They can go in the config file instead, under the same names — but then
they must be in it before the volume is first written. An env var that is not
passed with `-e` does not reach the container.

The values are **self-asserted**. A self-signed certificate attests nothing about
the party named in it, so a fuller subject makes the certificate legible to
humans and PDF readers — it does not make it trusted. Trust comes from the
recipient importing `ca.crt` and checking its fingerprint over a channel you do
not control.

Confirm what was actually created:

```sh
# Copy it out and inspect it on the host. The image has no openssl.
docker cp signsrv:/var/lib/signsrv/keystore/ca.crt /tmp/ca.crt
openssl x509 -in /tmp/ca.crt -noout -subject -fingerprint -sha256 -enddate
rm /tmp/ca.crt
```

Record the SHA-256 fingerprint and the `enddate` with the passphrase (§6). The
fingerprint is what a verifier checks `ca.crt` against, and once signatures exist
the subject cannot be changed without issuing a new CA and re-notifying everyone.
The `enddate` is the CA's own expiry — see §6 for why nothing warns you about it.

`checkconfig` prints the subject it will use, so you can confirm the settings
before anything is written to the volume:

```
keystore_dir=/var/lib/signsrv/keystore
ca_subject=CN=Example.org Document Signing CA, O=Example Ltd, ... (honoured on first start only)
```

The subject you set also appears on every signer's certificate as its
`Organization`, so a reader inspecting a signature sees one identity across the
chain instead of your organisation on the CA and `signsrv` on each signer.

Before it starts serving for real, ask it what it thinks the configuration is:

```sh
docker run --rm -v signsrv-data:/var/lib/signsrv \
  -e PUBLIC_URL=https://pdfsign.example.org \
  -e MAIL_FROM=signer@example.org \
  -e SMTP_HOST=smtp.example.org \
  -e KEYSTORE_PASS -e ADMIN_PASSWORD \
  signsrv:v0.0.1 checkconfig
```

`checkconfig` prints every effective value, with secrets shown as set/unset, and
exits non-zero on a configuration the service refuses to run: a `public_url`
that is not `https` when `dev=0`, a missing `smtp_host` outside dev mode, a
missing keystore passphrase, a keystore directory that does not exist, a JWT key
world-readable. Read it before the first `serve`; it is also the first thing to
run after any change.

Some findings are **warnings**, printed and then run anyway, because the
decision belongs to the operator and not to the binary. A listener outside
loopback is one of those: see *Why `--network host`*, below. A warning is
printed by `serve` too, so the tradeoff is stated on every start rather than
only when someone asks.

### Accounts, after the first start

**An account appears on the first start only, and only from `DEFAULT_ADMIN_EMAIL`.**
Everything after that is a command you run. This is the most common point of
confusion after an install, so read this before looking for a lost password.

| What | Where it is set | Creates an account? |
| --- | --- | --- |
| `DEFAULT_ADMIN_EMAIL` | env only | **Yes, on a first start** — the address seeded with `ADMIN_PASSWORD`. Unset falls back to `admin@pdfsign.com`, and the log says so. A restart of an instance that already exists never adds one |
| `ADMIN_PASSWORD` / `admin_password=` | env, or the config file | **No.** It is only the password the *seeding step* uses |
| `SIGNSETUP_ADMIN_EMAIL` | env, to `signsrv-firstboot` only | Yes, but only on a **deb** install (see below) |
| `signsrv admin add EMAIL` | a command you run | **Yes** — this is the real way |
| `signsrv-utils admin add EMAIL` | a command you run, same result | **Yes** — and it resolves the database from the service's own config without needing its secrets |
| `dev=true` | env, or the config file | **Yes**, `dev@localhost`, only when the database has no admins. Never in production |

`admin_password` is read at start-up to satisfy config validation, and it is the
password the first start hashes — into the account named by `DEFAULT_ADMIN_EMAIL`
in a container or under systemd, into the account named by `SIGNSETUP_ADMIN_EMAIL`
on a deb install, which runs `signsrv-firstboot` before the service ever starts.
Set a password but name no address, and on a first start the seed uses
`admin@pdfsign.com`; set neither, and the service starts green, `/healthz` answers
200, `/admin/` refuses every login, and the log says which command fixes it. If you
generate a password and no account follows it, that password belongs to nobody.

The one exception is `dev=true`: a dev instance with no admins seeds
`dev@localhost` with its own admin password and logs the address, so `docker run`
with `DEV=true` gives you a usable login immediately. That convenience is
switched off in production by the same flag that turns off the other dev
behaviours, and it will not add the account if any admin already exists.

Create the account explicitly. `admin add` takes the password from
`ADMIN_PASSWORD`, which the container already has when it comes from the
`env_file`, so no extra flag is needed; minimum 12 characters:

```sh
docker exec signsrv signsrv admin add you@example.org
docker exec signsrv signsrv admin list        # confirm it exists before you try to log in
```

If the password is not in the container environment, `admin add` prompts for it
twice instead — which fails under `docker exec` without `-it`, so add `-it` in that
case or pass `-e ADMIN_PASSWORD=...` explicitly.

`admin add` is not idempotent: a second call for an address that already exists is
an error, not a password reset. Use `admin passwd EMAIL` for that; it stamps the
credential epoch, which ends every access token and deletes the refresh chain — the
action to take when a token is stolen.

On a **deb** install the account can be created for you, but only if you say so
before the first start:

```sh
SIGNSETUP_ADMIN_EMAIL=you@your.host SIGNSETUP_ADMIN_PASSWORD=... apt install ./signsrv_*.deb
```

`SIGNSETUP_ADMIN_EMAIL` is a first-boot setup variable. It is **not** a service
setting, it is not read by `signsrv serve`, and it is not consulted again after the
first run — so setting it later, or setting it in the container environment, does
nothing at all. When it is absent on a deb install the installer says so in its
summary rather than leaving you to guess.

```sh
docker exec signsrv signsrv client add batch envelope:write envelope:read # prints the key ONCE
docker exec signsrv signsrv user add ops                                  # SPA login; prints the JWT secret
docker exec signsrv signsrv dbstatus                                      # schema version + row counts
```

### Why `--network host`

A container's `127.0.0.1` belongs to that container alone, so a bridge network
leaves the proxy unable to reach it. Two supported answers:

1. **host networking** (above, and what `deploy/docker-compose.yml` does) — the
   listener stays loopback, the proxy reaches it, nothing is exposed outward.
2. **a user-defined bridge** — then the listener has to be `0.0.0.0:8080`, so
   the container network becomes the boundary: do not publish the port, and keep
   the proxy in the same network.

Both are supported. The service binds whatever address you name — where the
listener sits is a property of the infrastructure around it, and a mesh with
mutual TLS, a sidecar proxy, or a private VLAN each make a public bind correct.
The service will not decide that for you, and will not stop you.

To publish the port on a host-network container, change one variable:

```sh
  -e LISTEN=0.0.0.0:8080 \
```

`--publish`/`-p` is ignored under `network_mode: host`, and there is nothing for
it to do: the container already has the host's interfaces, so the listen address
*is* the host's. The same is true of the published listener on a bridge — there
the container network is the boundary, and the `ports:` mapping is what carries
the traffic to the proxy. `deploy/docker-compose.yml` carries a commented block
for that shape (a host whose ports are already taken), including why to publish
it on `127.0.0.1:8080` rather than `0.0.0.0:8080`.

What it does is say so, on both paths. `checkconfig` prints it as text:

```
warning: listen binds outside loopback (0.0.0.0:8080): the service serves plain
HTTP, so TLS, a proxy, or network policy must terminate encryption in front of
it, or party tokens and the admin password cross the network in the clear
```

and `serve` writes the same sentence to the log as a WARN record, at every
start — so the warning is on the record for the run that is actually serving,
not only for a check someone has to remember to re-run after a deploy:

```json
{"level":"WARN","msg":"configuration warning","service":"signsrv",
 "warning":"listen binds outside loopback (0.0.0.0:8080): the service serves plain HTTP, ..."}
```

`docker compose logs signsrv | grep 'binds outside loopback'` is the check.

The warning is about the one thing the application cannot fix: it speaks plain
HTTP, and the signing link carries a token. Bind `0.0.0.0` and put nothing in
front, and a login POST and every signing link cross the network readable by
anyone on the segment. That is a real deployment behind a proxy and a real
mistake behind none, which is why it is a warning rather than a refusal — the
service runs it and names the cost. `listen=:8080` binds every interface too;
an empty host has never meant loopback, and the warning now catches it.

TLS is terminated in front of the service in both cases. See `deploy/Caddyfile`.

---

## 3. Settings

Every key has an environment variable named for it — the key uppercased, so
`public_url` is `PUBLIC_URL` and `keystore_pass` is `KEYSTORE_PASS`; with
`-config FILE` the same names work in the file, and **the environment wins**.
A `SIGNSRV_`-prefixed name is still read, as a legacy spelling, but the
unprefixed one wins when both are present.
The compose file and the systemd unit set the same values by different means,
which is deliberate — the behaviour must not depend on which you chose.

| key | default | note |
|---|---|---|
| `listen` | `127.0.0.1:8080` | any address is accepted. Outside loopback the service logs a warning that it speaks plain HTTP and encryption must be terminated in front of it — see §2 |
| `public_url` | — | **required.** Base of every signing link. A mismatch gives links that look real and go nowhere, and no check catches it |
| `trust_proxy` | `false` | set `1` when a proxy in front sets `X-Forwarded-For`. Without it the rate limits bind to the proxy's address and every visitor shares one bucket. Set `0` when clients reach the listener directly, whatever it is bound to: trusting the header lets a client choose the address the limits are keyed to |
| `dev` | `false` | mail goes to `outbox_dir` as `.eml` files instead of the relay, and the keystore passphrase and admin password are generated at start and printed to the log |
| `db` | `var/signsrv.db` | SQLite, WAL |
| `storage_dir` | `var/storage` | uploaded and signed PDFs |
| `keystore_dir` | `var/keystore` | the CA. Created on first start, mode 0750 |
| `keystore_pass` | — | **required.** Decrypts the CA. See §6 |
| `ca_common_name` | `signsrv CA` | CA subject. **Read at first start only.** See *The signing CA* in §2 |
| `ca_org` | `signsrv` | CA subject, and the `Organization` on every signer's certificate |
| `ca_unit` `ca_email` `ca_street` `ca_locality` `ca_province` `ca_postal` `ca_country` | unset | CA subject. Omitted from the DN when unset |
| `admin_password` | — | **required** at first start, seeds the admin. After that the DB hash is the truth |
| `smtp_host` | — | required when `dev=0` |
| `smtp_port` / `smtp_starttls` | `587` / `true` | |
| `smtp_user` / `smtp_pass` | — | leave unset for an unauthenticated relay. `SMTP_PASS` for the password |
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
docker exec -e KEYSTORE_PASS="$KEYSTORE_PASS" \
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
`schema version`, and `GET /api/v1/admin/schema` answers the same question to an
admin token: `{"version":8,"binary_version":8,"migration_open":false,"pending":[]}`,
i.e. whether `migrate` has anything left to do. Before starting on a copy of production, run the migration on
the copy instead, and the service never touches the original:

```sh
docker run --rm -v prod-copy:/var/lib/signsrv \
  -e DB=/var/lib/signsrv/signsrv.db -e DEV=1 \
  signsrv:v0.0.1 migrate
```

`migrate` applies what is pending, prints the version reached and the file it
touched, then runs `integrity_check`; a second run is a no-op. `DEV=1` is there
because the CLI commands validate the whole server config, and a bare `-e DB=`
run has no passphrase and no `public_url`.

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

### The CA: the thing that has a deadline

The keystore is the signing authority for every document you have issued, so
treat it like a certificate authority and not like a config file.

**It expires.** The CA certificate is valid for **10 years** from the day the
volume was first written. `checkconfig` does not warn you in advance; the expiry
is checked when the keystore is loaded, at startup and on every signing call, and
the failure looks like this:

```
signpdf: CA expires at 2036-11-09, regenerate the keystore
```

The service starts and serves anyway: verification, the admin app and the API all
keep working, and only document creation answers 503. That is why this fails
quietly in production — the process looks healthy — and loudly in the selftest.
Every document already signed still verifies; nothing you have already done
breaks.

Grep the log for it rather than waiting for a customer to notice. That ERROR
line, not the 503, is the signal to act on:

```
{"level":"ERROR","msg":"signing service unavailable","error":"signpdf: CA expires at 2036-11-09, regenerate the keystore","create":"endpoint will answer 503"}
```

**Put the CA's `NotAfter` date in your calendar now, with a year of slack:**

```sh
docker cp signsrv:/var/lib/signsrv/keystore/ca.crt /tmp/ca.crt
openssl x509 -in /tmp/ca.crt -noout -enddate; rm /tmp/ca.crt
```

**What breaks, and what does not.** Losing `keystore_pass` or `ca.key`, or
letting the certificate expire, stops *new* signatures and nothing else:

| | still works? |
|---|---|
| "Has this document been altered?" | Yes — the verifier needs nothing from you. The leaf certificate and the RFC 3161 timestamp are inside the PDF |
| The chain to your CA | Yes — the CA certificate is embedded in each signature's PKCS#7 |
| `trusted` on the recipient's reader | Unchanged. It is `false` for a self-signed CA until the recipient imports `ca.crt` as a trust anchor. A richer subject does not change this |
| Issuing a new signature | No |

So an expired CA is an outage for issuing, not a retroactive invalidation of the
documents. Plan the renewal as an outage window, not as a panic.

**Renew before you replace.** Replace means a brand-new key and a new identity,
and every recipient who imported the old `ca.crt` has to import the new one.
That is why the fingerprint recorded in §2 belongs with the passphrase: when
someone asks whether a `ca.crt` they received is genuine, that fingerprint is
what they check it against. Keep the old pair for as long as any document signed
under it needs to stay checkable — the old certificates do not have to remain
reachable, they are already in the documents, but keeping them costs nothing and
lets you answer a dispute years later.

**Distribute deliberately.** `ca.crt` is public and mode 0644; `ca.key` is
encrypted with Argon2id and mode 0600, and the service holds no copy of the
passphrase anywhere above the environment. The private key is never in a
document. Publishing `ca.crt` on your site is normal and helps verifiers;
putting `ca.key` anywhere they can reach is the only way this design fails.

**The identity is not a trust mechanism.** The `ca_*` fields name you; they do
not prove you. A recipient who wants proof of who signed a document has to
verify the certificate's fingerprint over a channel the signer does not control,
and the only thing that gives them that is a CA from an issuer they already
trust — or your own `ca.crt` pinned by policy. If your documents need
third-party attestation, that means a signing certificate from a commercial
trust list, which is a different design from this one: this service is built
around a self-issued CA and cannot use one as its root.

---

## 7. Upgrade and rollback

```sh
docker build -t signsrv:v0.0.2 -f deploy/Dockerfile .
docker stop signsrv && docker rm signsrv
docker run -d --name signsrv --network host -v signsrv-data:/var/lib/signsrv \
  --env-file /etc/signsrv/env signsrv:v0.0.2 serve
docker exec signsrv signsrv dbstatus        # schema version 8
```

`serve` applies pending migrations on start, so the new tag migrates the volume
by itself; `signsrv migrate` exists to do it deliberately first. Schema v8 adds
`parties.token_raw` and a unique index on the unsent mail queue. On a database
where a mailing button has already been clicked twice it deletes the older
duplicate queue rows before creating the index — that is deliberate, and it is
the one migration in this store that removes rows, so it is the one worth
checking a backup against. Nothing else about the upgrade is visible to a
signer: existing links keep working, because the column is additive and the
hash that authorises a link is unchanged.

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
  -e DEV=1 -e PUBLIC_URL=http://127.0.0.1:8080 \
  signsrv:v0.0.1 serve
```

`dev=1` is what makes this bearable: mail is written to `outbox_dir` as `.eml`
files instead of reaching a relay. It is not what makes it *safe*, and it no
longer restricts the listener — dev mode binds whatever address you name, which
is the combination to avoid, because in dev `serve` generates the keystore
passphrase and the admin password at start and prints them to the log. A
listener that reaches the network plus a readable log is enough to sign. Keep
`LISTEN` at `127.0.0.1:8080` here; the published shapes belong to §2.
Open `http://127.0.0.1:8080/healthz`, and read the invitation out of
`var/outbox`. Never start a container with `dev=1` on a machine that answers for
a real host name: the credentials it prints are the credentials that work.
