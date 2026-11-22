# Running the signing service

`signsrv` is the service: the API, the two web apps and the signing worker, in
one static binary. `pdf-go` is the CLI that prepares a document and drives the
service. Every command below is runnable as written, and every one was run
against the config in `tmp/`.

## Build

```sh
go build -o tmp/signsrv  ./cmd/signsrv
go build -o tmp/pdf-go   ./cmd/pdf-go
go build -o tmp/mock-tsa ./cmd/mock-tsa   # optional: a local TSA, for offline runs
```

`cmd/mock-tsa` is a development RFC 3161 responder: point `tsa_url` at it and a
signing run needs no network. It mints a fresh self-signed certificate on every
start and answers anyone who asks, so it is for local runs only — a production
`tsa_url` names a service whose certificate the verifier can trace to a root it
trusts.

`vendor/` is committed, so `GOFLAGS=-mod=vendor GOPROXY=off go build` works
offline. The CLI subcommand set is documented by `pdf-go doc`, and
`pdf-go help` prints every flag.

## Development

A dev config, written under `tmp/`:

```
listen=127.0.0.1:8090
public_url=http://127.0.0.1:8090
dev=true
db=tmp/signsrv.db
storage_dir=tmp/storage
keystore_dir=tmp/keystore
outbox_dir=tmp/outbox
audit_dir=tmp/audit
log_path=tmp/signsrv.jsonl
jwt_secret_file=tmp/jwt.ed25519.key
keystore_pass=dev-keystore-passphrase-that-is-long
admin_password=dev-admin-password-change-me
mail_from=signsrv@dev.local
link_ttl=72h
worker_interval=15s
tsa_url=https://freetsa.org/tsr
```

`dev=true` is allowed **only** on a loopback listener: SMTP is disabled and
every message is written as a `.eml` file into `outbox_dir`, so you can read
the invitation and click the link. `checkconfig` prints the effective config
with every secret masked as a digest.

`tsa_url` defaults to `https://freetsa.org/tsr`. The worker calls the TSA once
per signing batch, so a dev run that reaches consent needs a reachable TSA; set
it to a local mock to stay offline (`e2e/run.sh` starts one on `127.0.0.1`).

Run it, in order:

```sh
tmp/signsrv checkconfig -config tmp/signsrv-dev.conf   # must end with "config ok"
tmp/signsrv migrate     -config tmp/signsrv-dev.conf   # schema version, integrity_check
ADMIN_PASSWORD=dev-admin-password-change-me \
    tmp/signsrv admin add admin@dev.local -config tmp/signsrv-dev.conf
ADMIN_PASSWORD=dev-admin-password-change-me \
    tmp/signsrv serve -config tmp/signsrv-dev.conf &
curl -s localhost:8090/healthz
```

```
schema version 4, database main
admin 1 created for admin@dev.local
{ "request": "82d1abb28b4b8039", "status": "ok", "version": "0.1.0" }
```

**The admin account is created by `signsrv admin add`, not by the service at
startup.** `admin_password` (or `ADMIN_PASSWORD`) is the password that
account is created with, and the password `signsrv admin passwd` reads. It is
never used to sign in, and it seeds nothing on its own: a fresh database has no
admin row, and `/admin/` answers `the email address and password do not match`.
In dev mode, if the config carries no `admin_password`, the service generates
one and prints it in the log, with the value prefixed `dev-`.

The two apps are served from the binary: signers at `/s/<token>`, admins at
`/admin/`, assets under `/assets/spa/` and `/assets/admin/`. All four return
200 on the dev listener. The admin app is a login form; there is no
change-password page — use `signsrv admin passwd EMAIL`.

## Configuration

`config.example.env` documents every key. A key is read from `<KEY>` in
the environment first, then from the file given with `-config`; the environment
wins. Secrets (`keystore_pass`, `admin_password`, `smtp_pass`) are never logged
and never appear in `checkconfig` output: they print as `sha256:6577c212c163`
or `unset`.

Outside dev mode the service refuses to start when:

- `public_url` is missing, or is not `https://` — the signing link *is* the
  credential, so it must not travel in clear text;
- `smtp_host` or `mail_from` is missing;
- `keystore_pass` is missing — it encrypts the signing CA key;
- `admin_password` is missing — it is the password the admin account is created
  with.

`checkconfig` prints every problem and exits non-zero. An unknown key is a
problem too:

```
problem: tmp/typo.conf:1: unknown config key "listenx" (see config.example.env)
config NOT usable
```

## Production

- Run behind TLS (Caddy/nginx; reference `deploy/Caddyfile`, committed with
  `Strict-Transport-Security`). `public_url` must match what signers see.
- `KEYSTORE_PASS`, `ADMIN_PASSWORD` and `SMTP_PASS`
  come from the environment, not from the file: the file then holds no secret.
  The systemd unit mounts them with `LoadCredential`, so they are not in the
  unit file and not in the shell history.
- Run as the `signsrv` user. `deploy/signsrv.service` sets `User`/`Group` and
  `UMask=0027`, so every file the process creates is group-unreadable and the
  key material is owner-only. Verified on a dev run: `ca.key` and the JWT key
  are `0600`.
- The first start creates the keystore (`ca.crt`, `ca.key`), the JWT key and
  the database. The state directory must exist and be owned by the service user
  first.
- Log to `log_path` as JSON, rotated with `copytruncate`
  (`deploy/logrotate.conf`). The log is opened once with `O_APPEND`;
  `copytruncate` truncates the same inode, so the open file handle keeps
  writing at the new end of file and the service needs no reload signal. A
  rotation that *renames* the file would lose every line written after it,
  because the process keeps writing to the renamed inode.
- Trust `X-Forwarded-For` only when a proxy in front of the service sets it:
  `trust_proxy=true`. With it false, `checkconfig` reads the peer address, and
  a forged header cannot move a rate-limit bucket.

## First run, start to finish

```sh
tmp/signsrv serve -config tmp/signsrv-dev.conf &
tmp/signsrv client add readme-demo envelope:write envelope:read -config tmp/signsrv-dev.conf
```

```
client 1 created: readme-demo
key: key_0b286cf9ad6d7fe3c44a95e083369e1cba1b9a681f47b10a192b5d3179eb6635
The key is shown once and is not recoverable; the database stores its hash.
```

The key is the long-lived secret. It never rides on an API call: the CLI
exchanges it for a short-lived bearer token. Pass it through the environment,
never on the command line:

```sh
export TOKEN=key_0b286cf9ad6d7fe3c44a95e083369e1cba1b9a681f47b10a192b5d3179eb6635
```

`--token-env` names the variable (`TOKEN` by default), `--server`
(`URL` by default). Plain `http://` is refused unless you pass
`--insecure`, because a client token would travel in the clear.

A fill spec: `pdf-go extract in.pdf -o fill.json` writes the schema; put the
values in `{"values":{"Text1":"Ann Miller",...}}`, and add `logos` and
`paints` for artwork. `pdf-go doc` prints the format. Check it locally before
uploading:

```sh
tmp/pdf-go fill  tmp/fill.json testdata/sample2.pdf -o tmp/filled.pdf   # rc 0
tmp/pdf-go verify tmp/filled.pdf tmp/fill.json                          # rc 0, "checked": 6
```
https://pdfsign.kaykraft.org/s/7noiqcphdumvam32wdprgmx6vimq4d7yhncyhi=nifzbcpkffl3fq

A parties file — a JSON array, one object per party, `order` starting at 1,
no gaps, no duplicates. The address is the party's identity; the name is what
they see, and a name with a line break is rejected (header injection):

```json
[
  {"email": "ann@x.com", "name": "Ann Miller", "order": 1},
  {"email": "bob@y.com", "name": "Bob Lee", "order": 2}
]
```

Create and send:

```sh
tmp/pdf-go envelope create --server http://127.0.0.1:8090 --insecure \
    --title "NDA" --expires 3d --spec tmp/fill.json --parties tmp/parties.json \
    --links-out tmp/links.txt --send testdata/sample2.pdf
```

The answer is the envelope, the fill summary and the links. The links are the
parties' credentials, printed once. `--links-out` writes them to a JSON file of
mode 0600 (default `envelope-<id>.links.json`), so `envelope links` can print
them again from that file with no call to the service. Remove the file when the
parties have their links.

```json
{"envelope": {"id": "f6ff497d25d7b29b82067cb16a65bcf2", "status": "ready"},
 "fill": {"applied": ["Text1","Text2","Text3","Text4","Text5","Text6"], "lockedForm": true},
 "links": [{"order":1, "email":"ann@x.com",
            "url":"http://127.0.0.1:8090/s/bv4nkjlul4kg3a4sr6xf57sf5l6bcslci7cfsu3iqvh5mbhihpyq"}]}
```

Open that URL: the party states their address, reads the document, ticks the
box, consents. In dev mode the invitation is a file:

```
tmp/outbox/invite-f6ff497d25d7b29b82067cb16a65bcf2-85a7679f4f28ad15fd0219890e3ae8ac.eml
```

Watch the request, not the process:

```sh
tmp/pdf-go envelope get    --server http://127.0.0.1:8090 --insecure ID  # status, per party
tmp/pdf-go envelope links  --links-out tmp/links.txt ID                  # reprints from the file, no server
tmp/pdf-go envelope report --server http://127.0.0.1:8090 --insecure ID  # "complete": true when signed
```

When the last party consents, the worker certifies, signs every party in order,
calls the TSA, verifies the result and mails the signed document to each party.
A report that is not complete says why (`errors`).

`audit-verify` checks the hash chain, and needs `audit-write` to have run:

```sh
tmp/signsrv audit-write  -config tmp/signsrv-dev.conf
tmp/signsrv audit-verify -config tmp/signsrv-dev.conf
```

```
audit tmp/audit/2026-11-07.jsonl: 3 event(s) appended
audit dir tmp/audit: 3 event(s), chain valid
```

On a fresh `audit_dir` the verify command prints
`events up to id 3 exist, the log ends at 0 (events missing)` and exits 1: the
database has events the audit file has not recorded yet. Run `audit-write`
first, and run it every day (nightly job in `runbook.md`).

## Commands

`signsrv` (each takes `-config FILE`; `-config` may appear before or after the
command):

| command | what it does |
|---|---|
| `serve` | runs the service |
| `checkconfig` | prints the effective config, secrets as digests, exits non-zero listing every problem |
| `migrate` | applies pending migrations, prints the version, runs `integrity_check`. Re-running is a no-op |
| `admin add EMAIL` | creates the admin with the password from `admin_password` |
| `admin list` | the admin accounts |
| `admin passwd EMAIL` | changes a password and revokes that admin's sessions |
| `client add NAME [SCOPES…]` | creates an API client; the key is printed once |
| `client list` / `client revoke ID` | clients |
| `secrets init` | prompts for the missing secrets, writes them into the config file, mode 0600 |
| `sign-selftest [IN [OUT]] [-tsa URL]` | certify + one approval, verify, print the report. The TSA default is `tsa_url` |
| `checkpdf FILE [-config FILE] [-pin FILE] [-tsa URL]` | verify every signature in a file, offline; no config is needed, nothing is written to disk. `trust: pinned` means every signing certificate had to be issued by the anchor (the CA baked into a `build-release.sh` binary, or the file given with `-pin`); `trust: none` means only integrity was checked. See [Validation-Guide.md](Validation-Guide.md) |
| `sign NAME EMAIL IN [OUT]` | one approval signature; the key is made for the call and dropped, never written |
| `audit-verify` | walk the hash chain. Exit 0 = valid, 1 = a break (with the reason) |
| `audit-write` | append a heartbeat event, which opens the day's file |
| `sweep` | run the sweeps by hand: expire, prune revocations, requeue crashed leases |
| `dbstatus` | schema version, integrity check, row counts |
| `user add NAME [SCOPES…]` | creates an API **account**: the JWT secret is printed once, and `--password-stdin` (or `USER_PASSWORD`) optionally sets a web password. `admin:read` is refused here — no account can be an administrator |
| `user list` | every account: username, `secret=set`, `pw=set|-`, scopes, created, revoked. The secret is never reprinted |
| `user rotate ID` | a new secret, printed once. Every token signed with the old one stops verifying at the next request |
| `user revoke ID` | closes the account; its tokens stop working at the next request, and the row stays for the audit trail |
| `worker` / `batch` / `mail-test` | see `runbook.md` |

`pdf-go`:

| command | what it does |
|---|---|
| `extract IN [-o schema.json] [-q]` | read the AcroForm: name, type, value, allowed values, flags, geometry. The probe step |

| `verify OUT [SPEC]` | the fields are as the spec said, and the file is not incremental |
| `fields IN [-page N]` | the field names, as a list |
| `pages IN [--page 1,3-5] [-o pages.json]` | the page boxes |
| `add-logo IN IMAGE [-o OUT]` | stamp artwork at a position, a page, or a signature field |
| `envelope create/send/get/links/report` | drive the service |
| `admin <verb>` | the operator's chores **over the API**: `dbstatus`, `schema`, `config-check`, `sweep`, `audit-write` (`-day`), `audit-verify`, `mail-test` (`-to`), `users`, `revoke-user` (`-id`). No shell on the server; `--server` + a credential and the answer is JSON |
| `doc` | the machine-readable guide to the JSON formats |

## CLI flags

`envelope create` takes the document as a positional argument, then:

| flag | meaning |
|---|---|
| `--server` | service base URL (`URL`) |
| `--token` / `--token-env` | client key, prefer the environment |
| `--insecure` | allow `http://` (development only) |
| `--spec` | fill spec JSON |
| `--parties` | parties JSON array |
| `--title` | envelope title |
| `--subject` / `--message` | recorded on the create event. Not the mail: the mail subject is `Signature requested: ` + `--title` |
| `--expires` | link lifetime, `72h` or `3d`; capped by the envelope |
| `--send` | send the invitations after creating |
| `--widget` | **signature placement**: name of the form field the first signature is anchored on. Not the form lock — that is `lockForm` in the fill spec |
| `--widget-page` | page the signature stack is placed on; default page 1 |
| `--widget-x` / `--widget-y` | first signature box, PDF points from the lower-left of the page |
| `--links-out` | file the signing links are written to (JSON, mode 0600; default `envelope-<id>.links.json`) |
| `--json` | print the service's JSON answer (default true) |
| `--username` | account whose secret signs the request (`USERNAME`) |
| `--jwt-secret` / `--jwt-secret-env` | the account's shared secret, prefer the environment (`JWT_SECRET`) |
| `--ttl` | requested token validity when the CLI mints; the service caps it at 15m |
| `--timeout` | request timeout, default 60s |

**Where the signatures go is your decision.** The service does not detect a
"Sign here" line and does not pick a page. Send no widget at all and every
signature is drawn in a 220x80 pt box at `X=60, Y=60` — the bottom-left corner of
page 1 — which succeeds, and usually reads wrong on paper. Successive parties
stack 90 pt apart on that one page, each box above the previous (from y=60 on an
A4 page that is eight boxes; beyond that the stack clamps and piles up).

`pdf-go fields contract.pdf` lists signature field names to anchor on;
`pdf-go pages contract.pdf` gives the page boxes to choose coordinates in. A
field name that is not in the document, or a page past the end of the **filled**
document, refuses the create rather than falling back quietly — the alternative
is a signature in the default corner reported as a success.

```sh
# anchor on a signature field the document already has
./tmp/pdf-go envelope create contract.pdf --spec spec.json --parties parties.json \
    --widget SigClient --send
# or an exact spot on page 3 (points, origin at the lower-left)
./tmp/pdf-go envelope create contract.pdf --spec spec.json --parties parties.json \
    --widget-page 3 --widget-x 72 --widget-y 648 --send
```

`envelope send`, `get`, `links`, `report` take the envelope id and the same
`--server`/`--token` flags. Every command prints the service's problem document
on a refusal:

```json
{"error":{"code":"invalid_spec","message":"...","hint":"..."}}
```

## One-shot contract run: scripts/qld-sign-run.py

`pdf-go envelope create` needs a fill spec, a parties file and a credential on
every call. `scripts/qld-sign-run.py` wraps that for a rental contract: one PDF,
one YAML, one command, and the envelope comes out filled and waiting.

```sh
export SIGNSRV_KEY=key_...                                  # minted at POST /api/v1/admin/clients
export SIGNSRV_URL=https://test-pdfsign.kaykraft.org
./scripts/qld-sign-run.py forms/Form-18a-General-tenancy-agreement.pdf -d scripts/qld-agreement.example.yaml
```

Real output from the test instance, on the official RTA form:

```
qld-sign-run: pdf-go:  ./tmp/pdf-go
qld-sign-run: fields:  62 to fill
qld-sign-run: parties: 2 (msh.computing@gmail.com, kaycaonz@gmail.com)
qld-sign-run: filled:  /tmp/qld-sign-run-0gjdx6wj/filled.pdf (494732 bytes) verified
qld-sign-run: widget:  8 item(s) sit under the boxes at x=36 y=160 on page 12
qld-sign-run: links:   tmp/final-links.json (mode 0600) - 2 signing link(s), not mailed
qld-sign-run: envelope e16ee1c04cedde1d06fb5da4eef0eb9b created (ready)
qld-sign-run: service applied 62 field(s)
qld-sign-run: not dispatched: the admin sends the invitations from the dashboard
qld-sign-run: events:  created, transition
qld-sign-run: envelope e16ee1c04cedde1d06fb5da4eef0eb9b is 'ready' - filled, awaiting dispatch
```

The `pdf-go:` line names the binary actually used. There is more than one build
of it on this machine and they do not produce identical bytes, which matters
because the service re-applies the fill itself.

The YAML (`scripts/qld-agreement.example.yaml`) is the whole input: `pdf:`,
`server:`, `envelope:`, `widget:`, `form:` (field name = value, `true` for a
checkbox) and `parties:`. Nothing about the credentials is in it, so the file is
safe to commit or mail. Field names come from `pdf-go extract <form>.pdf`;
a name the PDF does not have stops the run and prints the culprit, rather than
uploading a half-filled agreement.

What the script does and does not do:

- fills **locally** with `pdf-go fill`, then `pdf-go verify` reads the result
  back. A mismatch exits 3 and nothing is uploaded. `pdf-go` is **required** —
  it is found via `$PDFGO`, then `pdf-go` on `$PATH`, then `./tmp/pdf-go`; name
  it explicitly with `--pdf-go` if you have more than one build, because the
  script prints which one it used and the service re-applies the fill itself.
- uploads the finished bytes to `POST /api/v1/envelopes` with the fill spec
  nested as `{"fill":{"values":{...}},"widget":{...}}`, exactly as `pdf-go`
  sends it.
- **never calls `/send`**. The envelope lands in `ready`, which is the state a
  create leaves behind, and the admin dispatches from the dashboard. The run
  re-reads the envelope and prints its events so you can see no dispatch
  happened.
- does not print the signing links, because nobody has been mailed. `--links-out
  FILE` writes them at mode 0600 when you want them.
- retries only `429` and `500`. `502/503/504` are ambiguous — the create may have
  committed while the answer was lost and the endpoint has no idempotency key —
  so it refuses to guess and tells you to check `GET /api/v1/envelopes`.

- signature placement is the `widget:` block. `auto: true` has the script
  measure the last page — page list from `pdf-go pages`, field rectangles from
  `pdf-go extract`, printed words from `pdftotext -bbox` — and start the stack in
  the lowest left-column band that clears them all, printing what it chose. The
  service never searches for free space and never refuses on overlap.

`--dry-run` does everything except the network: it fills, verifies, and prints
the payload. It needs no credential, which makes it the check to run before
touching a live instance. Exit codes: 0 created; 1 usage, config or fill
problem; 2 the service refused; 3 created but the envelope is not `ready`.

Full guide, including the placement arithmetic and the checks to run on a new
form: [`docs/skills/run-qld-contract.md`](docs/skills/run-qld-contract.md).

## Troubleshooting
## Two credentials, one username

An account in the `users` table can carry two credentials, and the API accepts
two kinds of bearer token. Keeping them straight is the whole design:

| credential | who holds it | what it does |
|---|---|---|
| `jwt_secret` (base64url, 32 bytes) | the operator's laptop, a CI runner, a systemd unit | lets the holder **sign** its own access token. The CLI does it with `--username` + `JWT_SECRET`; the secret itself never travels, and there is no token request |
| client key (`key_…`) | an API integration | is **exchanged** at `POST /api/v1/auth/token` for a short access token; the key never rides on a call |
| `password` (argon2id) | a human, at the web desk | signs in to the SPA. Today that desk is the admin portal; the account table is the table it will read |

`TOKEN` holds whichever of the two shapes you have: a `key_…` value is
exchanged, and a three-part `a.b.c` value — an access token minted by login, by
refresh, or by the token endpoint — is sent as it is, which is what a chore
script wants: mint once, spend one request per verb.

The service answers a request with the **scopes on the row**, re-read every
request, and with `role = 'user'` whatever the token claims. A caller-minted
token is refused on every `admin:*` route with `insufficient_scope`, so a leaked
dispatch secret is a document credential and nothing more. That is why
`signsrv user add` refuses to write `admin:read` into a row: the scopes column
could not make it true, and a column that lies is worse than one that is absent.

Closing an account is immediate, not at token expiry:

```sh
signsrv user rotate 7        # a leaked secret: every token signed with it dies now
pdf-go admin revoke-user -id 7 --server https://srv.example  # from the desk, no shell
```

Both leave the row in place, stamped `revoked_at`: the audit trail of what its
secret signed stays verifiable, and `pdf-go admin dbstatus` counts it under
`users_revoked` so you can tell "revoked" from "never existed".

Every variable a credential lives in — `URL`, `TOKEN`,
`USERNAME`, `JWT_SECRET`, `USER_PASSWORD` — is read from the
environment, never from argv, so none of them appears in a process list.


- `problem: file:line: unknown config key "listenx"` — typo in the config;
  accepted names are in `config.example.env`.
- `problem: dev mode is only allowed on a loopback listener` — `dev=true` with
  a public `listen`. Remove `dev` or bind to `127.0.0.1`.
- `/admin/` says `the email address and password do not match` — there is no
  admin row. Run `signsrv admin add EMAIL` with the password in
  `ADMIN_PASSWORD` (at least 12 characters).
- `the credential behind this token was replaced; sign in again` — the admin
  password was changed with `signsrv admin passwd`, which stamps the credential
  epoch and ends every token minted under the old password. This is the action
  to take when a token is stolen.
- A signing link says `This link has expired. Ask for a new one.` or
  `This request is closed. Nothing is signed.` — the token expired, was
  reissued, or the envelope was cancelled. An admin can reissue links.
- `Too many attempts. Try again in 30s.` — a rate limit: 5 logins per minute
  per address, 10 claims per minute per address, 10 consents per minute per
  envelope. The number comes from `Retry-After`.
- Mail sits in `outbox_dir` — dev mode, by design.
- Every response carries an `X-Request-Id` header, and the same id appears in
  the log line for that request; quote it when reporting problems. Tokens,
  passwords, keys and signing addresses never appear in the log: verified on a
  dev run (0 hits for the link token, the client key and the admin password in
  the whole log).
