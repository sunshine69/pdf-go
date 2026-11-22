# Quick Guide — how this codebase works

Read this first. It is the map: what the pieces are, how a request moves through
them, and where to make a change. Everything here is read from the code, not
from a design doc. If a longer doc contradicts this one, this one is current
(the design docs describe intent at build time; see [Doc map](#doc-map-what-to-read)).

Module: `github.com/sunshine69/pdf-go`. Pure Go, CGO off, `modernc.org/sqlite`.
One static binary ships the whole service.

---

## The 30-second version

A PDF with AcroForm fields goes in. The service fills it, certifies it with a
local CA, emails each party a one-time link, waits for consent, then
cryptographically signs it in a batch and emails the finished document back.
Signatures verify offline against the CA — the service is not needed to
validate a signed file.

Three binaries:

| Binary | What it is |
| --- | --- |
| `cmd/signsrv` | **The product.** HTTP API + 2 web apps + signing worker + all operator CLIs. |
| `cmd/pdf-go` | CLI: inspect/fill/verify a PDF, and drive the API. |
| `cmd/mock-tsa` | Test-only RFC 3161 timestamp server. Never production. |

`cmd/signsrv-utils` is a build-tag-gated maintenance binary (offline DB surgery).
Not in the normal flow.

---

## Package map

```
cmd/signsrv/        HTTP server, config, worker, operator verbs. Largest package.
cmd/pdf-go/         CLI (extract/fill/verify/pages/logos + `envelope` API client)
internal/signstore/ SQLite: migrations, every query, the audit hash-chain
internal/signauth/  JWT(HMAC + Ed25519), argon2id, rate limits, scopes, middleware
internal/signflow/  Domain core: states, tokens, create/send/claim/consent, batch, delivery
internal/signpdf/   PKCS#7: CA + keystore, certify, sign, verify, appearance, TSA
internal/pdf/       AcroForm I/O: extract, fill, appearance, overlay, pages
internal/signmail/  SMTP + the Go templates in web/templates/
internal/report/    Verification report shown by GET /report
internal/schema/    JSON shape of the fill spec
web/spa/            Signer app (vanilla JS, embedded)   → served at /s/{token}
web/admin/          Admin app  (vanilla JS, embedded)   → served at /admin/
web/templates/      Email + status-page templates (Go html/template)
e2e/                The end-to-end test (its own package; `e2e/run.sh`)
deploy/             Dockerfile, compose, systemd unit, nginx/Caddy, logrotate
packaging/deb/      The .deb: control, maintainer scripts, first-boot
testdata/           Sample PDFs used by the Go tests
```

Anything under `tmp/`, `run/`, `var/`, `dist/`, `*.links.json` is generated or a
credential. All are gitignored; never commit them.

The dependency direction is the thing to respect:
`cmd/signsrv → internal/signflow → {signstore, signauth, signpdf, signmail, pdf}`.
`signflow` holds the business rules. A handler that starts deciding things
belongs in `signflow` instead.

## Key files (the ones you end up in)

| File | Why it matters |
| --- | --- |
| `cmd/signsrv/routes.go` | Every endpoint, its scope, its rate-limit bucket. **Start here for any API change.** |
| `cmd/signsrv/config.go` | Every setting: file key, `*` env, default, validation. |
| `cmd/signsrv/envelopes.go` | Create (multipart!), send, get, document. |
| `cmd/signsrv/worker.go` | The background loop: mail, batches, sweeps. |
| `internal/signflow/state.go` | The state machine and the legal transitions. |
| `internal/signflow/consent.go` | `ConsentInput` — what the public consent endpoint accepts. |
| `internal/signflow/batch.go` | The batch-sign path: sign all parties, verify gates. |
| `internal/signstore/migrations.go` + `schema*.go` | Schema is versioned v1…v8 (`CurrentVersion`); new column = new `schema_vN.go` plus one entry in `migrations`. |
| `internal/signauth/middleware.go` | Scope names (bottom of file) and who is granted what. |
| `internal/signpdf/keystore.go` | CA + key passphrase handling. **Changing this can invalidate every past signature.** |

---

## The life of a document

```
POST /api/v1/envelopes (multipart: template, title, spec, parties)
  -> pdf fill (signflow/signfill)            unknown field name = hard error
  -> signpdf certify the filled PDF           needs keystore_pass
  -> store envelope + parties + revision      link token minted HERE, stored HASHED
  -> 201 {envelope, fill.applied, links[]}    links[] carries the only plaintext
POST /envelopes/{id}/send -> mails each link
POST /api/v1/sign/{token}/claim   {email}   -> session cookie; gates on STATUS not token
GET  /api/v1/sign/{token}/envelope          -> carries document_sha (needs claim)
POST /api/v1/sign/{token}/consent {consent, document_sha, signature_text, image}
  -> consent row written, NO PDF touched; last consent -> batch_queue row
worker: drainBatches -> signpdf sign each party -> verify gates -> completed -> delivered
GET  /envelopes/{id}/report   complete:true, signers[].valid:true, errors:[]  <-- PASS CONDITION
GET  /envelopes/{id}/audit.zip  evidence bundle
```

States (`internal/signflow/state.go`):
`draft → ready → sent → collecting → signed → completed → delivered`,
terminal side-exits `expired`, `cancelled`, `failed`.
Illegal transitions return `ErrStateConflict` → **HTTP 409**.

## The worker

`signsrv worker` (also started in-process by `serve`). Two tickers:
- **mail tick** (`worker_interval`, default **15s**): `drainMail` then `drainBatches`.
  Batches ride the mail tick deliberately — waiting for the sweep tick would leave a
  fully-consented envelope unsigned for a whole sweep period.
- **sweep tick**: expire, reclaim stale leases, retry/fail exhausted queue rows.

Link tokens are stored **hashed**. The queue therefore cannot reconstruct a link
that the creating process no longer holds — which is why `send` delivers inline
when it can and the queue is only the retry path. Don't "fix" this by storing
tokens in the clear.

---

## Auth: the four confusing facts

1. **An admin login token carries all scopes.** It answers `{scopes:["admin:read"]}`
   but the middleware (`internal/signauth/middleware.go`) grants every scope to an
   admin. The single name is not a restriction. **You never need a machine key to
   run the flow.**
2. **The admin surface is Ed25519-only** (`ScopeAdminRead` at middleware.go:223).
   A caller-minted HMAC token can never reach admin routes, whatever its row
   grants. A leaked dispatch secret cannot read the whole system.
3. **Machine keys mint HMAC tokens.** They exist to grant *less* than an admin, or
   to avoid holding a human password. Mint with `signsrv client add NAME SCOPES…`
   or `POST /api/v1/admin/clients`. Scopes are separate arguments.
4. **The public signing routes use no bearer token** — the link token *is* the
   credential, guarded by `signGuard` (per-address or per-envelope limits).

Scopes: `envelope:read`, `envelope:write`, `admin:read`. Access TTL is 15 min.

A route with no scope listed is **not granted** — default deny.

---

## Config

`-config FILE`, or env `*` (env wins). `signsrv checkconfig` validates
without starting. Load-bearing keys:

| Key | Notes |
| --- | --- |
| `keystore_pass` | Encrypts `ca.key`. **Cannot be rotated after the CA exists** — wrong passphrase = every past signature reads invalid. |
| `jwt_secret_file` | Ed25519 key pair. `signsrv secrets init` creates it. |
| `admin_password` | Password only. **In production it creates an account only on the first start**, and only the one `DEFAULT_ADMIN_EMAIL` names; after that use `signsrv admin add`. |
| `dev` | Never true in production. Loopback HTTP, mail to `outbox_dir`, and it **auto-creates `dev@localhost`** and logs the password when the DB has zero admins (`cmd/signsrv/devadmin.go`). |
| `storage_dir` | PDFs as `<sha256>.pdf` — content-addressed, so identical bytes share a file. |

---

## Schema changes while developing

Nothing to run, usually. Every command that opens the database migrates it
first — `serve`, `worker`, `dbstatus`, `admin`, `client`, `user`, `sign` — so a
schema added in `internal/signstore/` is applied the moment you start the dev
server.

To do it deliberately, on the database your config names:

```sh
signsrv -config CFG migrate       # or: DB=var/signsrv.db DEV=1 signsrv migrate
    migrations applied: 8, schema version 8       (only when something was pending)
    schema version 8, database /abs/path/var/signsrv.db
    integrity_check: ok

signsrv -config CFG migrate       # second run: nothing applied, same version
signsrv -config CFG dbstatus      # schema version + a row count per table
```

A fresh dev database is the same path with the file gone: `rm var/signsrv.db`
and start — `dev=true` then creates the schema, the CA, the token key and
`dev@localhost`, and logs the password it generated.

Adding a migration: new `internal/signstore/schema_vN.go`, one entry appended to
`migrations` in `migrations.go`, and `CurrentVersion` bumped. Never edit a
released entry. Each one runs in its own transaction with its version row, so a
half-applied step is not observable, and `Migrate` refuses a database whose
version is newer than the build (exit 1) rather than guessing — which is why
there is no down migration and a rollback means restoring the backup.

`signsrv-utils` migrates too, but it will not create a database: it refuses a
path with no file there, so pointing it at a typo cannot leave you editing an
empty one.

---

## Build / test / gates

```sh
go build ./... && go vet ./... && go test ./...      # the gate; must be clean before commit
gofmt -l cmd/ internal/                              # must print nothing
scripts/test.sh                                      # the same plus extras
go test ./cmd/signsrv/ -run DevAdmin -v              # run one group
e2e/run.sh                                           # full end-to-end against a real server
```

54 test files. `cmd/signsrv/*_test.go` build a real migrated store — copy
`auth_test.go`'s `authServer()` when you need a handler test, or
`signsrv_test.go`'s `newTestServer()`.

---

## Pitfalls (each one cost someone time)

- **`curl -F "spec=@file"` is wrong.** `@` makes a *file part*; Go's `FormValue`
  ignores file parts; you get `400 spec required` while the field is plainly
  present. Use `-F "spec=<file"`. Same for `parties`. (`template` is a real
  upload, so it *does* use `@`.)
- **`pdf-go extract` stdout is a human report, not JSON.** Use `-o schema.json`.
- **An unknown fill field is a hard error**, not a skip:
  `unknown field "…"; run extract to list the available fields`, no envelope created.
- **API times are UTC with a literal `Z`; log lines are local.** A signer in
  another zone can read a deadline a day off. State deadlines in words in `-message`.
- **Event rows use the key `kind`, not `type`.**
- **`send` returning 200 means queued, not delivered.** Trust the party status
  (`sent` → `claimed`) and then the report.
- **`report` needs `--server`** on the CLI, and the envelope id is positional.
- **A manual SIGTERM can hang the deb service** if the stop command is
  `/bin/kill` — Go does not trap signals through `/bin/sh`. Use `/usr/bin/kill`.
  (This killed a deploy; the systemd unit and init script now use `/usr/bin/kill`.)
- `dev=true` in production is a fatal config error, by design.

## Security rules for this repo

- Never commit or print a link token, machine key, password, session cookie, or
  `*.links.json`. `links.json`/`client.key` are mode 0600 and get deleted after a run.
- `reissue` invalidates the link a party is holding (their page becomes 410).
  Never re-mail a link without being asked.
- One envelope per document version. Changed document → new envelope.
  `send` on a sent envelope is 409.
- Consent is once-only: a consented party has no second consent; a decline ends
  the envelope.
- Never hand-edit a live SQLite database with an external tool — go through
  `signsrv` verbs or `signsrv-utils`.

---

## Where do I change X?

| Change | Touch |
| --- | --- |
| Add/modify an endpoint | `cmd/signsrv/routes.go` (pick scope + bucket), handler in `cmd/signsrv/`, rule in `internal/signflow/` |
| New request/response field | handler struct in `cmd/signsrv/`, `internal/schema/` if it's a fill spec |
| New config key | `cmd/signsrv/config.go`: read, default, validate; then `docs/CONFIG.md` |
| DB column/table | new `internal/signstore/schema_vN.go` migration; never edit an old one |
| Consent payload shape | `internal/signflow/consent.go` `ConsentInput` + SPA in `web/spa/` |
| Email wording/layout | `web/templates/`, rendered by `internal/signmail/` |
| Signature appearance/appearance box | `internal/signpdf/appearance.go`, `internal/pdf/appearance.go` |
| State transitions | `internal/signflow/state.go` |
| Rate limits | `internal/signauth/ratelimit.go` (constants), `cmd/signsrv/routes.go` (which bucket) |

## Verifying a change

Always: `go build ./... && go vet ./... && go test ./...` and `gofmt -l cmd/ internal/`.
A real round trip: `e2e/run.sh`, or `scripts/prod-sign-run.sh` for the full
live sequence. Security-sensitive change to a public route:
`scripts/security-probe-sign-endpoints.sh` (and `…2.sh`).

---

## Doc map (what to read)

**Current and useful**

| Doc | For |
| --- | --- |
| `docs/QUICK-START.md` | this file — orientation and where to change things |
| `docs/skills/prepare-and-dispatch-signing.md` | **fill + dispatch procedure**, API-first. The runnable recipe. |
| `docs/CONFIG.md` | every setting, env var, default, what refuses to start |
| `README-signing.md` | running the service end to end |
| `runbook.md` | operational procedures as commands |
| `docs/DEPLOY-DOCKER.md`, `docs/DEB-PACKAGE.md` | containers, .deb, first-boot, upgrade/purge |
| `docs/security-endpoint-audit.md` | the endpoint audit: probes, findings, accepted residual risks |
| `Validation-Guide.md` | recipient-facing: is this PDF genuine |
| `SECURITY.md` | secrets ranked by blast radius |

**Historical / build-time design — do not treat as current**

`docs/00-overview.md` and `docs/steps/01…14-*.md` are the original design and
signoff docs (the `Signoff` blocks are the reviewer's). `docs/build-and-test.md`
and `docs/runbook-e2e.md` describe per-step manual testing. Useful as "why is it
this way", misleading as "what does it do" — trust the code.

**Overlapping**

`Validation-Guide.md` (recipient, short) vs `Validation-Guide-Technician.md`
(full technical). Different audiences, not duplicates — keep both, link them.
