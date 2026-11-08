# Build and test, step by step

A single page that answers two questions: *how do I build this*, and *how do I
test each of the 12 steps by hand*. Every command is runnable as written. Every
step ends with a **Verification status** block that says, honestly, what is
proven by a test you can run today and what is still **TODO**.

The convention of `docs/steps/` is that the **reviewer** ticks the signoff
boxes, not the implementer. The boxes in steps 02, 03, 07, 08 and 12 are
deliberately left unticked: several of their acceptance items have no
mechanical check today, and ticking them on the strength of "the code looks
right" is exactly what the signoff is meant to prevent.

Related: [docs/README.md](README.md), [runbook.md](../runbook.md),
[SECURITY.md](../SECURITY.md), [docs/runbook-e2e.md](runbook-e2e.md).

## 0. The build

```sh
go build /cmd/signsrv       # the service: API, apps, worker
go build /cmd/pdf-go        # the CLI: PDF probe/fill/verify + envelope client
```

Both binaries are built by `e2e/run.sh` itself, so the acceptance run always
tests the tree it is in. There is no `vendor/` tree: `go build` takes the
dependency list from `go.mod` and verifies each module against `go.sum`, so the
first build on a clean machine reaches the network and later ones use the
module cache.

```sh
go vet ./...                  # silent
go vet -tags e2e ./e2e        # silent, includes the acceptance run
gofmt -l cmd internal web                 # silent
```

Dependencies are `modernc.org/sqlite` (pure Go driver), `github.com/go-chi/cors`,
`github.com/yeasy/pdfsign`, `golang.org/x/{crypto,mod}`. Nothing is fetched
during a build; nothing runs a Node build step. The web assets are committed
plain HTML/CSS/vanilla JS, embedded with `go:embed`.

## 1. The unit suite — one command

```sh
go test -count=1 ./cmd/pdf-go ./cmd/signsrv \
    ./internal/pdf ./internal/report ./internal/schema \
    ./internal/signauth ./internal/signfill ./internal/signflow \
    ./internal/signmail ./internal/signpdf ./internal/signstore \
    ./web/spa ./web/admin
```

- `-count=1` defeats the test cache: the run you see is the run that happened.
- No package needs a network, a browser, a service, or a real mailbox. Every
  test starts its own in-memory or temp-file SQLite store, its own mock TSA, and
  its own in-process HTTP handler.
- The acceptance run carries `//go:build e2e`, so `go test ./...` never compiles
  it. It is a program that drives real processes, not a test in the suite.

Current state: **all 11 tested packages pass.** Test counts, by package:
`cmd/signsrv` 70, `internal/signflow` 48, `internal/signauth` 41,
`internal/signstore` 32, `internal/signfill` 11, `web/spa` 11, `web/admin` 11,
`internal/signmail` 7, `internal/signpdf` 7, `cmd/pdf-go` 7. Total 220.

`internal/pdf`, `internal/report`, `internal/schema` and `internal/logos` have
**no package-level tests** — they are exercised through the CLI, the fill layer
and the signing tests. That is a coverage gap; see *TODO ledger* at the end.

```sh
go test -race ./cmd/signsrv ./internal/signflow   # race detector
go test -cover ./...                              # coverage report
```

## 2. The acceptance run — one command

```sh
e2e/run.sh                     # every phase
e2e/run.sh -list               # list the phases
e2e/run.sh "send + outbox"     # every phase up to the one named
E2E_SKIP_BROWSER=1 e2e/run.sh  # the phases up to "send + outbox"
```

Prerequisites: `go`, and — only for the browser phase — `node`, `playwright-core`
(installed into `/tmp/pw` by `run.sh` on first use) and a Chrome/Chromium
(`CHROME=/path/to/chrome` to point at one). The run does not use the network
beyond loopback: the TSA is a mock on `127.0.0.1`, the mail is written to a
dev outbox as `.eml` files.

Evidence lands in a temp work dir, printed as `evidence: …/reports`. The signed
artefacts are copied into `./signing-artefacts/` on a green run, together with
the private keys and the mock TSA root, so a human can check the chain with a
standard tool:

```sh
openssl verifysig -in signing-artefacts/approval_sig.p7b -in signing-artefacts/certified.pdf \
    -certs signing-artefacts/tsa-root.pem
```

Current state: **18 of 18 phases pass**, `failures: 0`, about 35 seconds with
the browser included. The history of the four checks that used to fail is in
§4.1: all of them were defects in the test code, none in the service.

## 3. Step-by-step: how to verify each step

For each step: the test command that proves it, the manual command that
demonstrates it, and the status. `TODO` means "no mechanical check today".

### Step 02 — database

```sh
go test -count=1 ./internal/signstore
```
Manual:
```sh
signsrv -config CFG migrate       # prints version reached, runs integrity_check
signsrv -config CFG migrate       # run twice: the second is a no-op
signsrv -config CFG dbstatus      # schema version + row count of every table
signsrv -config CFG sweep         # expire overdue rows, requeue crashed leases
```
Proven: migration is idempotent and versioned, refuses a newer schema,
cascades deletes, rejects duplicate parties, token-hash lookup, `PutPDF`
refuses non-PDF bytes, sweeps expire an old envelope, batch queue lease and
backoff, mail queue lifecycle, consent once per party, list search/paging,
status validation, JTI revocation, `events` has no UPDATE/DELETE path, settings
round trip, NULL scan mapping. Driver probe pins the driver contract.

> **Verification status:** [x] idempotent versioned migration · [x] sweeps tested
> · [ ] *no string-built SQL* — no grep/AST check, review by eye (**TODO**)
> · [ ] *no plaintext secret in any column* — only the JWT key ring is
> permissions-checked in tests; a column-level audit of `signstore` is
> **TODO**

### Step 03 — auth

```sh
go test -count=1 ./internal/signauth
go test -count=1 -run 'TestLogin|TestPassword|TestRefresh|TestLogout|TestClient|TestRequire|TestRateLimit|TestPathToken|TestSession' ./internal/signauth
```
Manual:
```sh
SIGNSRV_ADMIN_PASSWORD='…' signsrv -config CFG admin add ADMIN@OPS.EXAMPLE
signsrv -config CFG admin list
signsrv -config CFG admin passwd ADMIN@OPS.EXAMPLE   # stamps the credential epoch
signsrv -config CFG client add ops-tool envelope:write envelope:read
signsrv -config CFG client revoke ID
```
Proven: access round trip; tampered signature, `alg:none`, wrong audience,
expired, wrong keyring, revoked `jti`, pre-epoch tokens all refused; key ring
file permissions; argon2id round trip, salt is random, foreign format refused;
login cost is the same for an unknown address (no address enumeration);
refresh single-use, chain deleted as a unit, sweep deletes stale chains;
logout ends the chain and touches no other subject; admin scope cannot reach a
signer route and a signer cookie cannot reach the API; client login for
unknown/revoked clients; bearer scheme, missing bearer, missing scope;
signer cookie flags, claim required, session match, session cross-link,
expired link; rate limit 429, per-envelope limit, proxy trust, path token.

> **Verification status:** [x] all five items **proven by named tests** —
> `TestAccessAlgNone`, `TestAccessWrongAudience`, `TestRequireAPIRevokedJTI`,
> `TestRequireSignerSessionCrossLink`, `TestPasswordRoundTrip`,
> `TestLoginUnknownEmailCostsTheSame`, `TestRefreshSpendsTheToken`,
> `TestRequireAPIMissingScope`, `TestAdminClientTokenCannotReadStats`.
> The boxes in `docs/steps/03-auth.md` are still unticked for the reviewer.

### Step 04 — pdfsign adapter

```sh
go test -count=1 ./internal/signpdf ./internal/signfill
signsrv -config CFG sign-selftest testdata/sample2.pdf /tmp/out.pdf -tsa http://127.0.0.1:8999
signsrv -config CFG checkpdf /tmp/out.pdf
```
`sign-selftest` is the acceptance harness for this step: certify, sign three
test parties, verify; exit 0 only when the finished document is valid.
Proven: certify happens before any change; three parties nest in order;
a tampered document fails; missing TSA is an error, never a silent skip;
leaf certificates have a lifetime and no private key; widgets stay inside the
crop box; key file is owner-only (0600).

> **Verification status:** all five boxes **proven by named tests**.

### Step 05 — envelopes

```sh
go test -count=1 -run 'TestCreate|TestGetEnvelope|TestEnvelopeScopes|TestList|TestDownload' ./cmd/signsrv
go test -count=1 -run 'TestCreate|TestCertifiedDocument|TestTransition|TestDocumentDownload' ./internal/signflow
```
Manual:
```sh
signsrv -config CFG serve                                  # dev = true
pdf-go envelope create --server http://127.0.0.1:PORT --token TOK \
    --template testdata/sample2.pdf --spec fill.json --parties parties.json \
    --title "NDA" --expires 72h --links-out links.txt --send
pdf-go envelope get ID --server http://127.0.0.1:PORT --token TOK
pdf-go envelope links ID --links-out links.txt
pdf-go envelope report ID --server http://127.0.0.1:PORT --token TOK
```
Proven: create via API; an unknown field leaves **no rows**; duplicate and
gapped party orders refused; get and document download; every scope boundary;
list paging; download name is slugified; the certified document is read-only;
illegal state advances are refused.

> **Verification status:** all five boxes **proven by named tests**.

### Step 06 — tokens and email

```sh
go test -count=1 ./internal/signmail
go test -count=1 -run 'TestToken|TestSend|TestExpired|TestLinkExpiry|TestMailFailure|TestHostileName|TestNameWith' ./internal/signflow
```
Manual:
```sh
ls OUTBOX/                       # one .eml per party in dev mode
grep -c '^Message-ID:' OUTBOX/*.eml
```
Proven: tokens are unique and 52 characters; lookup round trip; send produces
one `.eml` per party; sending twice is a conflict; a hostile display name is
inert in the HTML and a name containing a line break is rejected (no header
injection); expired lookup is expired; link expiry is capped by the envelope;
create queues no mail and send queues one per party; a mail failure leaves the
envelope state and notifies the admin. Render tests: the full link, no markup,
the link needs no escaping, RFC 1123 date, Message-ID shape, one text/html 8bit
the dev outbox file parses.

> **Verification status:** all five boxes **proven by named tests**.

### Step 07 — consent

```sh
go test -count=1 ./internal/signflow
go test -count=1 -run 'TestConsent|TestDecline|TestClaim|TestLastConsent|TestSignerDocument' ./cmd/signsrv
```
Proven: consent is data only, no PDF touched in the request; consent carries
the certified document's sha, and a stale digest is refused; twice is refused;
the session is invalidated (claim after consent is refused); the declaration
(text, checkbox, image, `strict`) is validated; the signature image rules
(PNG/JPEG magic, size, count); decline refuses the envelope and twice is
refused; consent on an expired link is `gone`; the last consent enqueues
**one** batch row; the consent input carries no power (no fill, no key, no
signing); the state table and illegal advances.

> **Verification status:** all five boxes **proven by named tests** —
> `TestConsentInputCarriesNoPower`, `TestConsentIsBoundToTheCertifiedDigest`,
> `TestConsentTwiceIsRefused`, `TestLastConsentEnqueuesOneBatch`,
> `TestEnvelopeViewBeforeClaim` (other parties' addresses absent).

### Step 08 — signer SPA

```sh
go test -count=1 ./web/spa
go test -count=1 -run 'TestCSP|TestStaticRoutes|TestSignerShell' ./cmd/signsrv
```
Proven: the embedded files exist; no external URLs in HTML, JS or CSS; the
token is read from the path, never written to `localStorage`/`sessionStorage`;
`fetch` uses `same-origin` credentials; CSP signer directives; the consent
checkbox is required and not pre-checked; the timeout; every status code is
handled. The server tests prove the CSP header and that the signer shell hides
the token.

> **Verification status:** [x] all four boxes **proven by named tests**.
> [ ] *Verified in a real browser* (devtools shows the header, no request leaves
> the origin) is a **TODO** — the SPA tests read source, not a running browser.

### Step 09 — admin UI

```sh
go test -count=1 ./web/admin
go test -count=1 -run 'TestAdmin' ./cmd/signsrv
```
Proven: 11 static-asset tests (files exist, no external URLs, `textContent`
not `innerHTML`, same-origin fetch, visibility check on polling, the key is
shown once, the cancel action requires a reason); 10 server tests (the
collecting tile, a client token cannot read stats, cancel a collecting
envelope, cancel a delivered one is a conflict, the second reminder is
limited, reissue links, sign-now, audit zip, report, settings and clients,
events and logout).

> **Verification status:** all four boxes **proven by named tests**.

### Step 10 — batch signing

```sh
go test -count=1 ./internal/signflow
go test -count=1 -run 'TestBatch|TestDelivery' ./internal/signflow
```
Proven: all parties signed in order, signatures nest; the consent enqueues the
batch row; a TSA failure retries, keeps the envelope open for retry, then fails
cleanly; the batch runs a consented party without re-running consent; **gate 1**
refuses a missing party signature; the receipt is written; one delivery per
party; a large document uses a download link; **gate 2** refuses a tampered
document, and reissuing over tampered bytes keeps the accepted records;
settings are validated at the boundary; the batch is idempotent; a tampered
input fails and sends **no** email; the report matches the stored leaf
certificates; party rows are marked and signing links are closed; one consent
leaves the envelope open.

> **Verification status:** all five boxes **proven by named tests**.

### Step 11 — hardening

```sh
go test -count=1 -run 'TestSecrets|TestRedaction|TestAccessLog|TestCheckConfig' ./cmd/signsrv
go test -count=1 -run 'TestAudit' ./internal/signstore
signsrv -config CFG checkconfig      # exits non-zero, secrets printed as digests
signsrv -config CFG audit-verify     # hash chain, prev_hash, monotonic ids
```
Proven: tokens, passwords, keys, secrets and signing addresses never reach the
log; the redaction helper is honest; the access log shape; `checkconfig`
accepts a loopback dev config, refuses a non-loopback listener, a loose JWT key
mode, a missing keystore, warns on a plain TSA, and its report contains no
secrets; audit write then verify, write is idempotent, verify catches
tampering and missing events, write refuses a tampered tail, a tampered tail
behind an empty day, a backwards day, empty dir is fine, files are owner-only;
rate limits per address and per envelope, body caps, magic-byte refusals.

> **Verification status:** [x] redaction · [x] append-only audit ·
> [x] body limits and magic bytes · [x] `checkconfig` fails loudly ·
> [x] TLS/HSTS reference config (`deploy/Caddyfile`) committed.
> [ ] *Verified on a real TLS deployment* and [ ] *log rotation verified*
> are **TODO**.

### Step 12 — end-to-end

```sh
e2e/run.sh
```
The 18 phases: build, mock tsa, config, start service, admin login, client key,
cli create, send + outbox, browser signing, cli watch, cli report, audit chain,
artefacts, negatives, rate limit, user accounts, log redaction, graceful stop.

Proven today (all 18 phases green, `failures: 0`, 34 s): the CLI creates the
envelope through the API, the service sends, **real Chrome** drives a party
through claim → document → declination → consent, the worker signs the batch,
the CLI polls to delivered, the CLI writes the verification report, the audit
chain verifies, the signed artefacts are kept, tokens/keys/passwords are absent
from 403 log lines, SIGTERM drains clean, and every negative path asserts a
state (a replayed consent, an expired link, a cancel, 15 consent payload rules,
a non-PDF upload, the consent limit, the login limit, the link limit,
caller-minted tokens).

> **Verification status:** [x] artefacts kept for inspection ·
> [x] CLI integration uses the shared fill spec, no duplicated logic ·
> [x] no network beyond loopback ·
> [x] **Happy path runs green from a clean checkout** — 18 of 18 phases,
> `e2e/run.sh` exits 0 ·
> [x] **All negative paths assert a state** — 9 of 9 negative checks pass,
> each on a status code and a field, and each leaves an evidence file ·
> [x] the run leaves the audit chain valid after the negative set.

### Step 13 — accounts, CLI-minted tokens, chore endpoints

```sh
go test ./internal/signauth ./internal/signstore ./cmd/signsrv ./cmd/pdf-go
e2e/run.sh "user accounts"
```

Proven: an account's secret lets the CLI sign its own access token and the
service verifies it against the row (no token round trip, the secret never
travels); the scopes of such a request are the row's, and every `admin:*` route
refuses a caller-minted token with `insufficient_scope` **whatever** the row's
scopes column says — which is why `user add` refuses to write `admin:read` at
all; `user rotate` stops the old secret at the next request; `admin revoke-user`
closes the account at the next request and the refusal names `token_revoked`,
with the row left stamped so `admin dbstatus` can tell revoked from absent; all
nine chore verbs of `pdf-go admin` reach the route they name and answer with the
field asked about, and `admin users` never carries a secret.

> **Verification status:** [x] §7 items 1, 3, 6, 8, 9, 10 run in the acceptance
> run · [x] items 2, 4, 5, 7 run in the unit suites · [x] no credential read
> from argv · [x] `admin:read` ungrantable to an account · [x] the run's
> log-redaction phase covers `SIGNSRV_JWT_SECRET` and the minted token.

## 4. TODO ledger — the checks that do not exist yet

Every item below is a **gap I am not pretending is closed**. None is a service
defect found by a test; all are missing checks.

### 4.1 Closed: the four negative-path checks that used to fail

All four were test-code defects, and no service change came out of any of them:
the service refused as designed in every case, the test was reading the wrong
thing. What each one was, and what the fix asserts now:

| # | Item | What was wrong | What the fix asserts |
|---|---|---|---|
| 1 | `negatives / duplicate consent` | a request built by `negCreate` was left **ready**, never **sent**, so a party could not act on it at all; the consent bodies also omitted `document_sha`, which the service compares with the stored revision | `negCreate` sends the request before any party touches it, and the consent names the digest read from the envelope view. The gate is the status, not the token: create mints the link and send reuses it in one process, and a party cannot act until the request is sent. The replay is then asserted on two doors: a consented party may not claim again (409), and the same body without a session is refused (401) |
| 2, 3 | `negatives / consent rules`, `consent limit` | every check claimed from `127.0.0.1`; claim is 10/min **per address**, so the eleventh claim of the run got a 429 that said nothing about the rule under test | each check dials from its own loopback address (`negUseAddr`), and the 15 consent rules run against two requests, because the consent bucket is 10/min **per envelope** |
| 4 | `rate limit` phase | the flood spent `127.0.0.1`'s budget, so the client-key exchange that followed was answered 429 and the phase blamed the exchange | the flood dials from `127.0.0.44`, and the token exchange is performed **once** for the run — five exchanges a minute per address is the documented cap, and a client exchanges once |

Two consequences of the fixes are worth naming, because they are the reason the
checks are now worth running:

- **The consent rules must be split across envelopes.** The consent bucket is
  keyed on the envelope, deliberately, so that a party cannot escape it by
  changing address. A set of fifteen cases against one request is therefore
  throttled at ten, and the tail never runs. Asking "did the rule refuse?" after
  a 429 is not a pass, so the check now says so — and the set is grouped so that
  every rule is reached.
- **The status a request is watched for has to allow the terminal state.**
  Signing and delivery happen in one batch run, so a request can be past
  `signed` on the first poll. `negWaitStatus` now accepts the statuses that
  prove the same fact, instead of losing a race against the worker.
### 4.2 The endpoint audit (items 37 to 39)

The party-facing endpoints were audited by probing the running service and
reading the code that answers. The probes and the rules they verified are in
[security-endpoint-audit.md](security-endpoint-audit.md).

| # | Item | What was wrong | What the fix asserts |
|---|---|---|---|
| 37 | **The catch-all logged a raw request path.** A verb the mux does not route on a signing path — `DELETE`, `PUT`, `PATCH`, `HEAD`, `OPTIONS` on `/api/v1/sign/{token}/consent` — falls to `handleUnknown`, which logged `r.URL.Path` in the clear. One probe wrote a **live 48-character signing token into the log four times**, and the log is read by the shipper, by `journalctl`, by the 12-week logrotate history and by the support bundle: log read access was signing access, for the whole life of the link. | `handleUnknown` logs `redactPath(r.URL.Path)`, the same function the access log uses, so the record keeps its audit value (`/api/v1/sign/[token]/consent`) and loses the credential. `TestUnroutedSigningVerbDoesNotLogTheToken` sends all five verbs with a known token and fails if the token appears anywhere in the log, and fails if the redacted refusal is **absent** — a fix that silences the record is as bad as the leak. `TestRedactPathShapes` pins every credential-bearing path family, and that an envelope id is **not** redacted, because the log is how an operator finds a request. |
| 38 | Nine log points named the signing token's hash `token`. The values were hashes, so nothing leaked; the **name** is the defect. `token=<64 hex>` reads like a credential to whoever indexes the log, and a field named `token` invites the next author to put the value in it. | Every one is `token_sha256`. `TestRedactedNeverLeaksSecrets` fails if any sign handler logs a plaintext token; `TestAccessLogNeverCarriesASecret` extends the rule to the session cookie and the bearer token across the whole signing family, and requires the cookie **name** to survive so the audit trail keeps the claim. |
| 39 | The audit's first draft reported "the body cap is 3 KiB, as `docs/api.md` documents". Both halves were wrong: there is no `docs/api.md` in this tree, and the cap is **204 800 bytes** (the image has its own 1 MiB limit). What the probes actually showed is the **ordering**: a party endpoint answers `401 claim_required` without reading the body at all, and only once a session exists is size refused — with `413`, not the `400` the first probe reported. | The audit's limits table carries the real numbers, and the ordering is written down as a rule. `scripts/verify-release.sh` asserts both halves: 2 MiB before a session → `401`, 2 MiB with a session → `413`. |
| 40 | Two things the endpoint audit found in the code, not in the traffic. `cmd/signsrv/server.go` carried `setCSRFCookie`: a helper named for CSRF, with a comment saying step 03 owns it — but nothing called it, and the service has no CSRF token (the signer cookie is `SameSite=Strict`, so a cross-site form never carries it). A reader looking for the CSRF defence would have found a function that does nothing. And `handleAdminEvents` carried two doc comments at once, one of which claimed the envelope parameter was required when the handler filters optionally and answers an empty log for an id that matches nothing. | The dead helper is gone (its `SameSite`/`HttpOnly`/`Secure` rules already live in `signauth.NewSessionCookie` and `signerCookie`, which every real cookie in the service goes through). The stale half of the duplicate comment is gone, and `scripts/verify-release.sh` now asserts the surviving half: an unknown envelope answers an empty log, `limit=-5` answers 400. |

### 4.3 The production regression script (items 42 to 43)

`scripts/prod-sign-run.sh` is the whole path in one command: build, stop, config,
start, key, document, dispatch, prompt, watch, verify, report, audit chain, log-leak
scan. It is idempotent — every setting it writes is read back from `tmp/prod.conf`
first, so re-running preserves the CA passphrase that the keystore on disk is
encrypted with, and prints `preserved the existing secrets` rather than inventing one.
Two named sub-commands do no harm: `report <id>` re-verifies a finished run with no
side effect, `cancel <id>` closes a link left open by a walk-away test.

| # | Item | What was wrong | What the fix asserts |
| 42 | Writing the one-command production run surfaced two things the docs never said. **(1)** `audit-verify` on a healthy database reports `INVALID — events up to id 117 exist, the log ends at 0`: the day file is written only by `audit-write` (admin POST or CLI), never by the worker, so verify-without-write always looks like tampering. The pair is `audit-write` then `audit-verify`; the script now runs both, and PASS is "chain valid AND the events this run wrote are in the file". **(2)** Each `pdf-go` *process* exchanges the client key for its own bearer token, and `POST /api/v1/auth/token` sits under the login guard. So a shell loop that calls `pdf-go` per poll is a per-iteration key exchange that trips rate limiting and reads as a server fault (429). The correct shape is one long-lived `envelope get --watch`, or a `curl` loop on the raw endpoint, and the CLI calls in a run are counted, not assumed free. |
| 43 | A restart script that stops "the old server" by `pkill -f 'signsrv serve'` does not stop it. The real command line is `signsrv -config tmp/prod.conf serve`, so a pattern demanding the two words adjacent matches nothing; the old process keeps the port, the new one fails to bind and logs `ERROR serve "listen tcp 127.0.0.1:8090: bind: address already in use"`, and the health poll then reads **200 — from the server the script did not start**. Every later line prints green: the reported pid belongs to a dead child, `tail` reads the log file the dead child never wrote to, and the exit trap kills nothing. Two fixes, both in `scripts/prod-sign-run.sh`: the pattern is `[s]ignsrv( .*)? serve( .*)?` (anchored on argv[0] basename, tolerant of flags and trailing args, bracket so the script cannot match its own command line), and after the stop the script asks the port directly — `curl /healthz` — and if anything still answers it names the holder from `ss -ltnp` and exits 1 rather than reporting a healthy start it did not perform. |

The audit found no defect in the three rules that matter most on this surface,
and pins them as read-at-source facts: the **401 before the body is read** (a
page holding a link learns nothing until it claims, and the claim is what is
rate limited and logged); the **image type sniffed from the magic bytes** with
the data-URL label ignored, so a label cannot name a file whose name lies about
its bytes; and **no `innerHTML` anywhere** in either SPA — every server string
goes out through `textContent`, and the HTML email runs through `html/template`,
so an attacker-influenced title cannot become markup in the party's page or mail.

### 4.4 Missing checks in the unit tree

| Step | Missing check | Why it matters |
|---|---|---|
| 02 | no automated scan for string-built SQL | the box is "no string-built SQL"; today it is true by inspection, not by a check |
| 02 | no column-level audit that no plaintext secret is stored | refresh and consent records are proven to hold digests; the full set is unproven |
| 03 | no test that the **signing address** is stored hashed, in the store | `TestTokenHashLookup` proves link and refresh hashing; the signing address is the third secret in the table and has no test |
| 03 | no test for `admin passwd` on a live store | `TestPasswordChangeEndsTokens` covers the epoch in `signauth`; the operator command is not covered |
| 04, 05 | `internal/pdf`, `internal/report`, `internal/schema`, `internal/logos` have **zero package tests** | they are covered through the CLI and the fill/signing tests; a direct test for `pdf.Parse`, `report.Render`, `schema` validation is absent |
| 07 | no test that consent **cannot** be replayed from a second browser profile | session cookie scoping is tested; a cross-profile replay is not |
| 07 | no unit test that **send** is what mints the live link tokens | the create response carries tokens that were never delivered; every test that signs a link has to read the send's. The acceptance run depends on this and no package test states it |
| 07 | no unit test that the consent **image's label is not trusted** | the bytes are sniffed: a PNG body under a `jpeg:` label is accepted, a GIF under the same label is refused. The acceptance run asserts the refusal; the accept side is unproven |
| 08 | no browser-level CSP assertion | tests read JS source; nobody has opened devtools |
| 10 | no test for a **key rotation** mid-batch | the key ring is read once at start |
| 11 | log rotation not verified | `deploy/signsrv.service` ships a logrotate file; nothing runs it |
| 11 | TLS not verified on a real deployment | the reference Caddyfile is committed; the acceptance run is loopback plain HTTP in dev mode, which `checkconfig` permits and `checkconfig`'s own test proves a non-loopback listener is refused |
| 12 | no negative check for **concurrency** (two parties consenting at the same moment) | the last-consent enqueue is tested for one consent, not for two racing consents |
| 12 | no negative check for **delivery of a document whose gate-2 sha was recomputed after the queue** | gate 2 is tested on a tampered input; the reissue-then-batch path is tested, the race is not |

### 4.5 Signoff boxes still unticked

```
docs/steps/02-database.md   4 boxes
docs/steps/03-auth.md       5 boxes
docs/steps/07-consent.md    5 boxes
docs/steps/08-spa.md        4 boxes
docs/steps/12-e2e.md        4 boxes
```
Steps 01, 04, 05, 06, 09, 10, 11 are ticked. For the unticked ones, the
"proven by named tests" lines above tell you which boxes can be ticked from a
test run today, and the TODO ledger tells you which boxes must be ticked only
after a new check is written.

## 5. The full pre-release checklist, in order

```sh
# 1. clean tree
go vet ./...
go vet -tags e2e ./e2e
gofmt -l cmd internal web

# 2. every package
go test -count=1 ./cmd/pdf-go ./cmd/signsrv \
    ./internal/pdf ./internal/report ./internal/schema \
    ./internal/signauth ./internal/signfill ./internal/signflow \
    ./internal/signmail ./internal/signpdf ./internal/signstore \
    ./web/spa ./web/admin

# 3. race detector on the code that runs in the server
go test -count=1 -race ./cmd/signsrv ./internal/signflow

# 4. the acceptance run, all phases
e2e/run.sh

# 5. config and audit on a real deployment
signsrv -config /etc/signsrv/signsrv.env checkconfig
signsrv -config /etc/signsrv/signsrv.env audit-verify
signsrv -config /etc/signsrv/signsrv.env migrate   # no-op on a current schema
```

Step 5 is the only part that needs a machine that is not this checkout. Steps 1
to 4 need only `go`, plus `node` and Chrome for the browser phase.

## 6. Reading the evidence

| Where | What |
|---|---|
| `$E2E_WORK/reports/` | one file per phase, named for the phase, with the command and its output |
| `$E2E_WORK/outbox/` | one `.eml` per invitation, readable in any mail client |
| `$E2E_WORK/audit/` | the audit files, verified by `audit-verify` |
| `$E2E_WORK/browser/` | screenshots of the signing page at each step |
| `$E2E_WORK/browser/console.log` | console output, must be empty |
| `./signing-artefacts/` | the signed PDFs, the keys, the TSA root, kept on a green run |
| `$E2E_WORK/log/signsrv.jsonl` | the access log; `grep` for a token must find nothing |

The signed PDFs are openable in any viewer. `pdf-go verify` re-checks them:

```sh
pdf-go verify signing-artefacts/signed.pdf fill.json
signsrv -config CFG checkpdf signing-artefacts/signed.pdf
```
