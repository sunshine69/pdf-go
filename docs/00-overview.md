# 00 — System overview

Status: draft, needs review.
Scope: a small, self-contained PDF signing service in front of the existing
`pdf-go` CLI (module `github.com/sunshine69/pdf-go`).

## 1. What the system does

1. A client (an AI model, an operator, another service) authenticates to the API
   with a JWT and creates an **envelope**: a PDF form template, the values to
   fill, and the list of parties who must sign.
2. The service fills the form using the existing `internal/pdf` + `internal/schema`
   code (the same code the CLI uses), then **certifies** the result with
   `Permission(NoChanges)`: the document is frozen, only signatures can be added.
3. The service sends one email per party. Each email contains a **single-use,
   expiring link** to the signing page.
4. A party opens the link, reads the document, picks signing options (typed
   name, optional drawn image), ticks the consent box and clicks Sign. The
   service stores that consent. **No PDF is modified at this point.**
5. When the last consent is in, a server job signs the frozen document in
   `order`: party 1 over the certified bytes, party 2 over party 1's output,
   and so on, each with its own ephemeral key and its own RFC 3161 timestamp.
6. The service verifies the finished document. If valid, every party gets the
   signed PDF by email, plus a machine-readable receipt. If not valid, nothing
   is sent and the admin is alerted.
7. An admin logs in to a web page to list every envelope, see who has consented,
   download revisions, resend links, cancel.

## 2. Components

One Go binary, three faces: the JSON API, the SPA static files, the background
worker (email + signing batch + sweeps).

```
cmd/signsrv/            main, config, routes, server, static, serve
                        (+ api.go admin.go sign.go worker.go cli.go in 03..12)
internal/signstore/     database/sql store, schema, migrations, sweeps
internal/signauth/      JWT issue/verify, admin login, middleware, token hashes
internal/signpdf/       adapter over github.com/digitorus/pdfsign
internal/signfill/      adapter over internal/pdf + internal/schema (fill/lock)
internal/signmail/      templates + SMTP/provider send
internal/signflow/      envelope state machine, consent capture, signing batch
web/spa/                signer SPA (vanilla JS, no build step)
web/admin/              admin SPA (vanilla JS, no build step)
var/storage/           PDF revisions and images, content-addressed, immutable
var/keystore/           signing CA key material (passphrase protected)
```

`internal/pdf`, `internal/schema`, `internal/report` are reused as libraries.
No subprocess calls to the CLI. The CLI stays as the operator/AI tool.

## 3. Signing model (the important part)

PDF signatures are **incremental updates**: a signature can only be added on top
of the current file, and each one covers the bytes before it. So the service
collects consent first and signs last, in one batch.

```
create:   template -> fill -> certify(NoChanges)      # frozen, reviewable bytes
collect:  party consents, any order, DB only          # no file changes
batch:    certified -> sig(order 1) -> ... -> sig(order n)
finalize: verify -> deliver
```

Rules:

- Certification is the first signature in the document (pdfsign requires this)
  and uses `Permission(NoChanges)`, so form filling by a reader cannot alter
  what the parties reviewed. Adding approval signatures is allowed.
- Batch signing is strictly sequential by `order`, one thread, one job, in a
  loop: `in = certified; for p in parties: out = SignParty(in, p); in = out`.
- Every step writes a new immutable, content-addressed file. The revision chain
  is the audit trail and is never edited in place.
- Each party's private key is generated in memory at batch time and discarded
  after `Write`. The leaf certificate (public) is stored with the revision.
- Timestamp is an RFC 3161 token per signature (PAdES B-T), TSA URL configurable,
  default `https://freetsa.org/tsr`.
- Verification runs **before** delivery and **again at send time**. A failed
  verification means zero emails.

**Timestamp honesty.** Because signing is a batch, the signing time recorded in
the PDF is the batch time for all parties, seconds apart, and later than the
moment each human clicked. The true per-party agreement time lives in
`consents.consent_at` (with IP and user agent), is carried in the signature
`Reason` as text ("electronically agreed 2026-05-14T09:15Z"), and appears in
`receipt.json`. The TSA proves the batch time. Never set a leaf certificate's
`NotBefore` in the past to fake an earlier signing time: verifiers reject the
mismatch between certificate validity, signing time and timestamp token.

## 4. Key and certificate management

Default (Option A), what agents implement:

- Service owns a self-issued signing CA (ECDSA P-256) in `var/keystore`, key
  encrypted with a passphrase from the environment.
- Per signature: ephemeral in-memory key pair, leaf certificate valid 15 minutes
  with the party name and email in the subject, signed by the CA, used,
  discarded. Private keys are never written to disk, never logged, never
  returned by the API.
- Leaf certificate (public part) is stored with the revision for verification.

Trade-off, stated plainly: the server holds the signing capability, so it *can*
sign as any party. Controls: the consent record per signature (typed signature
text, consent timestamp, IP, user agent), append-only audit log, single-use
expiring token bound to an email match, and the fact that the document is
certified before anyone is asked to consent. This is standard server-side
signing.

Option B (party uploads PKCS#12, unlocks client-side) and Option C (CSC/HSM
remote signer via `pdfsign/signers/*`) are documented extension points in
`internal/signpdf`, out of scope for v1.

## 5. Data model

SQLite via `database/sql`. Timestamps are UTC ISO-8601 text.

| Table | Purpose |
|---|---|
| `admins` | admin logins, argon2id password hash |
| `clients` | machine API clients, name + key hash + scopes |
| `revoked_jtis` | logged-out / rotated JWT ids until expiry |
| `envelopes` | title, status, hashes, expiry, cert serial, creator |
| `parties` | email, name, order, status, token hash, expiry, session hash |
| `consents` | per party: signature text, appearance options, consent time, IP, UA |
| `revisions` | every PDF ever produced, hash-chained, who produced it |
| `events` | append-only audit log, actor + kind + payload |
| `settings` | TSA URL, SMTP config, expiry defaults |

Envelope states:

```
draft -> ready -> sent -> collecting -> signed -> completed -> delivered
                  \-> expired  \-> cancelled  \-> failed
```

`signed` = batch signing finished and verified. `completed` = delivery queued.
Party states: `invited -> claimed -> consented`, plus `declined` and `expired`.

Files are content-addressed: `var/storage/<sha256>.pdf`. A revision row stores
`sha256`, the previous revision id, the signature field it added, and the party
that produced it. The consent image (if any) is stored the same way.

## 6. Authentication

Two token types, never interchangeable.

**API JWT** (admins and machine clients). Ed25519-signed, `aud=api`, 15 min
access token + rotating single-use refresh token stored hashed. Claims: `sub`,
`role` (`admin` | `client`), `scopes`, `jti`. `Authorization: Bearer`. Admin
password login issues the same shape.

**Signer link token** (public). Opaque 256-bit random, never a JWT, stored only
as SHA-256, bound to one `(envelope, party)`. On first open the party must
claim with their email address, which issues a session cookie scoped to
`/api/v1/sign/`, `HttpOnly`, `SameSite=Strict`, valid until the link expires.
Forwarding a link gets the third party to a claim screen that fails the email
match. Default link TTL 7 days, configurable per envelope, max 30 days.

Rate limits: login 5/min/IP, claim 10/min/IP, consent 10/min/envelope, link
opens 60/min/IP, create 20/min/IP, send 30/min/IP, other API calls 600/min/IP.
429 with `Retry-After`. Every one is a `rate_limit_*` setting (see
`CONFIG.md`); these are the defaults, and a negative value disables a bucket.

## 7. API surface

Machine + admin, `aud=api`:

```
POST   /api/v1/auth/login | /auth/refresh
POST   /api/v1/envelopes                    create (multipart: template, parties, fill spec)
GET    /api/v1/envelopes?status=&q=         list
GET    /api/v1/envelopes/{id}               detail: parties, consents, revisions
POST   /api/v1/envelopes/{id}/send          email the parties who have not signed;
                                            repeatable, reuses their existing links
POST   /api/v1/envelopes/{id}/remind        deprecated alias of /send (rate limit
                                            lives here; the admin UI no longer shows it)
POST   /api/v1/envelopes/{id}/cancel
POST   /api/v1/envelopes/{id}/sign          manual trigger of the signing batch (admin)
GET    /api/v1/envelopes/{id}/document      current revision
GET    /api/v1/envelopes/{id}/revisions/{rid}
GET    /api/v1/envelopes/{id}/report        receipt.json
GET    /api/v1/envelopes/{id}/audit.zip
GET    /api/v1/admin/stats | /events | /settings
POST   /api/v1/admin/settings | /clients | /clients/{id}/revoke
```

Signer public, `aud=sign`, cookie-bound:

```
GET    /s/{token}                           SPA shell
POST   /api/v1/sign/{token}/claim           {email} -> session cookie
GET    /api/v1/sign/{token}/envelope        title, my name, parties, expiry, my status
GET    /api/v1/sign/{token}/document        the certified document, inline
POST   /api/v1/sign/{token}/consent         {signature_text, consent:true, image?}
POST   /api/v1/sign/{token}/decline         {reason}
```

Every response is JSON; errors are `{"error":{code,message,hint}}`. Status:
400 invalid, 401 no/bad token, 403 authenticated but not allowed, 409 state
conflict, 410 expired, 404 unknown, 429 rate limited.

## 8. Implementation steps

| Step | Doc | Deliverable |
|---|---|---|
| 01 | `01-layout.md` | new binary, deps vendored, config, `/healthz` |
| 02 | `02-database.md` | schema, migrations, store, sweeps |
| 03 | `03-auth.md` | JWT, login, middleware, rate limits |
| 04 | `04-pdfsign.md` | certify/sign/verify adapter, unit tests |
| 05 | `05-envelopes.md` | fill + certify + envelope CRUD API |
| 06 | `06-tokens-email.md` | tokens, links, email templates |
| 07 | `07-consent.md` | public consent endpoints, state machine |
| 08 | `08-spa.md` | signer SPA |
| 09 | `09-admin-ui.md` | admin SPA + admin endpoints |
| 10 | `10-batch-sign.md` | signing batch, verify, deliver, receipt |
| 11 | `11-hardening.md` | limits, audit chain, TLS, deploy |
| 12 | `12-e2e.md` | end-to-end test, CLI integration, runbook |
| 13 | `13-users-one-endpoint.md` | users table, caller-minted tokens, chore endpoints |

Order is linear. Steps 08 and 09 can run in parallel with 10 once 07 is signed.

## 9. Open questions (defaults in **bold**; reviewer decides)

1. Key custody. **Server-generated ephemeral keys (Option A)**. Party-uploaded
   P12 (Option B) later?
2. Certificate trust. **Self-signed CA + `TrustSelfSigned(true)`** in our own
   verification. Third-party CA later?
3. SQL driver. **`modernc.org/sqlite`**, pure Go, keeps the project's no-cgo
   property. `mattn/go-sqlite3` needs cgo.
4. Vendor. **Vendor everything** (`pdfsign`, modernc sqlite — a large tree) to
   keep the existing `vendor/` workflow, or move to plain modules?
5. Email. **SMTP with STARTTLS from env config**; provider API behind the same
   interface later.
6. SPA stack. **Vanilla JS, no build step, no framework**, embedded.
7. Signature appearance. **Typed text in an embedded handwriting TTF**, plus an
   optional drawn/uploaded PNG per party. Both required, or text only in v1?
8. Identity proof. **Email match + typed name + consent timestamp + IP/UA.** Any
   stronger step (SMS code, shared secret, ID upload)?
9. Signature time = batch time, consent time recorded separately in the DB, the
   `Reason` text and the receipt. **Accept?** (Alternative is per-party signing
   at click time, which puts the ordering constraint in front of users.)
10. Retention. **Keep every revision forever, no purge.**
11. Multi-tenancy. **Single CA, single admin realm.**
12. Timeout. Consent window expires with the link. If not everyone consents:
    **envelope `expired`, nothing signed, admin notified, no document is
    produced.** Accept, or auto-sign the subset that consented? (Auto-signing a
    subset is a legal hazard; recommendation is no.)
