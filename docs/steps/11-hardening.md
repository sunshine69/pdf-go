# 11 — Hardening, deployment, operations

Depends: 01..10.

## Deliverables

- `internal/signauth/middleware.go` (headers, limits), `cmd/signsrv/server.go`
- `deploy/signsrv.service`, `deploy/Caddyfile`, `deploy/Dockerfile`
- `SECURITY.md`, `runbook.md`, `signsrv checkconfig`

## Design

**Transport.** TLS termination is external (Caddy/nginx) — documented as the
default, `SIGNSRV_LISTEN=127.0.0.1:8080`, `SIGNSRV_TRUST_PROXY=1` required when
behind a proxy, otherwise `X-Forwarded-For` is ignored (rate limits bind to the
socket peer). `deploy/Caddyfile` is the reference config with `automatic_https`
and `header` directives, HSTS `max-age=31536000; includeSubDomains`.

**Headers** (set by the server for every response, CSP per site as in 08/09):
`Content-Security-Policy`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (except `/s/*` which
uses `frame-ancestors 'self'` in CSP because the SPA embeds the PDF iframe),
`Permissions-Policy: geolocation=(), camera=(), microphone=()`,
`Cache-Control: no-store` on all API responses.

**Body limits.** `http.MaxBytesReader`: 25 MB multipart, 64 KB JSON. Upload
accept only `.pdf` magic bytes; image accept PNG/JPEG magic bytes only.

**Request guards.** Per-IP sliding-window limits (03) with a global cap of
500 in-flight requests; slow-body timeout 30s; per-request context deadline
90s (signing includes TSA calls); `Server.BaseContext` cancels on shutdown.

**Logging.** slog JSON, one line per request:
`ts level method path status dur_ms request_id ip user envelope_id actor`.
Rules enforced by a log-redaction test:
- the token (`/s/<token>`, `?token=`) is replaced by `[token:sha1234abcd]`
  (12 chars of the hash),
- Authorization values are replaced by `[bearer sha1234]`,
- passwords, private keys, keystore passphrase never appear (the config loader
  exposes secrets only via accessor functions, never as fields that slog can
  walk),
- the party's typed signature text is logged at signing time (it is evidence)
  and marked `"field":"consent_text"`.

**Audit integrity.** `events` is append-only: no UPDATE/DELETE on `events`
anywhere in the codebase (asserted by a test that scans `internal/` for
`UPDATE events`/`DELETE FROM events`). Nightly job writes
`var/audit/<date>.jsonl` (all events) with a running SHA-256 chain
(`prev_hash` per row) so tampering is detectable; `signsrv audit-verify`
validates the chain.

**Backups.** `runbook.md`: SQLite via `sqlite3 .backup` (WAL-safe) every hour,
retention 30 days; `var/storage` is append-only, backed up with `rsync --ignore-existing`;
restore procedure = copy files + DB, run `signsrv migrate`, `signsrv audit-verify`,
`signsrv sign-selftest`. Keystore passphrase is documented as the one secret
that cannot be recovered.

**Config check.** `signsrv checkconfig` prints the effective config with
secrets masked and exits non-zero listing every problem: `PUBLIC_URL` must be
`https` unless `DEV=1`; `LINK_TTL` <= 720h; keystore present and readable,
mode 0600; SMTP set when not DEV. It warns, and runs, on a listener outside
loopback (plain HTTP, so TLS has to be terminated in front of it) and when
running as root.

**Secrets table** (what an operator must protect, in order of blast radius):
keystore passphrase + `var/keystore/`, `var/jwt.ed25519.key`, SMTP password,
the DB file (contains token hashes and consent text), the admin password.
Documented rotation: admin password (immediate, revokes own sessions), machine
client key (create new, revoke old), JWT key (requires restart, all API
sessions drop), CA (new CA, old signatures keep verifying via embedded certs).

## Acceptance

```
signsrv checkconfig -config config.example.env   # SIGNSRV_DEV=1 -> exit 0
signsrv checkconfig                              # PUBLIC_URL http + DEV=0 -> exit 1 with reason
go test ./internal/signauth -run Log             # redaction test
go test ./cmd/signsrv -run Header                # every route emits CSP/nosniff/no-store
signsrv audit-verify                             # chain validates on a test DB
grep -rn "UPDATE events\|DELETE FROM events" internal cmd   # must be empty
curl -si localhost:8080/s/x | grep -i 'content-security-policy\|referrer-policy'
```

Manual: `ab -n 200 -c 20 /api/v1/auth/login` produces only 200/401/429, no 5xx.
Kill -TERM mid-request: in-flight signing requests finish, then exit.

## Signoff

- [x] Tokens and bearer secrets are redacted in logs (test proves it) —
  `cmd/signsrv/redaction_test.go`: a log-capture handler is installed, a real
  claim/consent/sign round trip runs against it, and every captured line is
  checked for the link token, the session cookie value and the bearer token.
  The access log records `/api/v1/sign/[token]/claim`, `cookies=signsrv_s`,
  `auth=Bearer [credential]`. The config report is checked the same way.
- [x] events table is append-only; audit chain verifies —
  `grep -rn "UPDATE events\|DELETE FROM events" internal cmd` is empty (the
  scan is a test: `internal/signstore/store_test.go`), and
  `signsrv audit-verify` walks the date files and checks the hash chain.
- [x] TLS/HSTS reference config committed; plain-HTTP only on loopback **by
  default** — `deploy/Caddyfile` (automatic_https, HSTS max-age=31536000
  includeSubDomains, nosniff, frame-deny, no-store on /api),
  `deploy/signsrv.service`, `deploy/Dockerfile`. A listener outside loopback is
  a **warning**, not a refusal: the service speaks plain HTTP, so TLS, a proxy,
  or network policy must terminate encryption in front of it, but where the
  listener sits is the operator's infrastructure decision and the binary does
  not overrule it. `checkconfig` warns the same way when `tsa_url` is not HTTPS.
- [x] Body size limits and magic-byte checks on every upload path —
  `cmd/signsrv/upload_test.go`: 25 MB multipart (413, no rows created),
  64 KB JSON (400), `.pdf` magic bytes on the template, PNG/JPEG/GIF/TIFF
  magic bytes on logo artwork, the 512 KB and 4096-pixel ceilings.
- [x] `checkconfig` fails loudly on every insecure combination —
  `cmd/signsrv/checkconfig_test.go`: public_url not https, loose JWT key mode,
  missing keystore, missing secrets, and digests-only in the report are
  refusals; a non-loopback listener and a plain-HTTP TSA are warnings that the
  service still starts.
- Reviewer: ____________  Date: ________
