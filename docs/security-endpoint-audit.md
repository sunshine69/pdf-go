# Security audit of the endpoints

The service under audit is `signsrv` 0.1.0. The findings are ledger items 37 to
39 in [build-and-test.md](build-and-test.md).

Audited by probing the running service and reading the code that answers. Every
row is a request that was sent and the answer the service gave, or a rule read
at its source and re-checked by a test. The probes live in
`/tmp/steps/probe-sign-endpoints.sh` and `probe-sign-endpoints2.sh`; they ran
against the throwaway development instance, never against a live agreement.

## The endpoint inventory

| Surface | Routes | Guard |
|---|---|---|
| Public | `GET /healthz`, `GET /version`, `POST /api/v1/auth/login`, `POST /api/v1/auth/token`, `POST /api/v1/auth/refresh` | login bucket (3/60s), account lockout |
| Party-facing | `GET /s/{token}`, `POST /api/v1/sign/{token}/claim`, `GET …/envelope`, `GET …/document`, `POST …/consent`, `POST …/decline`, `DELETE …/session` | link token in the path + its own rate bucket, no bearer token |
| Bearer-guarded | 29 routes: documents, envelopes, events, bundles, revocations, support scope, admin CRUD | `RequireAPI` + scope + per-endpoint bucket |

The party-facing family is the attack surface that faces the internet: its
credential arrives from a link in an email, its input is attacker-controlled,
and the page that calls it is untrusted. Every rule below is enforced
server-side.

## Findings, and what was done

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | **High** | An unrouted verb on a signing path (`DELETE /api/v1/sign/<token>/consent`, `PUT`, `PATCH`, `HEAD`, `OPTIONS`) fell to the catch-all handler, which logged `r.URL.Path` **in the clear**. One probe wrote a live 48-character signing token into the log four times. The log is read by the shipper, by `journalctl`, and by the support bundle, so log read access was signing access — for the whole 72-hour life of the link. | **Fixed.** The handler now logs `redactPath(r.URL.Path)`, the same function the access log uses, so the record keeps its audit value (`/api/v1/sign/[token]/consent`) and loses the credential. Regression test: `TestUnroutedSigningVerbDoesNotLogTheToken` — it sends all five verbs and fails if the token appears anywhere in the log, and fails if the redacted refusal is **missing** (a fix that silences the audit trail is as bad as the leak). |

### The leak is real in a production log, and the exposure is closed

The verb probe was run against the local production-shaped instance, so the
damage is in that log and can be read:

```
$ grep -c "$(jq -r '.links[0].token' run/links.json)" tmp/real/signsrv.jsonl
4
742: {"msg":"route not found","path":"/api/v1/sign/3j…
```

The three earlier envelopes in `envelope-*.links.json` score 0: they were never
probed. The affected party is `stevek@kaykraft.com` on
`ae916bfe3d6d001462ce6c8108deb3ac`, and the exposure is closed, by three
independent facts read from the store, not assumed:

| Check | Result |
|---|---|
| Is the token stored in the clear? | No — at the time of this audit. `parties` had `token_hash` only, and a grep of every column found no plaintext token. **Changed since, by design:** schema v8 added `parties.token_raw`. See `docs/steps/02-database.md` for why reprintability beat irreversibility here, and what it costs (a dump carries live links). The leak scenario above still behaves as recorded — a used link is still refused. |
| Can the leaked link still be used? | No. `POST …/claim` → **410 `request_closed`**, `consent` → 410, `decline` → 410. The party is `consented`, so `partyOpen` refuses the claim. |
| Does it outlive the request? | No. The link dies with the request; `token_expires_at` was 2026-11-10 and the envelope is `delivered`. |

So the record is: a credential-bearing URL was written to a log that outlives
the request it belongs to, and the request happened to close before anyone read
it. That is the definition of a fixed-by-luck finding, and the fix is on the
path of every future request.

| 2 | Medium | Nine log points named the signing token as a field called `token`. The values were hashes, so nothing leaked; the **name** is the problem. `token_sha256=` is machine-recognisable as a credential, `token=<64 hex>` is not, and the field survives into every shipper's index. | **Fixed** (this release). Every one is `token_sha256`. `TestRedactedNeverLeaksSecrets` fails if any sign handler logs a plaintext token. |
| 3 | Low | Nothing proved that the **access** log, the cookie log and the authorization log keep credentials out. The rule was stated, not checked. | **Closed by test.** `TestAccessLogNeverCarriesASecret` sends the signing family with a session cookie and a bearer token attached and asserts none of the three secrets appears in any record, while the cookie **name** does. `TestLogRecordsAreValidJSON` asserts every record is parseable JSON — a log line built by concatenation breaks every shipper. |

The fix for #1 is one line, and its value is that it is one line in the place
where the leak was, not a filter downstream of every leak.

## Rules verified on the party-facing endpoints

**Ordering, which is the part a page cannot fake.**

| Step | Answer | Source |
|---|---|---|
| `envelope` on an unknown token | 404 `not_found` "this link is not valid" — no party, no status | probe 1, `ResolveSigner` |
| `consent` with no session, empty body | **401**, before the body is read | probe 2 |
| `consent` with no session, well-formed body | **401** — the token is not the session | probe 3 |
| `decline` with no session | **401** | probe 4 |
| `claim` on a party that has consented | **403** `party_status` | `partyOpen` |
| `claim` on a ready (never sent) request | **403** `state_conflict` | `Claim` |
| `claim` after the envelope deadline | **403** `envelope_expired` | `Claim` |
| `claim` with 100 001 runes of name | **400** `bad_request` | probe 9, `maxClaimName = 64` |
| `consent` on a signed request, valid session | **403** `state_conflict` | probe 17 |
| `document` after logout | **401** — the session is gone, not the link | probe 14 |

The 401-before-body order is the load-bearing one: a page that holds a link
learns nothing about a request until it has claimed it, and the claim is what
is rate limited and logged.

**The image, which is the one blob a party controls.**

| Rule | Enforcement |
|---|---|
| Size | `maxConsentImageBytes = 1 << 20`; a 2 MiB body is refused — probe 15 returned 400 in 0.08s |
| Decode time | 15s wall clock via a watchdog goroutine, so a decompression bomb cannot pin a worker |
| Type | **sniffed from the magic bytes; the data-URL label is ignored.** A GIF body under a `data:image/jpeg` label is stored as `image/gif`. Verified by `TestConsentImageLabelIsIgnored`. The label cannot name a file whose name lies about its bytes, because it is not consulted. |
| Accepted types | `image/png`, `image/jpeg` only |

**The consent itself.** `document_sha` is required and compared with the stored
revision, so a consent cannot be recorded against a document the party was not
shown. `consent: true` is required. The claim is capped at 64 runes and is
**never compared with the invited address** — the claim is recorded, not checked,
which is what makes the ledger honest about what the signer said.

**Limits.** Body cap 204 800 bytes on every signing POST; rate buckets
`claim 20/5min`, `view 120/60s`, `document 60/60s`, `consent 10/60s`,
`decline 10/60s`. All five buckets are hit-tested by
`TestSignRateLimitPerEndpoint`.

**Injection, where attacker text lands in markup.** The invited email address,
the envelope title, the reason and the signer's claim are all
attacker-influenced.

- Both SPAs write every server string with `textContent`. There is **no
  `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `document.write` or `eval`**
  in `web/spa/app.js` or `web/admin/app.js` — verified by grep, all 20
  candidate call sites.
- The HTML email runs through `html/template`, so a title containing `<script>`
  is escaped in the message the party reads.
- Title, subject and the custom message are refused at **create** for `\r`,
  `\n`, NUL and other control characters, which is what keeps a title out of a
  mail header.
- Recipients are RFC 5322 addresses, ASCII-only; a non-ASCII local part is
  refused at the API.

**Session and headers.**

| Property | Value |
|---|---|
| Signer cookie | `HttpOnly`, `SameSite=Strict`, `Path=/api/v1/sign/`, `Secure` over TLS |
| Consequence | the session cookie cannot be attached to an admin API call, and cannot be sent by a top-level navigation from another site |
| `/s/<token>` | `Cache-Control: no-store` (verified live), CSP signer (`frame-ancestors 'self'`, `base-uri 'self'`, `form-action 'self'`, `script-src 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Log redaction | signing token in `/s/…` and `/api/v1/sign/…` paths, `Authorization`/`Cookie` named by shape never value, bearer secrets shown as prefix + `…` |

## Residual risks, accepted for this release

1. **A claimed party can read the document bytes.** That is the product. The
   controls are the token's entropy, its 72-hour life, single-use on
   `consumed_at`, `no-store`, and per-endpoint rate limits.
2. **`frame-ancestors 'self'` on the signing app** — a same-origin page can
   frame it. Deliberate: the app embeds the document it asks the party to
   review. A same-origin frame is XSS, not clickjacking, and XSS is closed by
   `script-src 'self'` plus `textContent`.
3. **The body cap is 204 800, and it is applied AFTER the session check.** A
   party endpoint first answers `401 claim_required` without reading the body;
   only once a session exists is the size refused, with `413`. Both are correct
   (the ordering is what keeps a body from being read for a stranger), but the
   doc understates the surface and the ordering was not written down. Ledger
   item 39. There is no `docs/api.md` in this tree; the numbers live only in
   this audit's limits table.
4. **`429` responses omit `RequestId`**, as ledger item 21 has always recorded;
   the rate limiter writes the body itself.
5. **Dev mode seeds an admin account.** `checkconfig` warns loudly; a
   production config must set `dev = false`.

## Reproducing the probes

The two probe scripts are in the repo:

```sh
scripts/security-probe-sign-endpoints.sh   # items 1 to 10: no session
scripts/security-probe-sign-endpoints2.sh  # items 11 to 17: a claimed session
```

Each takes two arguments — the base URL and the signing link — and prints one
line per request with the answer the service gave. They run against the
throwaway development instance. Probe 17 consumes the link (it signs), so
item 17's recorded result comes from the scripted run in
`docs/steps/09-e2e.md`, and probe 8 is the shape-only refusal that does not
consume it. Run them against a request nobody cares about.

## The release gate

Everything below was run against the tree being released, not asserted from
reading it.

- `go test` — green over `cmd/pdf-go cmd/signsrv cmd/mock-tsa internal/{pdf,report,schema,signauth,signfill,signflow,signmail,signpdf,signstore}`.
  (`internal/logos` holds no Go files, and `web` has no tests: its templates are
  exercised through `cmd/signsrv`.)
- `go vet`, with and without `-tags e2e` — clean. `gofmt -l cmd internal e2e web` — silent.
- `e2e/run.sh`, WITH the browser phase — `failures: 0`, 34.8s.
- `scripts/verify-release.sh` — ALL GREEN: 47 checks over a throwaway instance
  (client key exchange, the transport guard, create/send, the refusal ORDER
  before a session, claim, the body cap WITH a session, consent, the signed
  digest, the admin reads, and the log scan). It SIGNS a document, so it needs
  its own instance; that instance is created by the operator and thrown away.

The script, not the table above, is the gate. It re-runs the probe results of
this document against a live service, so a regression in an endpoint fails a
release rather than a reading.
