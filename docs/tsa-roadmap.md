# TSA Implementation Roadmap

Status: **the service is using `https://freetsa.org/tsr` and that stays as it is.**
This is a plan, not a change. Nothing here is implemented. Every item below is
a TODO.

## Why a TSA at all

A PDF signature without a timestamp proves *what* was signed and *by whom*, not
*when*. A timestamp token from a timestamp authority attests the signing time
independently, so a signature stays verifiable after the party certificate
expires, and revocation can be judged at the signing moment rather than today.

The policy in `docs/steps/04-pdfsign.md` is checked off: **TSA is mandatory in
v1; failures are errors, not fallbacks.** Enforced in code:

| place | behaviour |
|---|---|
| `internal/signpdf/sign.go:96` | `TSAURL == ""` → `TSA URL is required: v1 has no unsigned-signature fallback` |
| `sign.go:120` | `Certify` refuses without a URL: *refusing a signature without a signing time* |
| `sign.go:171` | party signing needs the URL as well |
| `cmd/signsrv/config.go:145` | `tsa_url` defaults to `https://freetsa.org/tsr` |
| `cmd/signsrv/worker.go:293` | the worker reads `tsa_url` from settings per batch, so the admin knob is live |
| `cmd/signsrv/config.go:274` | `tsa_url` on `http://` → a `checkconfig` warning, not a refusal |

Measured, not assumed: `-tsa -` exits 1 with `TSA URL is required`; an
unreachable `tsa_url` exits 1 with `get timestamp: dial tcp …`. There is no
silent `B-B` fallback. So the dependency is a policy, and changing the policy is
the only way to remove it (option D).

## What we already have

- `github.com/digitorus/timestamp` is vendored. Its `Timestamp` type builds a
  response, parses a request, and creates a signed response with
  `CreateResponseWithOpts`. That is the RFC 3161 core, already in the tree.
- `e2e/e2e.go:285-362` is a **working RFC 3161 responder**: keypair, TSA
  certificate, `POST /tsr`, `ParseRequest`, serial, nonce echoed, policy OID
  `1.2.840.113549.1.9.16.1.1`, `AddTSACertificate: true`. 60 lines. It is the
  acceptance run's TSA, so offline signing already works end to end.
- Verification is offline: `internal/signpdf/verify.go` uses
  `ExternalChecks(false)` and `TrustSelfSigned(true)`. The token is checked
  against the certificate carried inside it. No responder is contacted, so a
  self-issued token verifies with the network down.
- `internal/signpdf/keystore.go` has `writeOwner` (0600, `enforceMode` at load),
  and `ca.go` has `seal`/`open` (argon2id + AES-GCM), `deriveKey`,
  `randSerial`. The keystore is the place the TSA key belongs.

## The trade-off, stated plainly

A public TSA attests time from outside your trust domain. A self-issued token
attests *"the service's clock said this, signed by our key"* — trusted by anyone
who trusts your CA, which is exactly the scope of `TrustSelfSigned(true)` that
verification already uses. Verifiers that demand a public TSA (Adobe's default
trust list, some `pdfsig` configurations) will show a self-issued signing time
as untrusted. That is a limitation to record, not to hide.

`config.go`'s `http://` warning is harmless on loopback: the token's integrity
is the PKCS#7 signature, not the transport. TLS on the TSA call is a transport
convenience, not a security property of the token.

## Options

| | change | keeps independent attestation | external verifiers |
|---|---|---|---|
**A. Keep freetsa** | none | yes | yes |
**B. External TSA you run** | `tsa_url` set to your own responder | yes | yes |
**C. Internal TSA inside `signsrv`** | ~200 lines | no (in-domain) | untrusted by default |
**D. Drop the TSA** | policy change, step 04 signoff flipped | no | no |

`A` is what runs today, and stays. `B` is zero code: the admin sets `tsa_url`.
`C` is the real roadmap. `D` is a policy decision, not engineering.

## Option C: internal TSA

Design decisions, fixed before writing code:

1. **TSA key in the keystore**, next to `ca.key`, same sealing (argon2id +
   AES-GCM), mode 0600, `enforceMode` at load. Created at first start when
   `tsa_url` points at the service itself.
2. **Certificate**: `ExtKeyUsage: ExtKeyUsageTimeStamping`, `IsCA: true`,
   `KeyUsage: DigitalSignature | CertSign`. `e2e.go`'s comment states why a
   plain leaf is not enough: the PKCS#7 verifier walks the chain, and the token's
   parent must be a CA certificate.
3. **Endpoint**: `POST /tsa/tsr` on the loopback listener, `Content-Type:
   application/timestamp-reply`. Request body limit 1 MiB, as `e2e.go` does.
4. **Excluded from the rate limiter** and from `X-Request-Id` request logging:
   the worker calls it once per batch, and a self-call must not be throttled.
5. **Rotation**: tokens minted under an old TSA certificate must keep verifying
   for documents signed years ago. Every TSA certificate is kept in the keystore
   as `tsa-<keyid>.crt`, and verification accepts a token from any of them. Only
   the newest key signs. **This is the part that breaks if it is skipped.**
6. **Clock**: the token's time comes from `Service.clock`, the same clock the
   audit chain uses, so the audit event time and the token time agree within the
   declared `Accuracy`.

`signpdf.Config` gains `TSAKey []byte` / `TSAStore *TSAStore`; `Service.TSAURL()`
stays the source of the URL the builder uses, so `Timestamp(o.TSAURL)` is
unchanged — the URL is just `http://127.0.0.1:<port>/tsa/tsr`.

## Tests, in the order they should be written

All are unchecked. Each is a signoff item, tested by a Go test or by a
`scripts/acceptance-<step>.sh` block.

### C1 — RFC 3161 conformance (the responder itself)
- [ ] Nonce echoed, and a request with a nonce the responder does not know is answered `rejected`
- [ ] Hash algorithm honoured: SHA-256 request → SHA-256 `messageImprint`; SHA-1 request refused or honoured as configured
- [ ] Policy OID accepted, and an unknown policy answered `rejected` with a `FailureInfo`
- [ ] `AddTSACertificate` present in the reply, and `signing-certificate-v2` names the issuer and serial
- [ ] Serial is monotonic per certificate, and the serial matches the audit event
- [ ] `Accuracy` declared, and the reply time is inside the declared window against the audit chain event time
- [ ] `Status: granted` for a well-formed request, `rejected` for a truncated body, 1 MiB limit enforced
- [ ] Bad ASN.1 returns `application/timestamp-reply` with `reject`, not HTTP 400 with text (`e2e.go` uses plain text; the real endpoint should be RFC 3161-compliant)

### C2 — Verification with a self-issued token
- [ ] `checkpdf` on a document stamped by the internal TSA, **with the network down** (`GOPROXY=off`, no DNS), exits 0 and `Timestamp: true`
- [ ] `verify` with `ExternalChecks(false)` and `TrustSelfSigned(true)` unchanged, so no code path needs a responder
- [ ] A token signed by a key not in the keystore fails verification
- [ ] A token whose `messageImprint` does not match the signed bytes fails verification

### C3 — Key rotation (the hard one)
- [ ] Sign a document with TSA key A, rotate to key B, verify the A-signed document: `Timestamp: true`
- [ ] Every historical `tsa-<keyid>.crt` is present and readable; a missing one is a `checkconfig` problem, not a silent pass
- [ ] The rotation event is in the audit chain, with both key fingerprints
- [ ] `checkpdf` on an archive of documents signed under three different TSA keys
- [ ] An old TSA certificate that has expired still verifies documents signed while it was valid
- [ ] `runbook.md` has the procedure: generate, append, mark the current, never delete

### C4 — Runtime wiring
- [ ] `tsa_url` set to the service's own URL in the admin settings: the worker follows it on the next batch (`worker.go:293`)
- [ ] `checkconfig` warns `tsa_url is not HTTPS` on loopback, and the warning names the internal-TSA case as expected
- [ ] `http://127.0.0.1:<port>/tsa/tsr` works when `--insecure` is irrelevant (the worker is in-process, not the CLI)
- [ ] Self-call does not deadlock: 1 request per batch against the service's own listener, `Server.WriteTimeout` respected
- [ ] The endpoint is excluded from the rate limiter (no `Too many attempts` from the worker)
- [ ] The endpoint produces no `request` log line, and the token in the reply never reaches the log
- [ ] A signing batch that gets no timestamp is a failure, and the mail queue is not written (the current behaviour for a dead freetsa, verified with `tsa_url` unreachable)
- [ ] `sweep` requeues a batch whose TSA call was cut by shutdown (`Server.BaseContext` cancels)

### C5 — External verdicts (recorded, not fixed)
- [ ] `pdfsig` on a self-stamped document: the verdict, recorded in the roadmap as a known limitation
- [ ] Adobe Reader default trust list: the signing time shows as untrusted; the procedure to trust the CA is written
- [ ] The report's `Timestamp` field is documented as *validated against the keystore*, not against a public TSA, when `tsa_url` is internal
- [ ] `SECURITY.md` says who can issue a token: the service's own key

### C6 — Migration
- [ ] Documents signed with freetsa verify after `tsa_url` moves to the internal TSA (tokens already embedded are untouched — no re-signing)
- [ ] `dbstatus` and `audit-verify` stay clean across the switch
- [ ] `e2e/run.sh` uses the internal TSA instead of `mockTSA`, and `tsaStamps`/`tsaHits` counters still prove one call per batch
- [ ] The acceptance run has a phase that signs with the internal TSA and verifies offline
- [ ] `README-signing.md` documents `tsa_url=<own URL>` and the `http://` warning

## Option C, the implementation order

1. `internal/signpdf/tsa.go`: key generation, sealing with `seal`, `enforceMode`,
   certificate with `ExtKeyUsageTimeStamping` + `IsCA`, the store of historical
   certificates. Reuse `deriveKey`, `randSerial`, `writeOwner`.
2. `internal/signpdf/tsa_responder.go`: `func (s *Service) Respond(req []byte,
   now time.Time) ([]byte, error)`, using `timestamp.ParseRequest` and
   `CreateResponseWithOpts`, in the shape `e2e.go` demonstrates.
3. `cmd/signsrv/tsa.go`: `POST /tsa/tsr` handler, request limit, content type,
   rate-limit exclusion.
4. `signpdf.Config` accepts the store; `NewService` creates it when the URL is
   the service's own listener, refuses when `tsa_url` is external and the store
   is missing.
5. Rotation: admin settings action, audit event, `runbook.md` procedure.
6. Tests C1→C6, in that order. C3 lands before C4.

## Option D, if the TSA is dropped

Not recommended. It is a policy change, and it needs the signoff of step 04
flipped, `TSAURL` allowed empty, the report's `Timestamp` reported as `false`
with no guarantee, `SECURITY.md` updated to say the signing time is the service's
word, and `docs/steps/04-pdfsign.md:134` rewritten. Mark as TODO:

- [ ] Decision recorded: which signatures are accepted without a timestamp
- [ ] The `B-B` fallback path tested: no timestamp, signature still verifies
- [ ] The report states `Timestamp: false`, and the admin UI shows it
- [ ] `pdf-go`/`checkpdf` refuse to call a timestamp-less signature "valid"
- [ ] The party-facing page says the signing time is unattested
