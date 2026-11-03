# 04 — pdfsign adapter

Depends: 01, 02, 03.

## Deliverables

- `internal/signpdf/{ca.go, sign.go, appearance.go, verify.go, font.go}`
- `internal/signpdf/testdata/` — a fillable template (reuse `testdata/sample1.pdf`)
  and a handwriting TTF (open licence, e.g. an OFL script font)
- `internal/signpdf/sign_test.go`, `verify_test.go`

## Library facts the adapter is built on

From `github.com/digitorus/pdfsign`:

```
doc, _ := pdfsign.Open(r io.ReaderAt, size int64)          // or OpenFile(path)
doc.Sign(signer crypto.Signer, cert *x509.Certificate, intermediates ...*x509.Certificate)
    .Type(pdfsign.CertificationSignature | ApprovalSignature | DocumentTimestamp)
    .Permission(...)            // certification only: what later signers may change
    .Format(pdfsign.PAdES_B_T)
    .Timestamp(tsaURL)
    .SignerName(name).Reason(r).Location(l).Contact(c)
    .Digest(crypto.SHA256)
    .Appearance(ap, x, y)       // widget size from NewAppearance(w,h)
    .Context(ctx)
doc.Write(out io.Writer) (*Result, error)   // applies staged ops as incremental updates
doc.Verify().TrustSelfSigned(true).Strict()...  // lazy: read .Valid()/.Signatures()/.Err()
pdfsign.NewAppearance(w, h).Standard()  /  .Text(s).Font(f, size).Position(x,y)
doc.AddFont(name, ttfBytes) *Font
```

`CertificationSignature` must be the first signature; `Permission` is only
meaningful on certification.

## Design

**Public API of the package** (small on purpose):

```go
type Service struct { ... }                     // holds CA, TSA URL, font, clock
func NewService(cfg Config) (*Service, error)   // loads/creates the CA, loads the font

func (s *Service) Certify(in []byte, o CertifyOptions) (*Out, error)
func (s *Service) SignParty(in []byte, o PartyOptions) (*Out, error)
func (s *Service) Verify(in []byte) (*Report, error)
```

```go
type Out struct { Data []byte; SHA256 string; Serial string; CertPEM string }
type Report struct { Valid bool; Signers []SignerInfo; Errors []string }
type SignerInfo struct { Name, Email, Reason string; Time time.Time; Valid bool; Serial string }
```

**CA.** `ca.go` loads `var/keystore/ca.key` + `ca.crt`, creating both on first
run: ECDSA P-256 self-signed CA, 10 years, `BasicConstraints: IsCA`,
`KeyUsage: CertSign|CRLSign`, key file 0600, encrypted with the keystore
passphrase (AES-256-GCM, key derived with argon2id from the passphrase, random
nonce stored in the file). Refuse to start if the passphrase is wrong; never
print it. `ca.go` also provides a CRL stub (empty, 24h) so verification has a
revocation source; publishing it is not required in v1 (no CRLDP in leaf certs,
verification runs with `TrustSelfSigned(true)` and `ExternalChecks(false)`).

**Leaf issuance.** `sign.go` issues a leaf per signature:
`Subject: CN=<party name>, O=signsrv, Email=<party email>`, serial = 16 random
bytes, `NotBefore = now-60s`, `NotAfter = now+15min`,
`KeyUsage: DigitalSignature|NonRepudiation`, `ExtKeyUsage: EmailProtection`,
`BasicConstraints: not a CA`, signed by the CA with the party public key. Leaf
validity is short on purpose: the key exists only for the signing call.
Private key: in-memory ECDSA P-256, discarded after `Write` returns.
`SignParty(in, PartyOptions)`: `Type(ApprovalSignature)` over the bytes given,
appearance built from `PartyOptions.Signature`/`Image`, TSA from options.
`Certify(in)`: fills happen **before** this call, then
`Type(CertificationSignature)` with **`Permission(NoChanges)`** — the library
constant that guarantees any modification after certification invalidates the
signature. This freezes exactly the bytes the parties review; adding approval
signatures is the only permitted change. `AllowFormFilling` is deliberately not
used: it would let a reader alter the document the parties consented to.

**Appearance.** `appearance.go` builds `NewAppearance(220, 80)`:
line 1 typed signature text in the embedded handwriting font at 26pt,
line 2 `{{Name}}` at 9pt grey, line 3 `{{Date}}` at 8pt grey, 1pt border.
If the party supplied an image, `Image(...)` is placed on the left, text
shifted right. Widget placement comes from the fill spec
(`signature_field` name) when the template declares a signature field,
otherwise from `SignOptions.Widget{Page,X,Y,W,H}`; default is bottom-right of
page 1 crop box minus 36pt margins. `.Standard()` is not used (we control layout).

**Verify.** `verify.go` wraps `doc.Verify()` with: `TrustSelfSigned(true)`,
`ExternalChecks(false)`, `MinRSAKeySize(2048)`, `HTTPTimeout(10s)`, context.
Returns one `SignerInfo` per signature. `Verify` is a pure function: it never
mutates input.

**Everything takes `[]byte` in, `[]byte` out.** No file paths inside the
package; storage is the store layer's job. Every function takes a
`context.Context` (TSA calls must be cancellable) and a `time.Time` clock
injected for testability.

## Acceptance

```
go test ./internal/signpdf
```

Must prove, on `testdata/sample1.pdf`:

1. `Certify` output: 1 signature, type certification, `/SigFlags` 3, `/P` =
   `NoChanges` (assert the annotation's `/P` name in the raw bytes), form
   read-only afterwards, document opens in `pdfinfo` / `pdftotext` without
   errors. Also assert that a `SetField` attempt on the certified bytes fails.
   Note: per ISO 32000 (12.8.4.5) a certification signature permits filling
   signature fields at **every** permission level, so `NoChanges` does not block
   the later approval signatures — step 10 test 1 proves it end to end.
2. `SignParty` chained 3 times over the certify output: 4 signatures, `Verify`
   returns `Valid=true` and 4 signers with the right names and increasing times.
3. Tampering: flip one byte of page content in the certified file before the
   third signature, or append an unsigned change after a signature -> `Verify`
   returns `Valid=false` with a non-empty `Errors`.
4. Missing TSA URL -> `Certify` returns a clear error (no silent B-B fallback).
5. Leaf `NotAfter` <= `NotBefore+16min`; private key absent from `Out` and from
   `CertPEM` (assert `BEGIN PRIVATE KEY` not present).
6. Widget rect is inside the page crop box.

```
signsrv sign-selftest        # CLI in cmd/signsrv: certify+sign+verify a test file,
                             # prints the JSON report; exit 0 only when valid
```

## Signoff

- [ ] Certification is first signature, `AllowFormFilling`, then approvals only
- [ ] Private key never leaves memory; asserted by test 5
- [ ] Verification is enforced before any delivery path (documented in 10)
- [ ] TSA is mandatory in v1; failures are errors, not fallbacks
- [ ] keystore key is encrypted at rest, 0600, no passphrase in logs
- Reviewer: ____________  Date: ________
