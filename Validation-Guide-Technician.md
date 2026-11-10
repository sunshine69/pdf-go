# Validation Guide

How to check that a signed PDF from this service is genuine.

You need the PDF. For the trust step you also need our CA certificate, which you
download from `https://pdfsign.kaykraft.org/ca.crt` (see §5).

The two questions are separate, and the tools answer them separately:

- **Is the document intact?** Answered by the file alone. The signature covers
  the document bytes, so recomputing the hash proves nothing has changed since the
  signature was made. No trust, no network.
- **Who signed it, and can I trust that?** Needs our CA as a trust anchor. The
  certificate chain travels inside the PDF, but a root that is in nobody's trust
  store proves nothing until you import it.

Every reader (Adobe, pdfsig, this CLI) reports these two separately, and both
report them as two lines. Read them as two lines.

---

## 1. pdfsig (free, command line)

`pdfsig` is part of poppler, the PDF library used by many Linux readers.

```sh
# Debian/Ubuntu
sudo apt install poppler-utils
# Fedora
sudo dnf install poppler-utils
# macOS
brew install poppler
```

Run it on the file:

```sh
pdfsig signed.pdf
```

An intact file reports, for each signature — this is the real output of a
document from the service:

```
Signature #2:
  - Signature Field Name: Signature 2
  - Signer Certificate Common Name: Steve Kieu
  - Signer full Distinguished Name: CN=Steve Kieu,O=signsrv
  - Signing Time: Nov 09 2026 19:13:54
  - Signing Hash Algorithm: SHA-256
  - Signature Type: ETSI.CAdES.detached
  - Signed Ranges: [0 - 59472], [83964 - 183823]
  - Total document signed
  - Signature Validation: Signature is Valid.
  - Certificate Validation: Certificate has Expired
```

There are normally two signatures: the first certifies the document before
signatures are collected, the second is the party's.

**Read `Signature Validation` as the integrity verdict.** `Signature is Valid`
means the document bytes match the signature: untouched since signing. A file
edited after signing says:

```
  - Signature Validation: Digest Mismatch.
```

`Certificate Validation` is the trust verdict, and on our documents it will read
`Certificate has Expired` or `Unknown issue with Certificate`. **That is
expected and is not a sign of a bad document.** Two reasons:

1. Our CA is self-signed and not in your trust store, so nothing can be
   confirmed above the leaf.
2. A party certificate is valid for 15 minutes. It is genuinely expired the
   moment you run the check. What proves the signature is the timestamp token
   inside it, which attests the signature existed inside the validity window.
   `pdfsig` does not consult the timestamp in this line, so it reports the
   certificate as expired.

To get a useful trust verdict out of `pdfsig` you must import the CA into an NSS
database and tell pdfsig to use it:

```sh
pdfsig -nssdir DIR signed.pdf
```

Two things stand in the way. Importing needs the NSS command-line tools
(`certutil`, `pk12util`), which do not come with poppler — on Debian/Ubuntu they
are the `libnss3-tools` package. And if `DIR` is not a valid NSS database, pdfsig
prints this before it prints anything about your document:

```
NSS_Init failed: security library: bad database.
```

That line is about the database, not the PDF; the report still follows and its
integrity line is still trustworthy.

**For the trust verdict, §2 is the shorter route.** It is a single command that
takes the CA file directly and needs nothing installed beyond `openssl` and
Python.

---

## 2. openssl (standard, in most systems)

`openssl` can do both checks. It needs the signed bytes, which are the ranges
listed in `/ByteRange` — the two segments around each signature's own blob. Use
the script in this repository, which does that and calls openssl:

```sh
# Integrity: no CA needed. Exit 0 when every signature matches the document.
python3 scripts/verify_pdf.py signed.pdf

# Integrity plus trust: supply the CA you downloaded (§5).
python3 scripts/verify_pdf.py signed.pdf ca.crt
```

Output of the second command, on a real document from the service:

```
signature 1
   signer:   /O=signsrv/CN=signsrv CA
   signed:   35819 bytes, at 261109091003Z
   digest:   OK
   chain:    OK
signature 2
   signer:   /O=signsrv/CN=Steve Kieu
   signed:   159331 bytes, at 261109091354Z
   digest:   OK
   chain:    OK

OVERALL: all digests verify
trust: every chain leads to the CA you supplied
```

- **`digest: OK`** is the integrity verdict. A file edited after signing prints
  `digest: FAILED` and exits 1.
- **`chain: OK`** is the trust verdict, checked **at the signing time** recorded
  inside the signature rather than today, because the party certificate is valid
  for 15 minutes and the timestamp token is what proves when the signature was
  made.
- **`trust:`** and **`OVERALL:`** are the two summary lines. Both must read well
  before you accept the document; a `chain` line that does not read `OK` means
  the CA you supplied is not the one that signed the file (§5).

A CA from somewhere else, for comparison — this is what it looks like when the
trust anchor is wrong:

```
   chain:    verification failed
...
OVERALL: all digests verify
trust: a chain does not lead to the CA you supplied (check the fingerprint, §5)
```

That case — digests fine, chain refused — is the shape of a document signed by a
different CA than the one you were given.

The reverse case matters just as much. On a tampered file the chain still reads
`OK`, because the certificate inside the signature was never touched; only the
document was. **`chain: OK` next to `digest: FAILED` is a tampered file signed by
the right CA.** The two lines are independent questions and neither implies the
other. Only `OVERALL` and the exit code combine them.

To do it by hand, for one signature:

```sh
# 1. The signed bytes: concatenate the two /ByteRange segments.
# 2. The signature blob is the gap between them, as hex.
openssl smime -verify -inform DER -in sig.p7b -content signed.bin \
    -noverify -out out.bin      # integrity
openssl x509 -in leaf.pem -noout -issuer -dates -ext extendedKeyUsage
openssl verify -attime <epoch-of-signingTime> -CAfile ca.crt leaf.pem   # chain
```

Two things to know:

- `openssl smime` needs `-out` for a detached signature; it has no `-noout`.
- The chain check must use the signing time. Verifying today reports
  `certificate has expired` for a signature that was valid when it was made.

---

## 3. Our own command line tool



`signsrv checkpdf` makes no network request and does not need an account. It
reads the signature and the certificates inside the PDF, and writes nothing to
disk.

**No config file is required.** `checkpdf` with just a filename is the recipient
path, and the binary published under `/dl/` carries this instance's CA, so the
one command is also the pinned one:

```sh
./signsrv checkpdf contract.pdf
```

`-pin ca.crt` supplies the CA from a file instead of from the binary (useful for
checking a document from a different instance, or when running a binary you built
yourself). `-config FILE` is the operator path: it adds `ca_sha256`, the
fingerprint of the CA in that config's keystore.

A binary built from this repository, rather than one built by
`scripts/build-release.sh`, carries no CA and therefore cannot name the signer.
It says so — `"trust": "none"` in the JSON and a warning on stderr — rather than
printing a verdict that looks stronger than it is.

```json
{
  "valid": true,
  "in": "contract.pdf",
  "sha256": "66e3122043ce5280b1988c2d71540e8af1faa582859b569b5886502c8d67bf3b",
  "pages": 2,
  "producer": "Acrobat Distiller 5.0.5 (Windows)",
  "trust": "pinned",
  "anchor_sha256": "67f4d365ff196c75bc581df8e79badb5c213ef19196d8de796d8fc95b7c3bdf6",
  "anchor_source": "this binary",
  "tsa_url": "not-configured",
  "signers": [
    {"Name": "signsrv", "Email": "", "Reason": "certify",
     "Time": "2026-11-10T12:00:51+10:00",
     "Valid": true, "Trusted": true, "Revoked": false,
     "Serial": "A0D96E2D3A2A04F10B6F5EADF6546EB1", "Timestamp": true}
  ],
  "bytes": 539388
}
```

What each field means, and what it does not:

- **`valid`** — the whole-document verdict, and the one to act on. The exit code
  is 0 when true and 1 when false, so a tampered file reports `"valid": false`
  and exits 1. `Valid` per signer is that one signature's verdict.
- **`trust`** — whether this run checked who signed.

  - `"pinned"`: every signing certificate had to have been issued by
    `anchor_sha256`. `valid: true` is now evidence of authorship, not only of
    integrity. A document signed by an unrelated CA — even a well-formed,
    self-consistent one of its own making — is refused here, with one error line
    per signature.
  - `"none"`: no anchor was available, so every chain only had to hold together.
    The verdict then says the document is intact and self-consistent and says
    **nothing** about who ran the CA. Do not quote `valid: true` from a run that
    reports `trust: none`.
- **`anchor_sha256` / `anchor_source`** — the CA the check required, and where it
  came from (`"this binary"`, `"-pin ca.crt"`, or a keystore path). Compare
  against the value the instance publishes at `/api/v1/ca`.
- **`sha256`** — the hash of the file you checked. Compare it against the hash
  the sender recorded, and you know you checked the file you were sent rather
  than a substitute.
- **`Valid: true, Timestamp: true`** — the signature matches the bytes, and a
  timestamp token attests the signature existed at that moment.
- **`Trusted`** — under `trust: pinned` this mirrors the anchor check. Under
  `trust: none` it is false for every signer, because nothing checked the issuer;
  read it together with `trust`, not on its own.
- **`ca_sha256`** — only present with `-config`, and it names **the CA in that
  config's keystore**, not necessarily the CA in the document. It is a fact about
  the machine running the check. To identify the CA that actually signed the
  document, use `anchor_sha256` (which the document's signatures were required to
  match), or §2 / §5.

The trust anchor is checked by requiring each signing certificate to bear the
anchor's own signature. This PKI is two levels deep — the CA signs leaves
directly — so that single hop is the whole chain, and the check is not subject to
the extended-key-usage nesting rules a chain builder applies, which reject these
certificates for reasons unrelated to who issued them.

Because a verification never signs anything, the tool refuses to run if
`keystore_dir` holds a CA certificate without its private key. This only applies
to `-config` runs: a plain `checkpdf` never opens a keystore.
---

## 4. Adobe Acrobat

Acrobat reports both verdicts in the Signature Panel. To trust our CA, open the
signature's certificate, **Add to Trusted Certificates**, and check the
fingerprint in §5 against the one you got from us on a channel we do not
control. Acrobat will then report the chain as trusted. The certificate
validity line still says expired, for the same reason as §1.

---

## 5. The CA certificate

Download:

- `https://pdfsign.kaykraft.org/ca.crt` (PEM, downloads as a file)
- `https://pdfsign.kaykraft.org/api/v1/ca` (JSON: subject, validity dates,
  SHA-256 fingerprint)

Fingerprint of the CA in use, as `openssl` prints it:

```
sha256 Fingerprint=67:F4:D3:65:FF:19:6C:75:BC:58:1D:F8:E7:9B:AD:B5:C2:13:EF:19:19:6D:8D:E7:96:D8:FC:95:B7:C3:BD:F6
notAfter=Nov  4 03:00:28 2036 GMT
```

The certificate is the public half of the signing key, so publishing it is
safe. Its value is not the download, it is the **comparison**: get the
fingerprint from us by a route the download does not use (a phone call, the
admin panel, the deploy record). A CA fetched from the same server as the
signed document proves nothing, because whoever sent you the document controls
both.

Check the download against the fingerprint:

```sh
openssl x509 -in ca.crt -noout -fingerprint -sha256 -subject -enddate
```

It must print exactly the fingerprint above. Import it as a **trust anchor**,
not as a trusted leaf, and check that the chain in any document you verify ends
at this certificate. The endpoint answers 503 when the instance has no keystore.

---

## 6. What the checks do not cover

- **Identity of a signer.** The name in the leaf certificate is asserted by us
  from what the party typed at the signing link. A self-signed chain proves the
  certificate was issued by our CA; it does not prove the person named was the
  person who clicked. The email, the consent text, and the link delivery are the
  evidence of who acted; the certificate is evidence of which key signed.
- **Revocation.** Leaf certificates carry no CRL or AIA pointer, and there is no
  responder to query. A verifier that insists on a revocation check cannot
  complete it here.
- **Strict EKU nesting.** A leaf carries `emailProtection` plus the document
  signing OID `1.3.6.1.5.5.7.3.36`; our CA carries only that OID. Verifiers that
  require a leaf's extended key usages to be a subset of its issuer's reject the
  chain. Observed, on the same document with the correct CA:
  - `openssl verify -CAfile ca.crt leaf.pem` — **accepts**. This is what §2 uses.
  - `openssl smime -verify -CAfile ca.crt ...` — **rejects**, `unsuitable
    certificate purpose`. Use `openssl verify` for the chain, not `smime`.
  - Go's `x509.Certificate.Verify` — **rejects**, `certificate specifies an
    incompatible key usage`. Its default key usage is server auth; passing
    `ExtKeyUsageAny` accepts the chain.
  - `pdfsig` — does not object on this at all; its complaint is the expiry (§1).

  A recipient using a strict tool sees a rejection that is not a sign of a bad
  signature. The integrity check (§1, §2) is unaffected by any of this.
- **Signatures added after the last one.** A signature covers the bytes that
  existed when it was made. Later signatures extend the ranges. Checking the
  last signature covers the whole document; checking an early one does not,
  which is why `pdfsig` prints `Not total document signed` for the first.
