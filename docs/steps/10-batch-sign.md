# 10 — Signing batch, verification, delivery, receipt

Depends: 04, 05, 07, 09.

This is the only place in the system that signs a document. Single-threaded,
one job per envelope, driven by the worker (an admin can also trigger it).

## Deliverables

- `internal/signflow/{batch.go,deliver.go,receipt.go}`
- `cmd/signsrv/worker.go` (batch queue consumer), `signsrv batch <envelope-id>`
- `web/templates/signed.txt.tmpl`, `signed.html.tmpl`
- `internal/signflow/batch_test.go`, `deliver_test.go`

## Design

**Trigger.** `signflow.EnqueueBatch(envelopeID)` inserts a row in
`batch_queue(envelope_id PK, attempts INT, next_at TEXT)`. Enqueued by the last
consent (step 07) and by `POST /envelopes/{id}/sign` (admin, for manual
re-run). The worker claims a queue row with
`UPDATE batch_queue SET lease_until = now+120s WHERE lease_until < now`
so a crashed worker's job is picked up again; `attempts <= 5`, exponential
backoff 30s/2m/10m/30m/2h.

**Batch** `signflow.RunBatch(ctx, envelopeID)`, idempotent:

1. Load the envelope; require status `collecting` **or** `signed` (resume).
2. Load all parties ordered by `order_idx`; require every party
   `status = consented` with a `consents` row, and the envelope not expired.
   Any other -> `ErrStateConflict`, job fails, admin alerted.
3. `in := store.Get(envelope.current_sha)` — the **certified** revision. Assert
   `sha256(in) == envelope.current_sha`.
4. In order, loop:

   ```go
   for _, p := range parties {
       out, err := signpdf.SignParty(ctx, in, signpdf.PartyOptions{
           Name: p.Name, Email: p.Email,
           Reason:    consent.Reason + "; electronically agreed " + consent.ConsentAt,
           Signature: consent.SignatureText,
           Image:     store.Get(consent.ImageSHA),      // nil if absent
           TSA:       settings.TSAURL,
       })
       // out.Data -> store.PutPDF -> revisions row
       //   kind="party", party_id, sig_field="Signature_<order>", prev_id, serial
       in = out.Data
   }
   ```

   Sequential, one thread: each party signs the output of the previous party, so
   signatures nest correctly and every earlier signature is covered.
   A failure at party *k* leaves revisions 1..k-1 on disk (immutable, harmless),
   keeps the envelope `collecting`, marks the job failed for retry. If the TSA
   call fails and retries exhaust, the envelope goes `failed`.
5. Envelope `collecting -> signed`. `events += {kind:"batch", payload:{n, final_sha}}`.
6. **Gate 1** — `signpdf.Verify(in)`. Require `Valid` and
   `len(Signers) == 1 + n` (certification + each party), and each
   `Signers[i].Name` matching the party names in order. Any mismatch -> envelope
   `failed`, admin alert, no delivery.
7. `Finalize` writes `receipt.json` (below), `envelope.final_sha = sha(in)`.
8. `completed`, then enqueue one delivery row per party.

**Delivery.** Per party, email with the signed PDF attached
(`<slug(-)>-signed.pdf`, `application/pdf`, base64 transfer encoding) and
`receipt.json` attached. If the file is > 20 MB, replace the attachment with a
download link `<public>/d/<random 32b>` (single document, 72h, no auth, stored
hash, 410 after expiry, cannot enumerate other documents). Retries 5x with the
same backoff. A party's delivery is recorded in `parties.delivered_at`; the
envelope goes `completed -> delivered` only when every party's delivery is
accepted.

**Gate 2.** Immediately before each attachment is written into a message,
re-verify the bytes read from storage. Verification failure at this gate stops
all delivery, sets `failed`, writes `events {kind:"verify_failed", payload:
{errors, expected_sha, got_sha}}`. Two gates mean a file swapped on disk between
finalize and send is caught.

**Receipt** `receipt.json`, stored as `<final_sha>.receipt.json`:

```json
{"envelope_id":"...","title":"...","iss":"signsrv","server_key":"<jwk fingerprint>",
 "final_sha256":"...","valid":true,
 "revisions":[{"kind":"certified","sha256":"...","serial":"...","created_at":"..."}],
 "parties":[{"order":1,"name":"Ann","email":"a@x","consent_at":"...",
             "signature_text":"Ann Miller","consent_ip":"...","consent_ua":"...",
             "document_sha":"<reviewed>","signed_at":"...","cert_serial":"...",
             "cert_fingerprint":"<sha256 DER>","sig_field":"Signature_1",
             "tsa":{"present":true,"authority":"freetsa.org","time":"..."}}],
 "verification":{"valid":true,"signers":[...],"errors":[],"warnings":[...]}}
```

`GET /envelopes/{id}/report` returns it. `consent_at` (agreement time) and
`signed_at` (batch time) are both present, explicitly labelled — the receipt
never implies they are the same.

**Long-term (documented, not v1).** PAdES B-LT needs the CA to publish
OCSP/CRL (hook: `Format(pdfsign.PAdES_B_LT)`); B-LTA is not supported by the
library; renewing long-lived evidence = add a `Type(DocumentTimestamp)`
signature later.

## Acceptance

```
go test ./internal/signflow -run "Batch|Deliver"
```

1. Certified doc + 3 consents -> batch produces exactly 3 party revisions, final
   `Verify` reports 4 signers, `valid:true`, names in `order`, every
   `sig_field` unique, `prev_id` chain unbroken.
2. Batch run twice -> second run is a no-op (`signed` -> returns existing
   final_sha, revision count unchanged, no duplicate deliveries).
3. Order test: tamper the batch input so party 2's digest covers the wrong bytes
   (replace the revision after party 1) -> final verification fails, envelope
   `failed`, **zero** emails.
4. TSA failure injected (unreachable URL) -> job retries 5x, backoff observed,
   envelope `failed`, admin event, no partial delivery.
5. Out-of-consent trigger: `POST /envelopes/{id}/sign` while party 3 has not
   consented -> 409, nothing signed.
6. Delivery: 3 `.eml` in outbox, each with the signed PDF and `receipt.json`;
   attached PDF sha == `final_sha`; envelope `delivered`; all links 410.
7. File-swap attack after Gate 1 -> Gate 2 stops delivery, `verify_failed`
   event names expected and got sha.
8. `report` JSON: 4 signers, `valid:true`, `consent_at` != `signed_at` for every
   party, fingerprints match stored leaf certs.

## Signoff

- [x] Signing happens only in RunBatch; verified by grep (no `SignParty` call
      outside batch.go and tests)
- [x] Batch is idempotent and resumable; a crashed job is re-claimed
- [x] Two verification gates, both tested (3, 7)
- [x] Delivery is per-party accepted; `delivered` requires all
- [x] receipt.json states consent time and signing time separately and honestly
- Reviewer: ____________  Date: ________
