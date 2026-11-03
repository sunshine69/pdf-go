# 07 — Consent capture (public endpoints, state machine)

Depends: 03, 05, 06.

The party **does not sign the document** in this step. They record consent.
Nothing here touches a PDF. The signing batch is step 10.

## Deliverables

- `cmd/signsrv/sign.go` (claim, envelope, document, consent, decline)
- `internal/signflow/{claim.go,consent.go,state.go}`
- `cmd/signsrv/sign_test.go`, `internal/signflow/consent_test.go`

## Design

**Claim** `POST /api/v1/sign/{token}/claim {"email":"a@x"}`

1. Resolve party by token hash. Unknown -> 404. Expired -> 410.
2. Compare email case-insensitively after trim. Mismatch -> 403 with
   "this link is issued to a different address" (the address is never echoed).
3. Rate limited 10/min/IP. On success `parties.status = claimed`, `claim_at`,
   session token generated, hash stored, session cookie set (see 03), returns
   `{"ok":true,"name":"Ann","title":"...","expires_at":"..."}`.
4. `events += {kind:"claimed", actor:party_id}` with IP and user agent.

**Envelope view** `GET /api/v1/sign/{token}/envelope` (requireSigner, also
allowed pre-claim for the title + expiry only, party list hidden):
`{"title","expires_at","my":{"order":2,"of":3,"name":"Ann","status":"consented",
"consent_at":"..."},"parties":[{"order":1,"name":"Bob","status":"consented"}]}`.
Party emails are **not** exposed to other parties, only names and order.

**Document** `GET /api/v1/sign/{token}/document` streams the **certified**
revision (the frozen bytes the party reviews), `Content-Type: application/pdf`,
`Content-Disposition: inline; filename="<slug>.pdf"`, `X-Content-Sha256`. The
sha is also in the envelope view so the SPA can show "you are reviewing
sha 1a2b3c…" and the consent record stores it.

**Consent** `POST /api/v1/sign/{token}/consent` (requireSigner):

```json
{"signature_text":"Ann Miller","consent":true,"image":"<optional base64 png>","document_sha":"1a2b3c..."}
```

Checks, first failure wins:

| Failure | Code |
|---|---|
| party status is `declined`/`expired`/`consented` | 409 |
| token expired | 410 |
| `consent != true` | 400 |
| `signature_text` empty, > 120 chars, or contains control chars | 400 |
| `document_sha` missing or != certified sha | 409 "the document changed, reload" |
| `image` present: not PNG/JPEG magic, > 512 KB, > 2000x2000, bad base64 | 400 |
| envelope status not `sent`/`collecting` | 409 |
| envelope expired | 410 |

Steps when all pass (transaction, `BEGIN IMMEDIATE`):

1. Store the image (if any) with `store.PutBlob` -> `image_sha`.
2. Insert `consents{party_id, envelope_id, signature_text, consent_at:now, ip,
   user_agent, document_sha, image_sha, appearance_json}`.
3. Party `status = consented`, `consent_at`. Session cookie invalidated —
   one consent per party.
4. `events += {kind:"consent", actor:party_id, payload:{sha_of_consent}}`.
5. Envelope `sent -> collecting` on the first consent.
6. If all parties are `consented`: enqueue the signing batch (step 10) and set
   `events {kind:"batch_queued"}`. Do **not** sign inline in the request.
7. Response `{"ok":true,"status":"consented","all_consented":bool}`.

Client-controlled data that reaches the signer in step 10 is exactly
`signature_text`, `image_sha` and `appearance_json`. Name, email, order, reason,
TSA URL, widget rect, certificate and key are all server-side. Assert by
grepping the consent request struct: no `name`, `email`, `order`, `tsa`,
`cert`, `key`, `rect` fields.

**Decline** `POST /sign/{token}/decline {"reason":"..."}` -> party `declined`,
envelope `collecting|sent -> failed`, all tokens/session hashes cleared, admin
notified, `events`. Response tells the party the request is closed.

**State machine** (`state.go`), table-driven:

```go
var allowed = map[State][]State{
  "ready":      {"sent", "cancelled", "expired"},
  "sent":       {"collecting", "cancelled", "expired"},
  "collecting": {"signed", "failed", "cancelled", "expired"},
  "signed":     {"completed", "failed"},
  "completed":  {"delivered", "failed"},
}
func Transition(ctx, e *Envelope, to State, actor string) error  // writes events
```

Any transition not in the table -> `ErrStateConflict` -> HTTP 409. `consented`
is a *party* status; the envelope moves to `signed` only through step 10.

**Worker hooks** (`cmd/signsrv/worker.go`): drains the mail queue, drains the
batch queue (step 10), runs the 5-min sweeps. Sweeps mark parties `expired` and
envelopes `expired` past `expires_at`; an envelope expiring mid-collection
notifies the admin and every party (documented outcome: nothing is signed).

## Acceptance

```
go test ./internal/signflow ./cmd/signsrv -run "Consent|Claim"
```

1. Claim with the correct email -> cookie set, party `claimed`; with a wrong
   email -> 403, `events` has a `claim_failed` row with the IP.
2. Consent happy path -> row in `consents` with text, time, ip, ua, document_sha;
   party `consented`; session cookie dead; second consent attempt -> 409;
   `revisions` count **unchanged** (proves no PDF was written).
3. `consent:false` -> 400. `signature_text:""` / 121 chars / `"a\nb"` -> 400.
4. Stale `document_sha` -> 409.
5. Oversized / non-image / malformed base64 image -> 400.
6. Expired link -> 410 (test injects a clock, `expires_in=1s`).
7. Decline -> envelope `failed`, all other parties' links 410, admin event.
8. Last consent enqueues exactly one batch (`SELECT count(*) FROM batch_queue`)
   and returns `all_consented:true`.
9. Request-struct grep test: no party-controlled name/email/order/cert/key/tsa.

## Signoff

- [ ] Consent is data only: no PDF is created, modified or signed in this step
- [ ] Consent stores document_sha, so consent is provably about the reviewed bytes
- [ ] One consent per party; session invalidated; consent is idempotent-safe
- [ ] Batch is queued, not executed inline (no signing inside an HTTP request)
- [ ] Party emails are never exposed to other parties
- Reviewer: ____________  Date: ________
