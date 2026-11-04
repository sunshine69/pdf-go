# 05 — Envelopes: fill, certify, CRUD API

Depends: 02, 03, 04.

## Deliverables

- `internal/signfill/{fill.go,spec.go}` — adapter over `internal/pdf` + `internal/schema`
- `internal/signflow/{envelope.go,state.go}` — creation, state machine, transitions
- `cmd/signsrv/envelopes.go` — the create/list/get endpoints
- `cmd/signsrv/envelopes_test.go`, `internal/signfill/fill_test.go`

## Design

**Fill.** Reuse the CLI logic by calling the library, not the binary:

```go
schema, err := pdf.Extract(templatePath, "")        // existing code
report, filled, err := signfill.Fill(template []byte, spec FillSpec, o Options)
```

`FillSpec` is exactly the CLI fill JSON (`values`, `logos`, `paints`) documented by
`pdf-go doc`, so the AI tool and the API share one format. `signfill` writes the
template to a temp file, calls the existing `pdf` package fill path, reads the
bytes back, and returns `report.Skipped`/`report.Warnings` unchanged.
`--strict` semantics are kept: an unknown field is a hard error at creation
(400), not a silent skip.

**Create request** (`POST /api/v1/envelopes`, `multipart/form-data`):

```
template        file, required, <= 20 MB, must be a PDF with >= 1 fillable field
spec            JSON, required: {"fill":{...}, "widget":{...}, "subject":"...", "message":"..."}
parties         JSON array, required, 1..20:
                {"email","name","order":1,"reason":"I agree to the terms"}
title           string, required, <= 200
expires_in      duration, optional, default SIGNSRV_LINK_TTL, max 720h
send            "true" -> create and send in one call
```

Validation, in order, all as 400 with a `hint`:
magic bytes `%PDF-`; template parses; extract succeeds; every `parties[].email`
is RFC-valid and unique; orders are `1..n` contiguous with no gaps; fill spec
resolves against the extracted schema (`pdftools fill --strict` rules, suffix
matching allowed); every fillable field is **not** required to be filled —
read-only fields requested are skipped with a warning, unknown fields abort.

**On create** (transaction + storage, all-or-nothing):

1. `id = 16 random bytes hex`.
2. Store template as a `revisions` row (`kind="template"`, `prev_id=NULL`).
3. Fill -> `kind="filled"`; certify -> `kind="certified"`, `envelopes.serial =
   certification cert serial`, `current_sha = certified sha`.
4. Insert parties with `status="invited"`, `token` generated (raw value kept only
   in the create response, hashes stored).
5. `status="ready"`. `events += {actor:<client>, kind:"created", payload:{...}}`.
6. If `send=true`, run step 06's send.

`GET /api/v1/envelopes/{id}` returns:

```json
{"id":"...","title":"...","status":"ready","expires_at":"...",
 "parties":[{"order":1,"email":"a@x","name":"Ann","status":"consented",
             "consent_at":"...","link_expires_at":"..."}],
 "consented":1,"total":2,
 "revisions":[{"id":"...","kind":"certified","sha256":"...","created_at":"..."}],
 "document_sha":"...","events":[{"kind":"sent","actor":"api","created_at":"..."}]}
```

`GET .../document` and `GET .../revisions/{rid}` stream the stored PDF with
`Content-Disposition: attachment; filename="<slug>-<kind>.pdf"`, `Cache-Control:
private, no-store`, and `X-Content-Sha256`. Available to `envelope:read` scope.

**State machine** lives in `state.go` as a table:

```go
var allowed = map[State][]State{ "ready":{"sent","cancelled","expired"},
  "sent":{"collecting","cancelled","expired"},
  "collecting":{"signed","failed","cancelled","expired"},
  "signed":{"completed","failed"}, "completed":{"delivered","failed"}, ... }
func Transition(e *Envelope, to State, actor string) error   // writes events row
```

Any transition not in the table is `ErrStateConflict` -> HTTP 409. Transitions
run under `BEGIN IMMEDIATE` so concurrent signers cannot double-advance.

## Acceptance

```
go test ./internal/signfill ./internal/signflow ./cmd/signsrv
```

1. Create with `testdata/sample1.pdf` + 2 parties -> 201, `status:"ready"`,
   3 revisions, 2 plaintext links in the response only.
2. Fill spec with an unknown field -> 400 naming the field, **no** envelope row
   created (assert count).
3. Duplicate party email / non-contiguous order -> 400.
4. Certified document: form fields read-only (assert via `pdf.Extract` flags on
   the stored certified file — every field carries `readOnly`).
5. `Transition(envelope, "completed")` from `ready` -> 409.
6. List: `?status=ready&q=title` filters; 1000 envelopes -> list call < 50 ms
   (index used, `LIMIT`/`OFFSET` enforced, max page size 100).
7. Document download sha matches the stored `current_sha`.

## Signoff

- [x] Fill format is the CLI fill JSON, no second invented schema
- [x] Certification happens at create; certified file has all fields read-only
- [x] Plaintext links exist only in the create/send response
- [x] State transitions are table-driven, transactional, audited
- [x] All create failures leave no partial rows (asserted)
- Reviewer: ____________  Date: ________

## Notes

`POST /api/v1/envelopes` takes a multipart form: `template` (the PDF file),
`title`, `expires_in`, `parties` (a JSON array), and `spec`. `spec` is one JSON
document — `{"fill": <CLI fill JSON>, "widget": {...}, "subject": "...",
"message": "..."}` — and `fill` is the exact document `pdf-go fill` accepts,
including `values`, `logos`, `paints`, and `lockForm`. A single spec file
produces the same fill through the CLI and through the API, and the acceptance
script asserts that the two agree.

The response is `{envelope, fill, links, request}`. `links` carries the raw
tokens: they exist in this response and nowhere else, the database stores
`token_hash`, and the log never sees them.

`internal/signflow/envelope.go` runs the create as one transaction: envelope,
the three revisions (template, filled, certified — `prev_id` chains them),
parties, and the `created` event. The certification signature is applied to the
filled bytes, all fields become read-only, and `current_sha` is the certified
hash. `signsrv checkpdf` on the downloaded document reports the certification as
the first signer.

`internal/signflow/state.go` holds the transition table (`var allowed`), and
`Transition` writes the new status and the audit event in one transaction. A
disallowed move returns `ErrStateConflict`, which the API answers as 409.

`sh scripts/acceptance-05.sh` runs every block above: the build offline from
vendor, vet/gofmt, the unit tests, the state-machine structure, a live service
driven with curl, the 1000-envelope list, the download headers, the scope
matrix, and the create rate-limit bucket.
