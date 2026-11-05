# 09 — Admin endpoints and admin UI

Depends: 03, 05, 07.

## Deliverables

- `cmd/signsrv/admin.go`, `internal/signflow/admin.go`
- `web/admin/index.html`, `app.js`, `app.css`
- `cmd/signsrv/admin_test.go`

## Design

Endpoints, all behind `requireAdmin` (or `envelope:read` where noted):

```
GET  /api/v1/admin/stats            # counts per status, totals, overdue
GET  /api/v1/admin/events?envelope= # audit log, newest first, page 100
GET  /api/v1/admin/settings         # TSA URL, link TTL, mail from, SMTP host
POST /api/v1/admin/settings         # whitelist of keys, writes events row
GET  /api/v1/envelopes?status=&q=   # list (envelope:read)
GET  /api/v1/envelopes/{id}         # detail incl. consents, cert serials
POST /api/v1/envelopes/{id}/send    #
POST /api/v1/envelopes/{id}/remind  #
POST /api/v1/envelopes/{id}/cancel  # body {"reason":"..."} required
POST /api/v1/envelopes/{id}/reissue # new tokens for outstanding parties
GET  /api/v1/envelopes/{id}/audit.zip  # every revision + consent records + events
POST /api/v1/admin/clients          # create machine client, key printed once
POST /api/v1/admin/clients/{id}/revoke
POST /api/v1/admin/logout
```

`audit.zip` is a zip of `document.pdf` (every revision, named
`001-template.pdf`, `002-filled.pdf`, `003-certified.pdf`, `004-sign-Ann.pdf`),
`consents.json`, `events.json`, `manifest.json` (sha256 of each file + the
verification report from `signpdf.Verify`). Generated on demand, streamed,
never cached on disk.

`POST /envelopes/{id}/sign` triggers (or re-triggers) the signing batch; allowed
from `collecting` when every party is `consented`, and from `signed` to re-run an
idempotent batch. Returns 409 when a party has not consented.

`cancel` rules: allowed from `ready|sent|collecting`; requires a reason;
invalidates all tokens; notifies parties by email ("the request was
cancelled"); writes `events`. Not allowed from `delivered` (409).

Admin SPA:

- Login form -> `POST /auth/login` -> token kept in memory only (JS variable),
  refresh on 401 using the refresh token from the login response held in a
  closure; a "log out" button clears it and calls `/auth/logout`.
- Views: dashboard (status counts + overdue list), envelope table (status,
  parties, progress, created, expires), detail page (parties with consent times,
  typed signature text, signing time + cert serial after the batch, revision
  chain, event log; buttons: send, remind, reissue, **sign now** (visible when
  all parties consented), cancel, download document, download audit.zip),
  settings page. The dashboard shows a `collecting` tile with
  `consented/total` per envelope.
- Polling: `GET /admin/stats` every 30s on the dashboard only, stopped when the
  tab is hidden (`document.visibilityState`).
- Same CSP/no-HTML-injection rules as 08. Table cells are built with
  `textContent`. `q` is sent URL-encoded and never interpolated into HTML.
- No admin secrets displayed: the machine client key appears once, in a
  `<pre>` block, with "this is the only time it is shown".

## Acceptance

```
go test ./cmd/signsrv -run Admin
```

1. Non-admin client token on `/admin/stats` -> 403. Admin token -> 200.
2. `cancel` on `collecting` -> parties' links return 410; cancel email in
   outbox; `events` has `cancelled` with the reason.
3. `cancel` on `delivered` -> 409.
4. `audit.zip` for a completed envelope: contains 1+n revisions, `consents.json`
   with the typed signature text and ip, `manifest.json` verification report
   `valid:true`, sha256s match the store.
5. `remind` twice in 10 minutes -> second call 429.
6. `reissue` invalidates the old token (old link 401/404) and the new link works;
   `reissue` skips parties already `consented` (assert their token is unchanged).
9. `sign` with a party not consented -> 409; with all consented -> batch runs,
   envelope `signed`, then `delivered`, and `/report` returns `valid:true`.
7. `POST /admin/settings` refuses unknown keys (400) and writes an event.
8. Grep assertions on `web/admin`: no `innerHTML`, no external URLs, no
   `localStorage`.

## Signoff

- [x] Every admin mutation writes an audit event with the actor
- [x] audit.zip is reproducible and includes the verification report
- [x] Cancel/reissue invalidate outstanding tokens (tested)
- [x] Client key material is shown exactly once, never stored plaintext
- Reviewer: ____________  Date: ________
