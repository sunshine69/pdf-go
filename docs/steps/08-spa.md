# 08 — Signer SPA

Depends: 03, 06, 07.

## Deliverables

- `web/spa/index.html`, `app.js`, `app.css` (embedded by the binary)
- No build step, no framework, no third-party JS, no external CDN
- `web/spa/spa_test.go` (serves the embedded files, asserts shape)

## Design

Routes served by the binary:

```
GET /s/{token}                 -> web/spa (index.html), token stays in the URL
GET /assets/spa/*              -> app.js, app.css   (Cache-Control: public, max-age=3600)
```

State machine in `app.js` (four views, one file, ~300 lines max):

1. **claim** — shown when `GET /sign/{token}/envelope` returns 401. One email
   input, prefilled empty, "I am signing as the person this link was sent to".
   `POST claim` -> on success re-fetch envelope.
2. **document** — `<iframe src="/api/v1/sign/{token}/document">` when the browser
   can render PDFs, plus a "Download to review" link (the iframe is not the
   consent: the checkbox below is). Party list with each party's order and
   status. Countdown of `expires_at`.
3. **consent** — the consent panel (the party records agreement, no PDF is
   touched at this point):
   - name display (read-only, from the server: `You are signing as Ann Miller`)
   - "You are reviewing document 1a2b3c…" (the certified `document_sha`, short
     form) plus the party list with each party's order and status
   - textarea for the typed signature, 120 char counter
   - optional file input for a drawn signature image (client-side size check
     mirrors the server: PNG/JPEG, 512 KB)
   - checkbox: "I have read the document and agree to sign it electronically.
     My typed name above is my signature." (required, no pre-check)
   - Agree button; disabled until text length > 0, checkbox checked, and the
     document view was opened at least once (`opened` flag in JS)
   - "Decline" button opens a reason prompt -> `POST decline`
   - The panel is read-only after a successful consent (`status:"consented"`,
     shows `consent_at`); there is no re-consent path.
4. **result** — `consented` ("your agreement is recorded; the document is signed
   and sent to everyone once all parties have agreed"), `expired`, `closed`
   (declined/cancelled/failed), `delivered` (signed document available).
   There is no "waiting for party N" view: consent order is free.

Hard rules for the SPA:

- No secret in storage: no `localStorage`/`sessionStorage` of the token; the
  token is read from `location.pathname` only.
- All DOM writes use `textContent`, never `innerHTML` with server data.
- CSP `default-src 'self'; script-src 'self'; style-src 'self'; frame-src 'self';
  connect-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'`
  set by the server on `/s/*` and `/assets/spa/*`.
- `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` on `/s/*`.
- Requests: `credentials:"same-origin"`, `Content-Type: application/json`,
  timeout 20s, single retry on network error only.
- 401 -> claim view. 409 -> re-fetch the envelope view and render the server
  message (stale `document_sha` means "reload, the document changed"; a consent
  after the envelope is `failed` means "closed"). 410 -> expired view.
  429 -> "too many attempts, retry in Ns" using `Retry-After`. 4xx -> show
  `error.message`, never `error.hint` (hints are for operators).
- Works with JS-only, no cookies disabled assumption: on `claim` success, if a
  follow-up request returns 401, show "cookies are blocked" with instructions.

## Acceptance

```
go test ./web/spa
```

1. `GET /s/<token>` returns 200 with the CSP, nosniff, no-referrer headers.
2. Embedded files exist, `<script>`/`<link>` point to `/assets/spa/...`, no
   external `http(s)://` URL anywhere in the three files (`grep`).
3. `app.js` contains no `innerHTML`, no `localStorage`, no `eval` (asserted).
4. Every server message shown to the party is rendered via `textContent`
   (grep for `innerHTML` = 0).
5. Manual checklist in the doc, verified by the reviewer in a browser:
   claim -> open doc -> type name -> check consent -> Sign -> result; the Sign
   button is unreachable without the checkbox; decline path; expired path.

## Signoff

- [ ] No third-party JS, no CDN, no build step
- [ ] Token never written to storage; CSP + referrer policy verified
- [ ] Server-rendered strings are never injected as HTML
- [ ] Consent checkbox is required and not pre-checked
- Reviewer: ____________  Date: ________
