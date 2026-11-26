# External client procedures

What a client outside the server does: hand over a contract PDF, have it
stamped and sealed, get signing links out to the parties, and confirm the
result. Nothing here needs a shell on the server, a database client, or
knowledge of the codebase. Three things are enough — the endpoint, a machine
key, and the PDF.

This run was executed against `https://test-pdfsign.kaykraft.org` on
2026-11-26 with client `test0` (id 1, subject `client:1`, scopes
`envelope:read` + `envelope:write`) and the Queensland Form 18A general
tenancy agreement. The envelope it ended on is
`e0d77f4ac27649a73ca7aa2edc4fdaf1`.

## What you need

| thing | where it comes from |
|---|---|
| the endpoint | the operator gives it to you. Use **only** that host |
| a machine key | the operator mints it (`signsrv client add`) and hands it to you. It is printed once and cannot be recovered |
| the document | the blank, unfilled form. Not a filled one — see step 4 |
| the `pdf-go` CLI | local tool; it talks to the endpoint for envelopes and does the PDF work on your machine |

The key is a bearer secret. Keep it in a file of mode `0600`, never in shell
history, a log, a screenshot, or a commit. If it leaks, ask for a new one.

```sh
umask 077
printf '%s' 'key_xxxxxxxx...exactly as given, prefix included' > run/client.key
chmod 600 run/client.key
```

The `key_` prefix is **part of the key**. Sending the hex alone is a 401
`the key is not valid` — a confusing error, because it reads as if the secret
were wrong rather than malformed.

## The two credentials are not the same thing

A machine key is long-lived and is what you hold. The service exchanges it for
a short-lived access token, 15 minutes:

```sh
curl -sS -X POST -H 'content-type: application/json' \
  -d @run/token-body.json \
  https://test-pdfsign.kaykraft.org/api/v1/auth/token
```

`run/token-body.json` is `{"key":"key_xxx..."}`. The answer carries `access`,
`expires_in: 900`, and the real `scopes` — read them, they tell you what this
key may actually do.

The CLI does this exchange for you. Point `--token-env` at the **name of an
environment variable**, not a file, and make sure it is exported:

```sh
export RUN_KEY=$(cat run/client.key)     # export, or the CLI sees no credential
pdf-go envelope get --server https://test-pdfsign.kaykraft.org --token-env RUN_KEY <id>
```

Two failures to expect. A plain `RUN_KEY=$(cat ...)` without `export` gives
`needs a credential`, which is the CLI saying it never saw the variable. A raw
access token passed as `--token-env` on a call that needs to mint a session is
rejected with `token_expired`. Set the variable to the machine key and let the
CLI handle tokens.

## The procedure

### 1. Read the form — never guess a field name

```sh
pdf-go extract forms/Form-18a-General-tenancy-agreement.pdf -o run/schema.json
pdf-go fields forms/Form-18a-General-tenancy-agreement.pdf
```

Form 18A carries 135 fields: 94 text, 39 checkbox, 2 push buttons. The names
are human-readable (`Rent amount`, `Start date (dd/mm/yyyy)`,
`Tenant 1 full name/s`), so guessing is *possible* and wrong in ways a tool
will not catch. Extract instead. Note also whether the form has any signature
fields: Form 18A has **none**, which decides how signatures are placed in
step 4.

### 2. Write the fill spec

Only the fields you set. Every name must come from step 1.

```json
{"values": {"Lessor name/trading name": "Keykraft Test Lessor Pty Ltd",
            "Rent amount": "620 per week",
            "Start date (dd/mm/yyyy)": "01/12/2026"},
 "lockForm": true}
```

`lockForm` matters for an agreement: without it the signed document stays
editable in a viewer. A value that does not fit its box is reported as a
`note`, not an error — read the notes.

### 3. Write the parties

One entry per signer. `order` is the signing order. Emails are unique. A name
containing a newline is rejected at create because it rides a mail header.

```json
[{"email":"lessor@example.com","name":"Keykraft Test Lessor","order":1},
 {"email":"tenant@example.com","name":"Pat Tenant","order":2,
  "reason":"I have read and agree to the terms of this agreement."}]
```

### 4. Create — and stop there

```sh
pdf-go envelope create \
  --server https://test-pdfsign.kaykraft.org --token-env RUN_KEY \
  --title "Form 18A general tenancy agreement - Keykraft / Tenant" \
  --subject "One document is waiting for your signature" \
  --message "Please review and sign. The link expires in 72 hours." \
  --expires 72h \
  --spec run/fill.json --parties run/parties.json \
  --widget-page 12 --widget-x 24 --widget-y 310 \
  --links-out run/links.json \
  forms/Form-18a-General-tenancy-agreement.pdf
```

Two things about that command cost real time to learn, so take them on trust.

**The positional file is the blank template.** `--spec` is applied
*server-side* to produce the certified bytes. If you upload a file you already
filled locally *and* pass `--spec`, the fill is applied on top of your fill:
the chain reads `template(filled) → filled → certified` and the bytes the
parties sign are not the bytes you verified locally. Fill locally only to
*check* the spec; upload the untouched form.

**Omitting `--send` is a feature, not an omission.** Nothing is mailed, no
party is touched, and you get a review gate (step 5). Sending first cannot be
unsent: the parties have the mail.

### 5. The review gate, before anything is mailed

Confirm state, then pull the certified bytes and look at them.

```sh
A=$(curl -sS -X POST -H 'content-type: application/json' \
  -d @run/token-body.json $BASE/api/v1/auth/token | jq -r .access)

curl -sS -H "Authorization: Bearer $A" $BASE/api/v1/envelopes/$ID -o run/envelope.json
jq -c '{status, revisions: [.revisions[] | {kind, sha256}]}' run/envelope.json

curl -sS -H "Authorization: Bearer $A" $BASE/api/v1/envelopes/$ID/document -o run/certified.pdf
pdf-go verify run/certified.pdf run/fill.json
sha256sum run/certified.pdf forms/Form-18a-General-tenancy-agreement.pdf
```

What to look for, in order:

- `status: ready`. Not `sent`, not `cancelled`.
- each party `sent_at: null`. Proof the gate is closed and nobody has been mailed.
- the revision chain has three entries, `template`, `filled`, `certified`, and
  the `template` sha equals `sha256sum` of the blank form you uploaded. If it
  matches your *filled* file instead, you made the mistake in step 4.
- `pdf-go verify` on the downloaded bytes: every field `match: true`, zero
  mismatches. This is the point where a wrong field name or a truncated value
  is cheap to fix. Cancelling and re-creating costs one command; recalling a
  signed document costs an explanation.

Cancelling here needs a reason and is clean:

```sh
curl -sS -X POST -H "Authorization: Bearer $A" -H 'content-type: application/json' \
  -d '{"reason":"wrong source document: the spec re-applied a fill that was already in the file"}' \
  $BASE/api/v1/envelopes/$ID/cancel
```

The CLI has no `cancel` verb, so this one goes direct to the API. Cancelled
envelopes keep appearing in the list, which is correct — an audit trail that
silently loses abandoned attempts hides more than it shows.

### 6. Send

```sh
pdf-go envelope send --server https://test-pdfsign.kaykraft.org --token-env RUN_KEY $ID
```

This performs `ready → sent` and queues one invitation per party. Subject
lines are built by the service as `Signature requested: ` + the title.

Two behaviours worth knowing.

**`send` ignores `--links-out`** and writes the links to
`envelope-<id>.links.json` in the current directory (mode 0600), where
`create` honours the flag. If you scripted `create` with `--links-out`, your
scripted `send` has just written a second links file somewhere else. Read the
links from one place — after send, they are `envelope-<id>.links.json`.

**`send` does not refuse a second call.** A send of an already-sent envelope
is accepted: exit 0, `status` still `sent`, party tokens unchanged, `updated_at`
moved forward, and the envelope gained further `send` events. On this run the
procedure was executed twice, so the log ended
`created, transition, transition, send, send, send`.

Whether a duplicate `send` re-queues the invitations is an operator-side
question — the mail queue is not a client endpoint, so you cannot check it
from here. Treat a retry as unsafe: guard the send in your script, and count
`send` events afterwards (exactly one is correct) so you can tell the operator
what happened if there are more.

The links themselves are the party's credential: unauthenticated by design,
the token is the secret. Fetching one returns the signing page
(`<title>Sign document</title>`); the consent checkbox and the sign button are
rendered by the page's script, so they will not appear in a raw `curl` of the
HTML.

### 7. Confirm, and report the answer

```sh
pdf-go envelope get    --server $BASE --token-env RUN_KEY $ID
pdf-go envelope report --server $BASE --token-env RUN_KEY $ID
```

The report is not a count of signatures. It is the **cryptographic** check on
the bytes:

```json
{"complete": false,
 "required_parties": 2,
 "sha256": "a19960f10f08...",
 "report": {"valid": true, "pages": 12, "errors": [],
            "signers": [{"name": "signsrv", "valid": true, "trusted": false,
                         "timestamped": true,
                         "reason": "document certified before signature collection"}]}}
```

Read it this way:

- `complete: false` while parties have not signed — expected, not a failure.
- `report.signers` lists signatures that exist **in the PDF**. Before anyone
  signs it holds exactly one: the service's certification signature. A party
  who has signed adds an entry.
- `trusted: false` is normal here. The signer is not in the client's trust
  store; the signature is still `valid`. Say this plainly rather than implying
  the document is unsigned.
- `sha256` is the value you quote when someone asks *which* PDF was signed.
  It is the certified revision's digest.

The envelope's `status` and the report's `complete` are different questions:
`sent` means invitations went out, `complete` means every party signed.

`GET /api/v1/envelopes` returns only this client's envelopes. On this run the
list held three ids: the live envelope and the two cancelled attempts. A
different client sees none of them. That isolation is per-client and it is not
configurable from your side.

## Signature placement, in one place

A signature box is 220 × 80 pt. `--widget-x` / `--widget-y` set the **first**
party's box; party `i` is placed 90 pt *above* that, so a stack grows upward
from one x. Coordinates are PDF points, origin at the **lower-left** of the
page, y upwards — the same convention as `rect` in the extract schema.

The consequences that are easy to get wrong:

- **All parties share one x.** There is no side-by-side placement. On a form
  whose signature block puts the lessor in the left column and the tenant in
  the right, one column simply cannot hold both; the stack has to run up
  through whatever is above it.
- **Running out of room is silent.** A box outside the crop box, less a 36 pt
  margin, is *clamped* inside rather than refused. For one box that is
  forgiving. For a stack it means every party after the overflow lands on the
  same highest legal y and the signatures pile on top of one another — and the
  document still signs and verifies, it just reads wrong. Placing the stack
  higher up a short page is the trap; place the base lower.
- **`--widget NAME` anchors the first party only.** The rest fall back to the
  default column. Anchoring one field and expecting a row underneath it is the
  usual surprise. Form 18A has no signature fields at all, so on this form the
  only choice is coordinates.
- **Omitting placement entirely** puts the signatures in a default column on
  **page 1** — not the last page, not the signature page. If a signed
  agreement's signatures appear bottom-left on the cover sheet, that is why.

Page 12 of Form 18A is the additional-terms page: the name and date fields sit
at y 262–306 and y 222–240, and the free bands between the printed rules are
shorter than the 170 pt a two-party stack needs. So `--widget-page 12
--widget-x 24 --widget-y 310` puts party 1 at 310–390 and party 2 at 400–480,
clear of every field and inside the page. Check the geometry of your own form
with `pdf-go extract`; do not copy these numbers.

## Rules that are not negotiable

- **Never reissue or re-mail a link without being asked.** `reissue`
  invalidates the link the party already holds: their open page becomes a 410.
- **One envelope per document version.** A changed document is a new envelope,
  never a re-send. `send` on an already-sent envelope is a 409, and that 409
  is the protection working.
- **A party that has consented has a right to sign that document.** If the
  document must change after a consent, that is a conversation, not a `cancel`.
- Quoting a `--message` is fine, but the mail the party receives is built by
  the service. Do not promise wording you have not seen.
- Delete the links files when the parties have their links. They contain live
  tokens.

## Exit codes

Same for `pdf-go` locally and over the endpoint. Measured on this run, and
matching `README.md` and `docs/skills/run-qld-contract.md`:

| code | meaning |
|---|---|
| 0 | ok. For `create`: created **and** `ready`; for `send`: accepted (see above — a send of an already-sent envelope is also 0) |
| 1 | usage, config, or a fill problem — nothing was uploaded |
| 2 | input error locally, or the **service refused**. An unknown envelope id and a missing credential both give 2 |
| 3 | partial: something was skipped, a value did not match on `verify`, or the envelope was created but is not `ready` |

Errors arrive on stderr as `{"error","source","hint"}`. A 2 usually means
"the service said no", so read the body before retrying — the `hint` names the
fix. `--strict` makes a requested-but-unapplied field a failure, which is what
a scripted caller wants.
