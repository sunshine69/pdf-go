# Skill: prepare a contract PDF and dispatch it for signing

Two binaries. `pdf-go` prepares the document and drives the service. `signsrv`
is the service (API + signing pages + worker). `README-signing.md` is the full
run, `docs/runbook-e2e.md` is the automated one.

There are two ways to do this and both work. **The API route (next section) is
the default**: four HTTP requests, no binary to build, nothing installed beyond
`curl` and `jq`. The CLI route (section 0 onward) is the same operation wrapped
in `pdf-go`, useful when you want the fill verified locally before anything is
sent. Read the API section even if you use the CLI — the checks and the failure
modes are the same ones.

Every command below is one that has been run against a live server and is
quoted from that run. Flags are Go-style: `-flag value`, and `--flag` works
too. **Flags go before positional arguments** — Go's parser stops at the first
non-flag word, so `-send file.pdf` is the shape, never `file.pdf -send`.

## The procedure: fill and dispatch, API only

This is the whole operation, and it is what has been run against production.
An agent should follow this section and need nothing else: one login, the PDF on
disk, four requests. Nothing fills or sends a document outside the API: no
machine key, no browser, and no `pdf-go` in the dispatch path. The one place a
local tool helps is reading the field names in step 2, which is optional.

**1. Log in.** The admin password is enough; no client key is needed for any of
this.

```sh
A=$(curl -sS -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" \
  https://host.example/api/v1/auth/login | jq -r .access)
```

An admin token answers with `scopes: ["admin:read"]` and the middleware treats
that as carrying every scope, so it reaches the envelope routes directly. Do not
be fooled by the single scope name — it is not a restriction. A machine key
(`signsrv client add`, or `POST /api/v1/admin/clients`) exists to grant a caller
*less* than an admin, or to avoid holding a human password. It is never a
prerequisite for filling or dispatching.

**2. Get the field names.** Never guess them. The server does not expose a
field-listing route, so read them from the local file:

```sh
pdf-go extract contract.pdf -o schema.json   # stdout is a human report, not JSON
jq -r '.fields[].name' schema.json
```

Use only names from this output. A name that is not in the form is a hard
error, not a silent skip: the fill fails with `unknown field "…"; run extract to
list the available fields` and the envelope is not created. That error is the
fast path back to step 2.

**3. Create, fill and address in ONE request.** The service fills the form
itself; nothing is filled locally.

```sh
curl -sS -X POST -H "Authorization: Bearer $A" \
  -F "template=@contract.pdf;type=application/pdf" \
  -F "title=Supply agreement - Steve Kieu" \
  -F "spec=<spec.json" -F "parties=<parties.json" \
  https://host.example/api/v1/envelopes
```

- `spec.json` is `{"fill":{"values":{"Text1":"Kaykraft Pty Ltd", …}}}`.
  `widget` and `subject` are optional siblings of `fill`.
- `parties.json` is `[{"email":"…","name":"…","order":1,"title":"…"}]`, and
  `title` may be omitted.
- Pass both with `-F "name=<file"`, **not** `-F "name=@file"`. `@` produces a
  file part, Go's `FormValue` ignores file parts, and you get a 400 that says a
  field is required when the field is plainly present. This is the single most
  common way to get this wrong.

A `201` returns the envelope, `fill.applied` (the fields the server actually
wrote) and the party links inline in `links[].url`. Check that `applied` lists
every field you meant to fill, and `fill.lockedForm: true` (the form is sealed
so nothing can be changed under a signature).

**4. Send.** `POST /api/v1/envelopes/{id}/send` with the bearer token. The party
routes after that are public, under `/api/v1/sign/{token}`: `claim` (with the
email address), `envelope` (carries `document_sha`), and `consent` with
`{consent:true, document_sha, signature_text, image}` where `image` is a
`data:image/png;base64,…` string. The link alone, without a claim, yields the
title and deadline and nothing else.

**5. Confirm the invitation left, and confirm the signature.** `send` returning
`200` says the request was accepted, not that mail arrived. Read
`GET /api/v1/envelopes/{id}` and the party row: status `sent` means queued,
`claimed` means the party opened the link. Then `GET /api/v1/envelopes/{id}/report`
— the pass condition is `complete: true` with every signer `valid: true` and
`errors: []` — and `GET …/audit.zip` for the evidence bundle. Event rows use
the key `kind`, not `type`.

Do not report a signing job as done on the strength of a `201`. Report it on the
strength of `complete: true`.

A server started with `dev=true` creates the admin account itself (`dev@localhost`)
when the database has no admins, and logs the password it set. It is the only case
where the service creates a login for you; production never does. See
`docs/CONFIG.md`.


## 0. Build, configure, serve

```sh
go build -o tmp/signsrv ./cmd/signsrv
go build -o tmp/pdf-go  ./cmd/pdf-go
go build -o tmp/mock-tsa ./cmd/mock-tsa   # offline timestamping only
./tmp/signsrv checkconfig -config tmp/prod.conf     # must print "config ok"
nohup ./tmp/signsrv serve -config tmp/prod.conf >> tmp/real/stdout.log 2>&1 &
curl -sS -o tmp/health.txt -w '%{http_code}\n' http://127.0.0.1:8090/healthz
```

The config file the service reads is a `key=value` file, mode 0600. The three
lines that decide what the signer receives:

| key | what it does |
|---|---|
| `listen` | the socket. `127.0.0.1:8090` behind a TLS proxy; `0.0.0.0:8090` when the process is the edge |
| `public_url` | the base of every signing link **in the email**. Set it to the URL the party can actually reach, or the link in the mail is dead |
| `trust_proxy` | `true` only behind a proxy that sets `X-Forwarded-For`; the audit trail's IP depends on it |

A real run also needs `smtp_host`, `smtp_user`, `smtp_pass`, `mail_from` (or the
invites go to `outbox_dir` as `.eml` files instead of to inboxes) and `dev=false`
with a real `tsa_url`.

## 1. A machine key for the CLI (printed once)

```sh
./tmp/signsrv client add cli-run envelope:write envelope:read -config tmp/prod.conf
```

Scopes are **separate arguments**, not one quoted string. The key is printed
once and cannot be recovered; put it in a file of mode 0600, never in a shell
history line, a log, a commit, or a chat reply:

```sh
awk -F': ' '/^key: /{print $2}' run/client.txt > run/client.key; chmod 600 run/client.key
```

`envelope:write` covers create and send; `envelope:read` covers the envelope
view and the report. `signsrv user add` is for **human** operators (the admin
UI); it does not create a CLI key.

## 2. Read the form — never guess a field name

```sh
./tmp/pdf-go extract testdata/sample2.pdf -o run/schema.json
jq -r '.fields[] | select(.type=="text") | .name' run/schema.json
```

`extract` prints field count and types; the JSON has every name, type, current
value, allowed values, flags and geometry. Only AcroForm fields are fillable. A
scanned PDF with no fields cannot be signed — stop and ask for a form-bearing
file.

## 3. Write the fill spec

`fill.json` — only the fields you set; every name must come from step 2:

```json
{"values": {"Text1": "Steve Kieu", "Text2": "2026-11-08", "Text3": "USD 12,400"}}
```

Then fill and verify before anything is mailed:

```sh
./tmp/pdf-go fill run/fill.json testdata/sample2.pdf -o run/filled.pdf
./tmp/pdf-go fields run/filled.pdf      # the values are in the output
```

`fill` reports each applied field and any `notes` (a value that does not fit
the box is a note, not a failure — read them).

## 4. Write the parties

One entry per signer. `order` is the signing order; emails are unique; a name
containing `\r\n` is rejected at create, because it rides a mail header:

```json
[{"email": "msh.computing@gmail.com", "name": "Steve Kieu", "order": 1}]
```

`reason` is optional and is the sentence shown beside the checkbox on the
signing page.

## 5. Create and dispatch — one command, one document, one version

```sh
RUN_KEY=$(cat run/client.key) ./tmp/pdf-go envelope create \
  -server https://pdfsign.kaykraft.org -token-env RUN_KEY \
  -title "Supply agreement - Steve Kieu" \
  -subject "One document is waiting for your signature" \
  -message "Please review and sign. The link expires in 72 hours." \
  -expires 72h -spec run/fill.json -parties run/parties.json \
  -links-out run/links.json -send testdata/sample2.pdf
```

The document is the positional argument; `-spec` applies `fill.json` server-side
so the certified bytes are the filled ones. `-send` performs the `ready -> sent`
transition and queues one invitation per party. **Without `-send` nothing is
mailed** and the parties have nothing to act on.

The answer carries the envelope id, and `-links-out` writes the signing links
(mode 0600). The links are printed once. `-insecure` is required for an
`http://` server URL and never for `https://`.

For an offline run, add a local TSA and a dev listener, and point
`-server http://127.0.0.1:<port>` at it with `-insecure`; the invitations are
then written as `.eml` files in `outbox_dir`, and `grep -o '/s/[a-z0-9]*'
outbox/*.eml` recovers the link.

## 6. Confirm the invitation left

```sh
TOK=$(curl -sS -X POST -H 'Content-Type: application/json' \
      -d "{\"key\":\"$(cat run/client.key)\"}" \
      http://127.0.0.1:8090/api/v1/auth/token | jq -r .access)
curl -sS -H "Authorization: Bearer $TOK" \
  http://127.0.0.1:8090/api/v1/envelopes/<id> \
  | jq -c '{status, parties: [.parties[] | {email, name, status}]}'
```

`status: "sent"` and one party per line is the pass. Then:

```sh
./tmp/pdf-go envelope get <id> -server URL -token-env RUN_KEY --watch
```

**Exchange the key once and reuse the bearer token.** The exchange is limited
per source address; a CLI call per shell command spends that budget and the
answer is a 429 that looks like a server fault.

Mail failure does not fail the send: the queue row is marked `mail_failed` and
retried. Check the row, not just the envelope:

```sh
sqlite3 tmp/real/signsrv.db "select kind,attempts,sent_at,last_error
  from mail_queue where envelope_id='<id>';"
```

## 7. What the party does (tell them this before they ask)

The link opens the signing page. The party types their email — it must match
the invitation exactly — which **claims** the link and sets the session cookie;
every later call on that link needs the session, not the link.

On a phone the inline PDF frame is blank (Chrome on Android). The party uses
**Open the document** or **Download to review**, reads it, and returns to sign.
That is not an error.

The party ticks the consent box, draws or types the signature, and submits.
Consent is one-shot: a consented party who reloads sees the record, not a second
form, and cannot sign again.

## 8. After everyone signs

```sh
./tmp/pdf-go envelope report <id> -server URL -token-env RUN_KEY
```

`complete: true` with every signer `valid: true` and `errors: []` is the pass
condition. The signed PDF and the receipt are delivered to each party; the
receipt names the digest, the certificate serial and the TSA stamp.

## Rules an agent must not break

- Never reissue or re-mail a signing link without being asked. `reissue`
  invalidates the link the party is holding: their open page becomes a 410.
- One envelope per document version. A changed document is a new envelope, not
  a re-send. `send` on a sent envelope is a 409.
- A party that consented has no second consent; a party that declined ends the
  envelope. Start a new envelope.
- No token, key, link, password, or session cookie in a log, a commit, a
  screenshot, or a chat reply. `links.json` and `client.key` are mode 0600 and
  get deleted when the run is over.
- `dev=true` allows a plain-HTTP loopback listener and writes invites to
  `outbox_dir`. It is never a production setting.
- The timestamps in an invitation and in every API answer are **UTC**, rendered
  with a literal `Z` (`2026-11-10T22:28:45Z`). The service's own log lines are
  local (`+10:00`). A signer in another zone reads a UTC deadline as a local
  one and can be up to a day off: state the deadline in the party's own words
  in the `-message` text, and do not trust the machine stamp to be understood.

## What the service guarantees (so a check is aimed at the right thing)

- The link token is minted at **create**. `send` reuses it while the same
  process still holds the plaintext; a process that restarted mints a fresh one
  and re-hashes it. The gate on a party acting is the **status**, not the
  token: a `ready` request resolves its link, shows a page, and refuses consent
  (409).
- A signing link on its own buys the title and the deadline only — no status,
  no digest, no signer list. Those require a claim, which requires the email
  address.
- The consent image's type comes from the bytes, never from the label in the
  data URL; a GIF under a `jpeg:` label is refused, and a PNG under a `jpeg:`
  label is stored as the PNG it is.
- The consent row records the digest it was given, the timestamp, the IP and
  the user agent, and writes no PDF.
