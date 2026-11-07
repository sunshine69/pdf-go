# Skill: prepare a contract PDF and dispatch it for signing

Two binaries. `pdf-go` prepares the document and drives the service. `signsrv`
is the service (API + signing pages + worker). Read `README-signing.md` for a
full run; this file is the shortest path that works.

## 0. Prerequisites

```sh
go build -o tmp/signsrv ./cmd/signsrv && go build -o tmp/pdf-go ./cmd/pdf-go
tmp/signsrv checkconfig -config <conf>     # must end with "config ok"
nohup tmp/signsrv serve -config <conf> > serve.log 2>&1 &
```

Machine key for the CLI (printed once, store it in the environment):

```sh
tmp/signsrv client add "contract-desk" "envelope:write envelope:read" -config <conf>
export SIGNSRV_URL=https://pdfsign.kaykraft.org SIGNSRV_TOKEN=key_...
```

`http://` needs `--insecure`; a real run must use the `https://` public URL.

## 1. Read the form (never guess a field name)

```sh
tmp/pdf-go fields contract.pdf          # compact list
tmp/pdf-go extract contract.pdf -o schema.json   # names, types, allowed values, geometry
```

Only AcroForm fields are fillable. A scanned PDF with no fields cannot be
signed — stop and ask for a form-bearing file.

## 2. Write the fill spec

`fill.json` — only the fields you change; every name must come from step 1:

```json
{"values": {"Text1": "Steve Kieu", "Text2": "2026-11-07", "Text4": "NDA-2026-11"}}
```

Check before dispatching: `tmp/pdf-go fill fill.json contract.pdf -o out.pdf && tmp/pdf-go verify out.pdf fill.json` (exit 0 = matches).

## 3. Write the parties

`parties.json` — one entry per signer, `order` is the signing order, emails
unique, no `\r\n` in a name (rejected at create):

```json
[{"email": "msh.computing@gmail.com", "name": "Steve Kieu", "order": 1},
 {"email": "kaycaonz@gmail.com",      "name": "Kay Kao",   "order": 2}]
```

## 4. Create and dispatch (one command)

```sh
tmp/pdf-go envelope create --spec fill.json --parties parties.json \
  --title "NDA 2026-11" --subject "Signature requested: NDA 2026-11" \
  --message "Please review and sign." --expires 72h \
  --links-out links.json --send contract.pdf
```

`--send` transitions `ready -> sent` and queues one invite per party. Without
`--send` nothing is mailed. Signing links are returned **once**, by this
command only: `links.json` is mode 0600, delete it once the parties have them.
A second send of the same envelope is 409.

## 5. Confirm it left

```sh
sqlite3 <db> "select status from envelopes where id='<id>';"                       # sent
sqlite3 <db> "select kind,attempts,sent_at,last_error from mail_queue
              where envelope_id='<id>';"                                           # sent, 1, <time>, empty
tmp/pdf-go envelope get <id> --watch        # polls until the envelope settles
```

Mail failure does not fail the send: it marks `mail_failed` and retries 5x.

## 6. After everyone signs

```sh
tmp/pdf-go envelope report <id>     # signers, validity, TSA stamp, errors: []
```

`complete: true` with every signer `valid: true` is the pass condition.

## Rules an agent must not break

- Never reissue or re-mail a signing link; it is single-party and expiring.
- Never put a token, a key, or a link into a log, a commit, or a chat reply.
- One envelope per document version: a changed document is a new envelope, not
  a re-send of the old one.
- A party that already consented or declined has no second consent; if they
  declined, create a new envelope.
- The signing page on a phone shows no inline PDF frame (Chrome on Android
  renders it blank) — the party uses **Open the document** or **Download to
  review**, then returns to sign. Tell the signer this if they report a blank
  area; it is not an error.
