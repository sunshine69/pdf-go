# Run one rental contract end to end


For the same procedure from **outside** the server — no `signsrv`, no server
shell, only the endpoint and a machine key — see
[`../external-client-procedures.md`](../external-client-procedures.md).
`scripts/qld-sign-run.py` fills a Queensland tenancy PDF and creates the signing
envelope in one command. It **creates, it does not dispatch** — the envelope
lands in `ready` and an admin mails the parties from the dashboard.

```sh
python3 scripts/qld-sign-run.py <form.pdf> --data <contract.yaml>
```

## What you need

| Input | Where |
| --- | --- |
| the blank form PDF | the positional argument (or `pdf:` in the YAML — the argument wins) |
| the contract data | `--data file.yaml`, see below |
| the service URL | `SIGNSRV_URL`, or `server:` in the YAML |
| one credential | `SIGNSRV_KEY` (client key) **or** `SIGNSRV_TOKEN` (session token) |
| `pdf-go` | **required.** `$PDFGO`, else `pdf-go` on PATH, else `./tmp/pdf-go`. Or `--pdf-go /path`. Build: `go build -o tmp/pdf-go ./cmd/pdf-go` |

A client key is minted once by an admin (`POST /api/v1/admin/clients`, shown
once) and is exchanged for a 15-minute session at `POST /api/v1/auth/token` on
every run. Nothing about the credential is in the YAML, so the YAML is safe to
commit or mail.

`scripts/qld-agreement.example.yaml` is a full worked example: 41 fields, 3
parties. Copy it, do not edit it in place.

## The YAML

```yaml
pdf: forms/Form-18a-General-tenancy-agreement.pdf
server: https://test-pdfsign.kaykraft.org      # optional if SIGNSRV_URL is set

envelope:
  title: "Residential Tenancy Agreement - 12 Somewhere St"   # 200 chars max
  expires: 72h                                # link lifetime, else service default
  subject: ""                                 # stored now, used when the admin dispatches
  message: ""
  notify: ""                                  # told if a party declines

widget:                                       # where signatures go, see below
  page: 12                                    # page 12 is Form 18a's signature page
  x: 36
  y: 160                                      # on the lessor's signature line

form:                                         # FIELD: value, exact names
  Lessor name/trading name: "Brisbane Rentals Pty Ltd"
  Address of the rental premises1: "12 Somewhere St"   # note the trailing 1
  Weekly: true                                # checkbox; false really clears it
  Fixed term agreement1: true                 # trailing digit is part of the name
  Account number: "123456789"                 # maxLen 9 - longer is truncated

parties:
  - email: lessor@example.com
    name: "Brisbane Rentals Pty Ltd"
    order: 1
```

`form:` keys are the PDF's own field names. Get them from the document, never
from memory:

```sh
tmp/pdf-go extract form.pdf -o schema.json
python3 -c "import json;[print(f['name'],f['type'],f.get('maxLen')) for f in json.load(open('schema.json'))['fields']]"
```

A name the PDF does not have stops the run before anything is uploaded:

```
qld-sign-run: the PDF has no field(s): nosuchfield
  nothing was filled; list the real names with:
    tmp/pdf-go extract forms/Form-18a-General-tenancy-agreement.pdf -o schema.json
```

Values are not checked against `maxLen` before upload — `pdf-go` truncates to
fit and `verify` then fails the run if the bytes do not read back as asked,
which is the signal that text was cut. Keep values inside `maxLen`. Form 18a
limits `Account number` to 9, `BSB number` to 6, and both ABN boxes to 11.

Checkboxes take a YAML `true`/`false`. The script sends a JSON boolean and the
fill maps it to the document's own on-state — on this form every box's only mark
is `/Yes`. `false` clears the box (it used to leave the tick in place), and a
string `"true"` or `"yes"` resolves to the same `/Yes` rather than inventing an
export state called `/true` that viewers render blank. Form 18a asks for
either/or pairs (`Fixed term agreement1` vs `Periodic agreement1`, `Weekly` vs
`Monthly` vs `Fortnightly`): set the one you want `true` and the others `false`
explicitly, because an untouched box keeps whatever the PDF shipped.

## Run it

```sh
# 1. check everything without touching the service: no credential needed
python3 scripts/qld-sign-run.py forms/Form-18a-General-tenancy-agreement.pdf -d my-contract.yaml --dry-run

# 2. create
export SIGNSRV_URL=https://test-pdfsign.kaykraft.org
export SIGNSRV_KEY=key_...
python3 scripts/qld-sign-run.py forms/Form-18a-General-tenancy-agreement.pdf -d my-contract.yaml --links-out tmp/links.json
```

```
qld-sign-run: fields:  41 to fill
qld-sign-run: parties: 3 (lessor@example.com, tenant@example.com, agent@example.com)
qld-sign-run: filled:  /tmp/qld-sign-run-.../filled.pdf (157186 bytes) verified
qld-sign-run: widget:  {"page": 2, "x": 36.0, "y": 42.0}
qld-sign-run: links:   tmp/links.json (mode 0600) - 3 signing link(s), not mailed
qld-sign-run: envelope aa37fe14d2e9f78197ff7b96eecfc4ec created (ready)
qld-sign-run: service applied 41 field(s)
qld-sign-run: not dispatched: the admin sends the invitations from the dashboard
qld-sign-run: events:  created, transition
qld-sign-run: envelope aa37fe14d2e9f78197ff7b96eecfc4ec is 'ready' - filled, awaiting dispatch
```

The last two lines are the proof the job is done: `ready` is the state a create
leaves behind, and `events: created, transition` means nothing was mailed.

Then an admin dispatches — `--send` is deliberately never called:

```sh
tmp/pdf-go envelope send <envelope-id>          # or the dashboard
```

### Useful flags

| Flag | |
| --- | --- |
| `--dry-run` | fill + verify + print the payload, no network, no credential |
| `--form KEY=VALUE` | override one field, repeatable; beats the YAML |
| `--links-out FILE` | write the signing links at mode 0600 (default: not printed, nobody was mailed) |
| `--keep-dir` | keep the temp dir with the filled PDF and the spec |
| `--json` | print the service's whole answer |

### Exit codes

`0` created and `ready` · `1` usage, config or fill problem (nothing uploaded) ·
`2` the service refused · `3` created, but the envelope is not `ready`.

## Where the signature goes

Nothing is auto-detected. The service does not find a "Sign here" line and does
not pick a page: the `widget:` block decides it, and if you omit the block every
signature is drawn in a 220x80 pt box at **X=60, Y=60 on page 1** — the
bottom-left corner, over whatever else is down there. That is legal and usually
wrong on paper.

Pick one of three shapes:

```yaml
# let the script measure the page and pick the band (recommended)
widget: {auto: true}                 # last page; or {auto: true, page: 3}

# anchor party 1 on an existing field's rectangle
widget: {field: SigClient}

# or name an exact spot; every later party stacks ABOVE it
widget: {page: 2, x: 36, y: 42}
```

**`auto: true`** is the script doing the looking-for-you. The signature page is
where the party blocks are, and the last page is where they usually are — but
"usually" is not good enough, so it checks the page rather than assuming it:

- `pdf-go pages` gives the page list and sizes; `pdf-go extract` gives the
  rectangle of every form field; `pdftotext -bbox` (poppler, when installed)
  gives the position of every printed **word**, converted to PDF points.
- It then walks candidate base `y` from the bottom up and takes the first band
  where **every** party's box clears every field box and every printed word in
  that column, and where the whole `80 + 90×(parties-1)` pt stack still fits
  above `y`. `x` is the 36 pt margin, pushed left if the page is narrower than
  220+72 pt.
- What it decided is always printed, so a wrong guess is visible:

  ```
  qld-sign-run: widget:  auto -> page 2 of 2, x=36 y=36 (170 pt stack, 149 item(s) in that column)
  qld-sign-run: widget:  {"page": 2, "x": 36.0, "y": 36.0}
  ```

- When **no** band is free it does not silently pick one: it takes the
  least-crowded one and says so (`no band on page 2 holds a 260 pt stack clear
  of print; y=36 is the least crowded`). That is the honest answer on a form with
  no signature space — the fix is more room on the page, or fewer parties per
  page, not a different number in the YAML.
- Without poppler it still places the stack, avoiding the form fields only, and
  the line says `printed text not checked`.

### A placement you name is measured too

A create refuses a **field name** that is not in the document and a **page** that
does not exist, but it can never refuse an **overlap** — the boxes are not drawn
until the parties sign, so at create time there is nothing to measure. That check
is the one thing the script can do and the service cannot, so it runs on explicit
`x/y` as well, and reports without overruling:

```
qld-sign-run: widget:  page 2 x=36 y=36 - clear of print and of the form fields
qld-sign-run: widget:  32 item(s) sit under the boxes at x=36 y=430 on page 2
qld-sign-run: widget:  x=36 y=760 is outside the legal band on page 2 (A4-like
                       595x842: x <= 339, y <= 726); the service clamps it, it
                       does not refuse
qld-sign-run: widget:  2 parties need 170 pt above y=760 but page 2 ends at 842:
                       the last signatures clamp onto one row
qld-sign-run: widget:  'z35' anchors party 1 only; the other 1 fall back to the
                       default column on page 1
```

Warnings, not refusals: your `y` is your call, and a signature deliberately laid
over a blank rule line is legitimate. What is gone is the silence — every one of
those used to be discovered on paper, after three people had signed.

Field titles are how you confirm you picked the right page, and the same probe
that lists them shows what is near them:

```sh
tmp/pdf-go extract form.pdf -o s.json
# each entry: name, type, page, rect [x0 y0 x1 y1]
```

Rules, from `internal/signpdf/appearance.go`:

- **Coordinates are PDF points, origin at the LOWER-LEFT**, y increasing
  upwards — the same convention as `rect` in `extract`.
- The box is **220 x 80 pt** (~77 x 28 mm). Successive parties are placed
  `y + 90 × index` on that **same page**, so 3 parties need 260 pt of room above
  your base `y`. A stack never spreads over more than one page.
- With `field:`, **only party 1** gets the field. Parties 2 and 3 fall back to
  the default column at (60, 60 + 90×i) on page 1, because offsetting them would
  walk them off the field. With one party that is fine; with three it is a
  surprise, so prefer x/y when there is more than one signer.
- Placement is **clamped, never refused**: the box must fit inside the page's
  crop box minus a 36 pt margin, so on A4 (595x842) the legal base is
  `36 ≤ x ≤ 339` and `36 ≤ y ≤ 726`. Ask for y=730 and you silently get y=726.
  Ask for a stack taller than the page and every extra party lands on the same
  clamped row, piling up — one legible signature, not three.
- A **field name that is not in the document refuses the create** rather than
  falling back quietly, and the page number is checked against the **filled**
  document (a fill can change the page count):

  ```
  qld-sign-run: create refused: HTTP 400 {"code": "invalid_widget.field",
    "message": "signflow: widget.field: \"nosigfield\" is not a field of this document",
    "hint": "run extract on the template and use one of its field names, or leave the field empty"}
  ```

### Finding the numbers

```sh
tmp/pdf-go fields form.pdf | grep -B1 '"signature"'   # signature fields to anchor on
tmp/pdf-go pages  form.pdf                            # page sizes and crop boxes
tmp/pdf-go extract form.pdf -o s.json                 # rect [x0 y0 x1 y1] of every widget
```

The repo's form is the real thing: `forms/Form-18a-General-tenancy-agreement.pdf`,
the RTA's general tenancy agreement (Form 18a), downloaded from
`https://www.rta.qld.gov.au/sites/default/files/2021-06/Form-18a-General-tenancy-agreement.pdf`
— 12 pages, 135 fields (94 text, 39 checkbox, 2 pushbutton), and **no signature
form-field anywhere**, so x/y or auto is the only honest choice. Page 12 is the
signature page: a 2x2 grid of slots, lessor and tenant 1 on top, tenants 2 and 3
below. Its names are human-readable (`Lessor address`, `Rent amount`) but exact —
trailing digits on repeated boxes (`Lessor address2`), literal apostrophes
(`Lessor's agent ABN (optional)1`), and the RTA's own typos (`facsimilie`).

Measured on page 12 (A4 595x842, legal base `x 36–339`, `y 36–726`): the
"Signature" labels sit at y 240–252 and y 84–96, the print-name boxes are fields
at y 262–306 and y 104–149, the date boxes at y 222–241 and y 65–85. **No band
on that page is both field-free and word-free** — a signature page is dense by
design. So `auto: true` says so out loud:

```
widget:  no band on page 12 holds a 170 pt stack clear of print; y=411 is the
         least crowded (1 item(s) under the first box)
```

y=411 is the Special terms box, which is the wrong answer arrived at honestly —
that is why the shipped example states the spot instead:

```yaml
widget: {page: 12, x: 36, y: 160}   # party 1 on the lessor's signature line
```

A box based at y=160 spans y 160–240: it lands on the lessor's signature rule
and stops exactly where the "Signature" label begins. The script still warns
(`8 item(s) sit under the boxes`) because the tenant-2 name box and its labels
are in that column; on a signature page that overlap is the point, not a
mistake. The service stacks **upward** at a fixed x, so party 2 lands at y 250
and does cover the "Name/trading name" label — the form's 2-column grid and the
service's 1-column stack cannot both be satisfied. More than two parties in one
stack is worse; sign per role, or accept the labels under the signatures.

A create does **not** check the stack for overlap — nothing can, the boxes are
not drawn until the parties sign. So after the first run on a new form, dispatch
one envelope, sign it, and look:

```sh
tmp/pdf-go envelope report <id>          # proves the signature is valid, not that
                                         # the placement is sane
tmp/pdf-go extract signed.pdf -o s.json  # rect of each signature widget
```

The report's validity and a signature sitting on top of a party's printed name
are entirely compatible outcomes.

What that check actually returns on the run above (`page: 2, x: 36, y: 36`,
three parties):

```
Signature 1  page=None rect=[0,0,0,0]      # the document certification, not a box
Signature 2  page=2    rect=[36,  36, 256, 116]   -> 0 printed words covered
Signature 3  page=2    rect=[36, 126, 256, 206]   -> 0 printed words covered
Signature 4  page=2    rect=[36, 216, 256, 296]   -> 31 printed words covered
```

Two things worth knowing:

- **One extra signature field than you have parties.** `Signature 1` carries no
  page and no rectangle — it is the document-level certification, added per
  envelope. Count the parties from the ones that have a `page`.
- The stack is **exactly** `y + 90 × index`, and the last box is the one that
  runs into the form. That is why the base `y` goes low on the page and why
  `auto` measures the whole 260 pt band rather than the first 80 pt.

## When the service refuses

| Answer | Cause |
| --- | --- |
| `HTTP 401` at `/api/v1/auth/token` | wrong or revoked `SIGNSRV_KEY` |
| `HTTP 403` on create | the client lacks `envelope:write` |
| `invalid_title` / `title too long` | over 200 characters |
| `invalid_spec.fill "empty"` | the `form:` block produced no values |
| `invalid_widget.field` / `.page` | placement does not exist in the **filled** document |
| `HTTP 429` / `500` | retried up to 3 times with backoff |
| `HTTP 502/503/504` | **not retried** — no idempotency key, so the run refuses to guess. Check `GET /api/v1/envelopes` before re-running |
| `no credential: set SIGNSRV_KEY` | neither env var is set; the run stopped before the network |
| `no pdf-go at ...` / `no pdf-go found` | nothing was built or installed; the script fills through it, so it cannot run without it |

## When the two pdf-go binaries disagree

The script fills locally, and the **service fills its own copy of the template
again** from the spec it was sent. So there are two implementations of `fill`
that have to agree about the document: the local binary and the server's build.
The run prints the binary it used, and warns when the counts diverge:

```
qld-sign-run: pdf-go:  /home/stevek/.local/bin/pdf-go
qld-sign-run: WARNING: asked for 41 field(s), the service applied 39. The local
                pdf-go (...) and the service do not see the same form - rebuild
                it, and re-check the names with 'extract'
```

Two traps, both real on this machine: an installed `pdf-go` on PATH is found
before `tmp/pdf-go`, and they are **different builds** — same form, 33 bytes
apart in the output. If you have both, say which one you mean with `--pdf-go` or
`PDFGO`. And the placement checks above run against the **template**; the service
validates the placement against the **filled** document, because a fill can
change the page count. Both are reported the same way: the run stops before
uploading, or refuses the create.
