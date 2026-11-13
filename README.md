# pdf-go

A generic PDF tool for scripted use: read the form metadata of a document as
JSON, write the form back from JSON, stamp images and text at exact positions,
and read the result back to check it.

This module also builds `signsrv`, a document signing service that uses
`internal/pdf` as a library.

**Working on the service?** Read [docs/QUICK-START.md](docs/QUICK-START.md)
first: package map, the life of a document, the auth model, where to change
what, and the known pitfalls. Then [README-signing.md](README-signing.md) to run
it, and [docs/](docs/) for everything else — that index says which docs are
current and which are historical design records.

It uses the pure-Go PDF library `github.com/benoitkugler/pdf`, so
there is no cgo, no external binary and no shared library to install.

```
pdf-go extract  <in.pdf>   [-o schema.json]      read the AcroForm
pdf-go fill     <spec.json> [in.pdf] [-o out.pdf] write the form, logos, paints
pdf-go verify  <out.pdf>   [spec.json]            read it back and compare
pdf-go fields  <in.pdf>    [-page N]              compact field listing
pdf-go pages   <in.pdf>    [--page 1,3-5]        page boxes and geometry
pdf-go add-logo <in.pdf> <img> [--page 1 --position top-right]
pdf-go append   <in.pdf> [--from notes.md] [-o out.pdf]  typeset text onto new pages
pdf-go insert   <in.pdf> --from notes.md --at N          ... at a chosen position
pdf-go doc                                        full JSON reference
```

## The loop

```sh
pdf-go extract form.pdf -o spec.json
# edit spec.json: set "value" on the entries you care about
pdf-go fill spec.json -o filled.pdf
pdf-go verify filled.pdf spec.json
```

`extract` output *is* `fill` input: the schema carries the `source` path, so
the document argument is optional and no translation step is needed.

A minimal spec is `{"values":{"form[0].name":"Ada","agree":true}}`.

Values by type: `text` string, `checkbox` true/false (or an on-state from
`states`), `radio` the export value of the button to switch on (set it on the
group), `combo`/`choice` one of `options` (array when multi-select). Signature
and push-button fields cannot be filled: stamp artwork on them.

## Graphics

A logo is an image drawn as page content (bar codes, QR codes, logos,
signatures). A paint is text baked into the page (stamps, reference numbers,
dates). Both accept `"field"`, `"rect"`, or `"page"+"box"+"position"`, in that
priority order:

```json
{
  "logos":  [{ "id": "qr", "image": "qr.png", "field": "qrField" },
             { "image": "logo.png", "page": 1, "box": "crop",
               "position": "bottom-right", "width": 120, "margin": 18 }],
  "paints": [{ "text": "PAID IN FULL", "page": 1, "box": "crop",
               "position": "top-right", "font": "Helvetica-Bold",
               "size": 16, "color": "#B00000", "align": "right" }]
}
```

Coordinates are PDF points: origin lower-left, y upwards, `rect` is
`[x0 y0 x1 y1]`. `pdf-go pages` prints the boxes of every page. Prefer the
`crop` box: the media box is the paper, the crop box is what gets printed.

## Appending pages

`append` typesets Markdown, HTML or plain text and splices the result in as new
pages. Added pages copy the size and rotation of the page they follow, so an
annex matches the document it joins rather than assuming A4.

```sh
pdf-go append signed.pdf --from terms.md --title "Schedule 2" -o final.pdf
pdf-go insert signed.pdf --from note.txt --at 2   # after the third page
```

Text runs from `--from FILE` (`-` for stdin) or `--text`. The format is taken
from the file extension, defaulting to Markdown. The report says which page the
annex starts on (`at`), how many pages were added and how many lines were
typeset.

Content that does not fit goes on further pages; nothing is clipped and nothing
is dropped. Because the standard 14 fonts cover Latin-1 only, characters they
cannot draw (CJK, Cyrillic, Greek, emoji) are reported as warnings and written
as `.`; `--strict` makes them a failure instead of a quiet substitution.

Appending changes the document, so it happens before signing: append first,
then send the envelope.

## Reports and exit codes

`fill` and `extract` print JSON. A report lists what was `applied`, what was
`skipped` and why, per-field `notes` (value clipped to maxLen, characters the
field font cannot draw, a value outside the allowed list), and where each logo
and paint landed. Errors go to stderr as `{"error","source","hint"}`.

`0` ok · `1` usage · `2` input error · `3` partial (something was skipped, or a
value did not match on `verify`).

`--strict` turns a requested-but-unapplied field, logo or paint into a
failure, which is what a scripted caller usually wants. `-q` reports nothing on
stdout and only sets the exit code.

Appearances are baked into the output, so the file prints the same everywhere;
the form stays editable unless the spec sets `"lockForm": true`.

## Layout

- `cmd/pdf-go` — CLI: commands, flags, JSON reports.
- `internal/schema` — the JSON contract shared by `extract` and `fill`.
- `internal/pdf` — AcroForm reading, value conversion, appearance generation,
  boxes/anchoring, image stamps, painted text.
- `internal/report` — the report envelopes.
- `testdata` — sample forms from the library test suite (MIT).

`go test ./cmd/pdf-go` covers extract → fill → verify, the schema
round-trip, strict mode, geometry, stamps and paints.
