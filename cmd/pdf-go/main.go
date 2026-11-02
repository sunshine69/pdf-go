// Command pdf-go is a generic PDF tool: it extracts the form metadata of a
// document as JSON, fills that form back from JSON, and stamps graphics
// (logos, bar codes, QR codes, signatures) at precise positions.
//
// The JSON formats are documented by `pdf-go doc`, which prints a
// machine-readable guide; the shapes are designed so a program - typically a
// language model - can probe a document, decide on values, and write it back
// in one round trip.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sunshine69/pdf-go/internal/pdf"
	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/schema"
)

const version = "0.1.0"

func main() {
	// The PDF library reports unencodable glyphs with log.Printf. That is
	// noise for a JSON tool: every message we care about is written to
	// stderr ourselves, and a glyph we cannot draw is reported as a note.
	log.SetOutput(io.Discard)
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return report.Usage
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "extract", "probe":
		return runExtract(rest)
	case "fill", "write":
		return runFill(rest)
	case "fields":
		return runFields(rest)
	case "verify", "check":
		return runVerify(rest)
	case "pages", "boxes", "geometry":
		return runPages(rest)
	case "add-logo", "stamp", "logo":
		return runAddLogo(rest)
	case "doc", "guide":
		fmt.Print(guide)
		return report.OK
	case "version", "-v", "--version":
		fmt.Println("pdf-go", version)
		return report.OK
	case "help", "-h", "--help":
		usage()
		return report.OK
	default:
		fmt.Fprintf(os.Stderr, "pdf-go: unknown command %q\n\n", cmd)
		usage()
		return report.Usage
	}
}

func usage() {
	fmt.Println(`pdf-go - generic PDF tools

  pdf-go extract <in.pdf> [-o schema.json]
      Read the AcroForm: one entry per field with its name, type, current
      value, allowed values, flags and geometry. Without -o the schema goes
      to stdout. This is the probe step.

  pdf-go fill <spec.json> [in.pdf] [-o out.pdf]
      Write the form back. The spec is either the schema produced by extract
      with values filled in, or {"values":{"name":value}}. When in.pdf is
      omitted the "source" recorded in the schema is used. Logos and painted
      text in the same spec are stamped in the same pass.

  pdf-go verify <out.pdf> [spec.json]
      Read the filled document back and compare every requested value. Exit 0
      when it matches, 3 when a value differs or a field is missing.

  pdf-go fields <in.pdf> [-page N]
      Compact field listing, for quick probing.

  pdf-go pages <in.pdf> [--page 1,3-5] [-o pages.json]
      Page geometry: media, crop, trim, bleed, art and content boxes in PDF
      points, plus page size, rotation and how many widgets each page carries.
      Use it to place logos and painted text.

  pdf-go add-logo <in.pdf> <image> [-o out.pdf]
      Stamp one image. --page, --rect x,y,w,h, --position
      (top-left, center, bottom-right, ...) and --box
      (media, crop, trim, bleed, art, content, header, footer) place it;
      --field NAME anchors it on the widget of a form field.

  pdf-go doc
      The JSON formats in full detail. Start here if you are an agent.

  pdf-go version

Options
  -o FILE   output file (stdout for extract, <in>-filled.pdf for fill)
  -p PASS   decrypt the input with this user password
  -s        strict: fail when a requested field, logo or paint is invalid
  -q        quiet: report nothing on stdout, only set the exit code
  --page N  page number, or a list like 1,3-5 (pages, add-logo)

Exit codes: 0 ok, 1 usage, 2 input error, 3 partial (some fields skipped)`)
}

// ---------------------------------------------------------------- extract ---

func runExtract(args []string) int {
	fs, err := parseFlags(args)
	if err != nil {
		return fail(err, "")
	}
	if fs.positional < 1 {
		fmt.Fprintln(os.Stderr, "usage: pdf-go extract <in.pdf> [-o schema.json]")
		return report.Usage
	}
	in := fs.args[0]

	schemaData, err := pdf.Extract(in, fs.password)
	if err != nil {
		return fail(err, in)
	}
	schemaData.Fields = sortedFields(schemaData.Fields)

	if fs.output == "" {
		if err := writeJSON(os.Stdout, schemaData); err != nil {
			return fail(err, "")
		}
		return report.OK
	}
	if err := writeJSONFile(fs.output, schemaData); err != nil {
		return fail(err, fs.output)
	}

	byType := map[string]int{}
	for _, f := range schemaData.Fields {
		byType[f.Type]++
	}
	r := report.ExtractReport{
		Source: in, Schema: fs.output, FieldCount: schemaData.FieldCount,
		ByType: byType, NeedsAppearances: schemaData.NeedsAppearances,
		Warnings: schemaData.Warnings,
	}
	if fs.quiet {
		return report.OK
	}
	if err := writeJSON(os.Stdout, r); err != nil {
		return fail(err, fs.output)
	}
	return report.OK
}

// ----------------------------------------------------------------- fields ---

func runFields(args []string) int {
	fs, err := parseFlags(args)
	if err != nil {
		return fail(err, "")
	}
	if fs.positional < 1 {
		fmt.Fprintln(os.Stderr, "usage: pdf-go fields <in.pdf> [-page N]")
		return report.Usage
	}
	in := fs.args[0]
	schemaData, err := pdf.Extract(in, fs.password)
	if err != nil {
		return fail(err, in)
	}
	type row struct {
		Name  string    `json:"name"`
		Type  string    `json:"type"`
		Value string    `json:"value,omitempty"`
		Page  int       `json:"page,omitempty"`
		Rect  []float64 `json:"rect,omitempty"`
	}
	limit := fs.page
	out := struct {
		Source     string `json:"source"`
		FieldCount int    `json:"fieldCount"`
		Fields     []row  `json:"fields"`
	}{Source: in, FieldCount: schemaData.FieldCount}
	for _, f := range sortedFields(schemaData.Fields) {
		if limit > 0 && f.Page != limit {
			continue
		}
		out.Fields = append(out.Fields, row{Name: f.Name, Type: f.Type, Value: f.Value, Page: f.Page, Rect: f.Rect})
	}
	out.FieldCount = len(out.Fields)
	if err := writeJSON(os.Stdout, out); err != nil {
		return fail(err, "")
	}
	return report.OK
}

// ------------------------------------------------------------------- fill ---

func runFill(args []string) int {
	fs, err := parseFlags(args)
	if err != nil {
		return fail(err, "")
	}
	if fs.positional < 1 {
		fmt.Fprintln(os.Stderr, "usage: pdf-go fill <values.json> [in.pdf] [-o out.pdf]")
		return report.Usage
	}
	// The schema written by `extract` carries its own source path, so the
	// document argument is optional: pdf-go fill form.json -o out.pdf
	// fills the file the schema was extracted from.
	var specPath, in string
	specPath = fs.args[0]
	if fs.positional >= 2 {
		in = fs.args[1]
	}

	spec, err := readSpec(specPath)
	if err != nil {
		return fail(err, specPath)
	}
	if in == "" {
		in = spec.Source
	}
	if in == "" {
		return fail(fmt.Errorf("no input PDF: give a document, or a schema with a \"source\""), specPath)
	}
	out := fs.output
	if out == "" {
		out = strings.TrimSuffix(in, filepath.Ext(in)) + "-filled.pdf"
	}

	status, rep := fillDocument(in, out, specPath, spec, fs)
	if status != report.OK {
		return status
	}
	if fs.quiet {
		return report.OK
	}
	if err := writeJSON(os.Stdout, rep); err != nil {
		return fail(err, "")
	}
	if len(rep.Skipped) > 0 {
		return report.Partial
	}
	return report.OK
}

func fillDocument(in, out, specPath string, spec schema.FillSpec, fs *flagSet) (int, report.FillReport) {
	rep := report.FillReport{Source: in, Output: out, Spec: specPath, Locked: spec.LockForm}

	doc, _, err := pdf.Load(in, fs.password)
	if err != nil {
		return fail(err, in), rep
	}
	schemaData, err := pdf.Extract(in, fs.password)
	if err != nil {
		return fail(err, in), rep
	}

	values := map[string]any{}
	for k, v := range spec.Values {
		values[k] = v
	}

	applied, notes, err := pdf.FillDoc(doc, schemaData.Fields, values, spec.LockForm)
	rep.Applied, rep.Notes = applied, notes
	if err != nil {
		// Report the fields we did apply, so a caller can resume.
		for _, name := range missing(values, applied) {
			rep.Skipped = append(rep.Skipped, report.SkippedField{Name: name, Reason: "not applied"})
		}
		if fs.strict {
			return fail(err, in), rep
		}
		rep.Warnings = append(rep.Warnings, err.Error())
	}
	rep.Skipped = append(rep.Skipped, skippedButtons(schemaData.Fields, values, applied)...)

	// Logos, bar codes, QR codes, signatures.
	pages := doc.Catalog.Pages.Flatten()
	annotPage := pdf.AnnotPages(doc)
	targets := pdf.Targets(doc)
	for _, l := range spec.Logos {
		var target *pdf.FieldTarget
		if l.Field != "" {
			t, resolved, found := pdf.LookupTarget(targets, l.Field)
			if !found {
				msg := fmt.Sprintf("logo %s: unknown field %q", logoLabel(l), l.Field)
				if fs.strict {
					return fail(fmt.Errorf("%s", msg), in), rep
				}
				rep.Warnings = append(rep.Warnings, msg)
				continue
			}
			t.Name = resolved
			target = &t
		}
		pageIdx, err := pdf.LogoPage(pages, l, pageOf(target))
		if err != nil {
			if fs.strict {
				return fail(err, in), rep
			}
			rep.Warnings = append(rep.Warnings, err.Error())
			continue
		}
		page := pages[pageIdx-1]
		place, err := pdf.StampLogo(pageIdx, page, l, target)
		if err != nil {
			if fs.strict {
				return fail(err, in), rep
			}
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("logo %s: %s", logoLabel(l), err))
			continue
		}
		rep.Logos = append(rep.Logos, report.LogoReport{
			ID: place.ID, Page: place.Page, Box: place.Box, Position: place.Position,
			Field: place.Field, Rect: place.Rect, Size: place.Size,
			Rotate: place.Rotate, Note: place.Note,
		})
	}
	_ = annotPage

	// Text stamped directly on pages.
	for _, p := range spec.Paints {
		var target *pdf.FieldTarget
		if p.Field != "" {
			t, resolved, found := pdf.LookupTarget(targets, p.Field)
			if !found {
				msg := fmt.Sprintf("paint %s: unknown field %q", paintLabel(p), p.Field)
				if fs.strict {
					return fail(fmt.Errorf("%s", msg), in), rep
				}
				rep.Warnings = append(rep.Warnings, msg)
				continue
			}
			t.Name = resolved
			target = &t
		}
		pageIdx, err := pdf.PaintPage(pages, p, pageOf(target))
		if err != nil {
			if fs.strict {
				return fail(err, in), rep
			}
			rep.Warnings = append(rep.Warnings, err.Error())
			continue
		}
		place, err := pdf.PaintText(pageIdx, pages[pageIdx-1], p, target)
		if err != nil {
			if fs.strict {
				return fail(err, in), rep
			}
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("paint %s: %s", paintLabel(p), err))
			continue
		}
		rep.Paints = append(rep.Paints, report.PaintReport{
			ID: place.ID, Page: place.Page, Box: place.Box, Position: place.Position,
			Field: place.Field, Rect: place.Rect, Lines: place.Lines,
			Size: place.Size, Font: place.Font, Note: place.Note,
		})
	}

	if err := doc.WriteFile(out, nil); err != nil {
		return fail(fmt.Errorf("write %s: %w", out, err), out), rep
	}
	sort.Strings(rep.Applied)
	return report.OK, rep
}

func logoLabel(l schema.Logo) string {
	if l.ID != "" {
		return l.ID
	}
	if l.Field != "" {
		return "field:" + l.Field
	}
	return l.Image
}

func paintLabel(p schema.Paint) string {
	if p.ID != "" {
		return p.ID
	}
	if len(p.Text) > 24 {
		return fmt.Sprintf("%q...", p.Text[:24])
	}
	return fmt.Sprintf("%q", p.Text)
}

func pageOf(t *pdf.FieldTarget) int {
	if t == nil {
		return 0
	}
	return t.Page
}

func missing(values map[string]any, applied []string) []string {
	done := map[string]bool{}
	for _, a := range applied {
		done[a] = true
		for k := range values {
			if pdf.NormaliseName(k) == pdf.NormaliseName(a) {
				done[k] = true
			}
		}
	}
	var out []string
	for k := range values {
		if !done[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// skippedButtons reports the values that cannot be applied because the field
// type has no value - the caller must know it did not land.
func skippedButtons(fields []schema.Field, values map[string]any, applied []string) []report.SkippedField {
	byName := map[string]schema.Field{}
	for _, f := range fields {
		byName[f.Name] = f
	}
	done := map[string]bool{}
	for _, a := range applied {
		done[a] = true
	}
	var out []report.SkippedField
	for k := range values {
		f, ok := byName[k]
		if !ok {
			continue
		}
		if done[k] {
			continue
		}
		switch f.Type {
		case schema.TypePushButton:
			out = append(out, report.SkippedField{Name: k, Reason: "push buttons have no value"})
		case schema.TypeSignature:
			out = append(out, report.SkippedField{Name: k, Reason: "signature fields need a digital signature; stamp the artwork with a logo instead"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ------------------------------------------------------------- spec input ---

// readSpec loads the fill specification. A path of "-" reads stdin.
func readSpec(path string) (schema.FillSpec, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
		if err != nil {
			return schema.FillSpec{}, fmt.Errorf("read spec from stdin: %w", err)
		}
	} else {
		b, err = os.ReadFile(path)
		if err != nil {
			return schema.FillSpec{}, fmt.Errorf("read spec: %w", err)
		}
	}
	spec, err := schema.ParseFillSpec(b)
	if err != nil {
		return spec, fmt.Errorf("%s: %w", path, err)
	}
	if spec.Values == nil {
		spec.Values = map[string]any{}
	}
	return spec, nil
}

// ------------------------------------------------------------------ utils ---

type flagSet struct {
	args       []string
	positional int
	output     string
	password   string
	pages      []int
	rect       []float64
	position   string
	field      string
	opacity    float64
	strict     bool
	quiet      bool
	page       int
}

func parseFlags(args []string) (*flagSet, error) {
	fs := &flagSet{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-o", "--out", "--output":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs a file name", a)
			}
			fs.output = args[i]
		case "-p", "--password":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs a password", a)
			}
			fs.password = args[i]
		case "-page", "--page":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs a page number, or a list like 1,3-5", a)
			}
			list, err := parsePageList(args[i])
			if err != nil {
				return nil, fmt.Errorf("%s: %v", a, err)
			}
			fs.pages = append(fs.pages, list...)
			if len(list) > 0 {
				fs.page = list[0]
			}
		case "--rect":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs x,y,width,height", a)
			}
			parts := strings.Split(args[i], ",")
			if len(parts) != 4 {
				return nil, fmt.Errorf("%s: expected x,y,width,height", a)
			}
			fs.rect = fs.rect[:0]
			for _, p := range parts {
				v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", a, err)
				}
				fs.rect = append(fs.rect, v)
			}
		case "--position", "--pos":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs a position", a)
			}
			fs.position = args[i]
		case "--field":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs a field name", a)
			}
			fs.field = args[i]
		case "--opacity":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s needs a value between 0 and 1", a)
			}
			v, err := strconv.ParseFloat(args[i], 64)
			if err != nil || v < 0 || v > 1 {
				return nil, fmt.Errorf("%s: %s is not between 0 and 1", a, args[i])
			}
			fs.opacity = v
		case "-s", "--strict":
			fs.strict = true
		case "--json":
			// Accepted for symmetry with the machine-readable output of the
			// other sub-commands: the reports are always JSON.
		case "-q", "--quiet":
			fs.quiet = true
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				return nil, fmt.Errorf("unknown option %q", a)
			}
			fs.args = append(fs.args, a)
		}
	}
	fs.positional = len(fs.args)
	return fs, nil
}

func sortedFields(f []schema.Field) []schema.Field {
	out := append([]schema.Field(nil), f...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func writeJSON(w jsonWriter, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "pdf-go: %v\n", err)
		return fmt.Errorf("%v", err)
	}
	return nil
}

type jsonWriter interface{ Write([]byte) (int, error) }

func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return f.Close()
}

func fail(err error, source string) int {
	e := report.Error{Error: err.Error(), Source: source}
	switch {
	case strings.Contains(err.Error(), "unknown field"):
		e.Hint = "run `pdf-go fields <file.pdf>` to list the field names, then use them verbatim"
	case strings.Contains(err.Error(), "no AcroForm"):
		e.Hint = "this document has no form fields; stamp graphics with the logos array"
	}
	b, _ := json.MarshalIndent(e, "", "  ")
	fmt.Fprintln(os.Stderr, string(b))
	return report.InputErr
}

// guide is the long-form walkthrough printed by `pdf-go doc`. It is written
// for an automated caller: the shortest path from an unknown document to a
// filled one.

// ---------------------------------------------------------------- verify ---

// runVerify checks a filled document against the values it was supposed to
// receive: read the file back, compare every requested value, report the
// differences. Exit code 0 means the document matches.
func runVerify(args []string) int {
	fs, err := parseFlags(args)
	if err != nil {
		return fail(err, "")
	}
	if fs.positional < 1 {
		fmt.Fprintln(os.Stderr, "usage: pdf-go verify <in.pdf> [spec.json]")
		return report.Usage
	}
	in := fs.args[0]

	current, err := pdf.Extract(in, fs.password)
	if err != nil {
		return fail(err, in)
	}

	want := map[string]string{}
	if fs.positional >= 2 {
		spec, err := readSpec(fs.args[1])
		if err != nil {
			return fail(err, fs.args[1])
		}
		for k, v := range spec.Values {
			want[k] = fmt.Sprint(v)
		}
	}

	rep := report.VerifyReport{Source: in, Checked: len(want)}
	byName := map[string]schema.Field{}
	for _, f := range current.Fields {
		byName[pdf.NormaliseName(f.Name)] = f
	}

	if len(want) == 0 {
		for _, f := range current.Fields {
			if f.Value != "" {
				rep.Matches = append(rep.Matches, report.ValueReport{
					Name: f.Name, Type: f.Type, Value: f.Value, Match: true,
				})
			}
		}
		rep.Checked = len(rep.Matches)
	}

	for _, key := range sortedKeys(want) {
		f, ok := byName[pdf.NormaliseName(key)]
		if !ok {
			rep.Missing = append(rep.Missing, key)
			continue
		}
		expect, got := want[key], f.Value
		if f.Type == schema.TypeCheckbox || f.Type == schema.TypeRadio {
			expect, got = normaliseState(expect), normaliseState(got)
		}
		v := report.ValueReport{
			Name: f.Name, Type: f.Type, Want: expect, Got: got,
			Match: strings.EqualFold(strings.TrimSpace(expect), strings.TrimSpace(got)),
		}
		if v.Match {
			rep.Matches = append(rep.Matches, v)
		} else {
			rep.Mismatches = append(rep.Mismatches, v)
		}
	}

	sort.Slice(rep.Matches, func(i, j int) bool { return rep.Matches[i].Name < rep.Matches[j].Name })
	sort.Slice(rep.Mismatches, func(i, j int) bool { return rep.Mismatches[i].Name < rep.Mismatches[j].Name })
	sort.Strings(rep.Missing)

	status := report.OK
	if len(rep.Mismatches) > 0 || len(rep.Missing) > 0 {
		status = report.Partial
	}
	if fs.output != "" {
		if err := writeJSONFile(fs.output, rep); err != nil {
			return fail(err, fs.output)
		}
	} else if !fs.quiet {
		if err := writeJSON(os.Stdout, rep); err != nil {
			return fail(err, "")
		}
	}
	return status
}

// normaliseState folds the many ways a check box can be "on" into one word.
func normaliseState(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case s == "", strings.EqualFold(s, "Off"), strings.EqualFold(s, "false"), strings.EqualFold(s, "no"):
		return "Off"
	case strings.EqualFold(s, "true"), strings.EqualFold(s, "yes"):
		return "Yes"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// guide is the long-form walkthrough printed by `pdf-go doc`. It is written
// for an automated caller: the shortest path from an unknown document to a
// verified, filled one.
const guide = `pdf-go - PDF forms for scripted use

THE LOOP
  1. pdf-go extract in.pdf -o spec.json
     spec.json describes every field: name, type, current value, allowed
     values, flags, page and rectangle.
  2. Edit spec.json: put the wanted value in the "value" key of the entries
     you care about. Delete the entries you do not touch - the smaller the
     spec, the cheaper the fill. Leave "name" exactly as it is.
  3. pdf-go fill spec.json -o out.pdf
     The input document is taken from "source" in the spec.
  4. pdf-go verify out.pdf spec.json
     Reads the result back and compares. Exit 0 = matches, 3 = differs.

MINIMAL SPEC
  {"values":{"form[0].name":"Ada","agree":true}}
  This is all fill needs. You can hand-write it, or use the schema from
  extract (its "fields" array is read as values too).

VALUES BY TYPE
  text         string. Truncated to maxLen, scaled to fit the box.
  checkbox     true / false, "" / "Off" to clear, or an on-state from
               "states" (the appearance keys the document defines).
  radio        the export value of the button to switch on, taken from the
               children "options". Set it on the group name.
  combo        one of "options".
  choice       string, or array of strings when multi-select.
  signature    not fillable. Stamp artwork with a logo instead.
  pushbutton   not fillable.

GEOMETRY
  Coordinates are PDF points: 1/72 inch, origin at the lower-left of the page,
  y increasing upwards. rect is [x0 y0 x1 y1].
  pdf-go pages in.pdf [-o pages.json] [--page 1,3-5]
  prints media, crop, trim, bleed, art and content boxes of each page, its
  size, rotation and the number of widgets it carries. Place logos and paints
  inside the crop box: the media box is the paper, the crop box is the print.

LOGOS (bar codes, QR codes, signatures, stamps)
  {"logos":[{"image":"qr.png","field":"qrField"},
            {"image":"logo.png","page":1,"box":"crop","position":"bottom-right",
             "width":120,"margin":18,"opacity":0.9,"rotate":0}]}
  Target, in priority order: "field" (placed inside the field rectangle),
  "rect" (exact), or "page"+"box"+"position".
  Boxes: media, crop, trim, bleed, art, content, header, footer.
  Positions: top/bottom/center, left/right, e.g. "bottom-left", "center".
  PNG with transparency is preferred; JPEG works.
  A logo on a field with no widget reserves the area with a read-only widget.

PAINT (text baked into the page, not a form field)
  {"paints":[{"text":"PAID IN FULL","page":1,"box":"crop","position":"top-right",
              "font":"Helvetica-Bold","size":14,"color":"#B00000",
              "align":"right","opacity":0.8,"rotate":0},
             {"text":"REF-42","field":"z1","font":"Courier","size":8}]}
  Fonts: Helvetica (+-Bold/-Oblique), Times (+-Bold/-Italic), Courier,
  Symbol, ZapfDingbats. Colors: "#rrggbb" or black/white/red/green/blue/
  yellow/grey/orange/navy.

READING THE REPORT
  applied   fields whose value was written
  skipped   requested fields not written, and why
  notes     per-field warnings: value clipped to maxLen, characters the field
            font cannot draw, a value not in the allowed list, ...
  logos     where each image landed
  paints    where each text block landed
  warnings  non fatal problems (unknown field, unreadable image, ...)
  Exit 3 (partial) means something was skipped: read "skipped" and fix.

ONE-LINERS
  pdf-go fields in.pdf                     list the field names
  pdf-go pages in.pdf                      list the page boxes
  pdf-go add-logo in.pdf code.png --page 1 --position top-right -o out.pdf
  pdf-go add-logo in.pdf sign.png --field signature --opacity 0.8 -o out.pdf
  pdf-go extract in.pdf -o spec.json -q && pdf-go fill spec.json -o out.pdf

RULES
  * A field name is matched exactly, then by suffix: "Last" resolves to
    "form1[0].#subform[0].Last[0]" when unique. Do not guess - extract first.
  * readOnly fields are skipped; they carry the document's own value.
  * Values are baked into appearance streams, so the output prints the same
    everywhere; the form stays editable unless "lockForm" is true.
  * Text drawn with paints/logos is not interactive: it cannot be cleared.
`

// ---------------------------------------------------------------- pages ---

// runPages prints the geometry of the pages of a document: every box a
// graphic element can be anchored to, in PDF points. Run after `extract`:
// the schema says what can be filled, this says where things can be drawn.
func runPages(args []string) int {
	fs, err := parseFlags(args)
	if err != nil {
		return fail(err, "")
	}
	if fs.positional < 1 {
		fmt.Fprintln(os.Stderr, "usage: pdf-go pages <in.pdf> [--page 1,3-5] [-o pages.json]")
		return report.Usage
	}
	in := fs.args[0]

	geoms, err := pdf.Pages(in, fs.password, fs.pages)
	if err != nil {
		return fail(err, in)
	}
	if fs.output == "" {
		if err := writeJSON(os.Stdout, geoms); err != nil {
			return fail(err, "")
		}
		return report.OK
	}
	if err := writeJSONFile(fs.output, geoms); err != nil {
		return fail(err, fs.output)
	}
	if fs.quiet {
		return report.OK
	}
	if err := writeJSON(os.Stdout, report.PagesReport{Source: in, Output: fs.output, PageCount: len(geoms)}); err != nil {
		return fail(err, "")
	}
	return report.OK
}

// parsePageList reads the value of --page: a comma separated list of page
// numbers and ranges, e.g. "1,3-5,10". Pages are 1-based.
func parsePageList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.Index(part, "-"); i > 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("bad page range %q", part)
		}
		b := a
		if strings.TrimSpace(hi) != "" {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("bad page range %q", part)
			}
		}
		if b < a {
			a, b = b, a
		}
		for n := a; n <= b; n++ {
			out = append(out, n)
		}
	}
	return out, nil
}

// ------------------------------------------------------------ add-logo ---

// runAddLogo stamps a single image. It is the one-shot form of the logos
// array of a fill spec: enough for "put this barcode on page 1".
func runAddLogo(args []string) int {
	fs, err := parseFlags(args)
	if err != nil {
		return fail(err, "")
	}
	if fs.positional < 2 {
		fmt.Fprintln(os.Stderr, "usage: pdf-go add-logo <in.pdf> <image> [-o out.pdf] [--page 1] [--rect x,y,w,h] [--position top-right] [--field name]")
		return report.Usage
	}
	in, image := fs.args[0], fs.args[1]
	out := fs.output
	if out == "" {
		out = strings.TrimSuffix(in, filepath.Ext(in)) + "-stamped.pdf"
	}

	logo := schema.Logo{Page: 1, Box: "crop", Image: image}
	if len(fs.pages) > 0 {
		logo.Page = fs.pages[0]
	}
	if fs.rect != nil {
		logo.Rect = fs.rect
	}
	if fs.position != "" {
		logo.Position = fs.position
	}
	if fs.field != "" {
		logo.Field = fs.field
	}
	if fs.opacity > 0 {
		logo.Opacity = fs.opacity
	}

	status, rep := fillDocument(in, out, "", schema.FillSpec{Logos: []schema.Logo{logo}}, fs)
	if status != report.OK {
		return status
	}
	if fs.quiet {
		return report.OK
	}
	if err := writeJSON(os.Stdout, rep); err != nil {
		return fail(err, "")
	}
	if len(rep.Skipped) > 0 {
		return report.Partial
	}
	return report.OK
}
