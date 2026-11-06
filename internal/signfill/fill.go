package signfill

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sunshine69/pdf-go/internal/pdf"
	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/schema"

	_ "image/gif"  // registered for image.DecodeConfig
	_ "image/jpeg" // registered for image.DecodeConfig
)

// MaxImageBytes is the ceiling of one logo's artwork, and MaxImageEdge its
// pixel ceiling. The API's create endpoint reads these bytes from the client,
// so the limits are checked at the same point the fill is validated: a logo
// that is 20 MB or 10000 pixels wide is refused with 400, not stored.
const (
	MaxImageBytes = 512 * 1024
	MaxImageEdge  = 2000
)

// Fill writes a fill specification into a PDF and returns the bytes of the
// result. It is the one implementation of the fill format: `pdf-go fill` and
// the envelope creation endpoint both call it, so an agent and an API client
// get the same semantics from the same JSON.
//
// Strict is the contract the API relies on: in strict mode an unknown field
// name, an unreadable value, a logo pointing at a field that does not exist,
// or a paint that does not fit is an error. Nothing partial is returned -- the
// caller gets an error and no bytes, so a create request that fails leaves no
// half-written document behind.
func Fill(in []byte, spec schema.FillSpec, o Options) (report.FillReport, []byte, error) {
	if len(in) == 0 {
		return report.FillReport{}, nil, fmt.Errorf("signfill: empty document")
	}
	if !bytes.HasPrefix(in, []byte("%PDF-")) {
		return report.FillReport{}, nil, fmt.Errorf("signfill: input is not a PDF")
	}

	// The existing extract path is file-based, so the template is staged on
	// disk for the duration of the call. Nothing is kept: the temp directory
	// is removed on every return.
	tmp, err := os.MkdirTemp("", "signfill")
	if err != nil {
		return report.FillReport{}, nil, fmt.Errorf("signfill: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	inPath := filepath.Join(tmp, "in.pdf")
	if err := os.WriteFile(inPath, in, 0o600); err != nil {
		return report.FillReport{}, nil, fmt.Errorf("signfill: stage template: %w", err)
	}

	doc, _, err := pdf.Load(inPath, o.Password)
	if err != nil {
		return report.FillReport{}, nil, fmt.Errorf("signfill: parse: %w", err)
	}

	schemaData, err := pdf.Extract(inPath, o.Password)
	if err != nil {
		return report.FillReport{}, nil, fmt.Errorf("signfill: extract: %w", err)
	}

	rep := report.FillReport{
		Source: o.Path,
		Spec:   o.Spec,
		Locked: spec.LockForm,
	}

	values := map[string]any{}
	for k, v := range spec.Values {
		values[k] = v
	}

	applied, notes, err := pdf.FillDoc(doc, schemaData.Fields, values, spec.LockForm)
	rep.Applied, rep.Notes = applied, notes
	if err != nil {
		if o.Strict {
			return rep, nil, err
		}
		for _, name := range missing(values, applied) {
			rep.Skipped = append(rep.Skipped, report.SkippedField{
				Name: name, Reason: "not applied"})
		}
		rep.Warnings = append(rep.Warnings, err.Error())
	}
	rep.Skipped = append(rep.Skipped, skippedButtons(schemaData.Fields, values, applied)...)

	pages := doc.Catalog.Pages.Flatten()
	targets := pdf.Targets(doc)

	for _, l := range spec.Logos {
		var target *pdf.FieldTarget
		if l.Field != "" {
			t, resolved, found := pdf.LookupTarget(targets, l.Field)
			if !found {
				msg := fmt.Sprintf("logo %s: unknown field %q", logoLabel(l), l.Field)
				if o.Strict {
					return rep, nil, fmt.Errorf("%s", msg)
				}
				rep.Warnings = append(rep.Warnings, msg)
				continue
			}
			t.Name = resolved
			target = &t
		}
		pageIdx, err := pdf.LogoPage(pages, l, pageOf(target))
		if err != nil {
			if o.Strict {
				return rep, nil, err
			}
			rep.Warnings = append(rep.Warnings, err.Error())
			continue
		}
		place, err := pdf.StampLogo(pageIdx, pages[pageIdx-1], l, target)
		if err != nil {
			if o.Strict {
				return rep, nil, fmt.Errorf("logo %s: %w", logoLabel(l), err)
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

	for _, p := range spec.Paints {
		var target *pdf.FieldTarget
		if p.Field != "" {
			t, resolved, found := pdf.LookupTarget(targets, p.Field)
			if !found {
				msg := fmt.Sprintf("paint %s: unknown field %q", paintLabel(p), p.Field)
				if o.Strict {
					return rep, nil, fmt.Errorf("%s", msg)
				}
				rep.Warnings = append(rep.Warnings, msg)
				continue
			}
			t.Name = resolved
			target = &t
		}
		pageIdx, err := pdf.PaintPage(pages, p, pageOf(target))
		if err != nil {
			if o.Strict {
				return rep, nil, err
			}
			rep.Warnings = append(rep.Warnings, err.Error())
			continue
		}
		place, err := pdf.PaintText(pageIdx, pages[pageIdx-1], p, target)
		if err != nil {
			if o.Strict {
				return rep, nil, fmt.Errorf("paint %s: %w", paintLabel(p), err)
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

	var out bytes.Buffer
	if err := doc.Write(&out, nil); err != nil {
		return rep, nil, fmt.Errorf("signfill: write: %w", err)
	}
	sort.Strings(rep.Applied)
	rep.Missing = missing(values, rep.Applied)
	return rep, out.Bytes(), nil
}

// Extract reads the form schema of a PDF held in memory. It is the same
// extract the CLI uses, so a fill spec validated against this schema is the
// fill spec the CLI accepts.
func Extract(in []byte) (schema.FormSchema, error) {
	if !bytes.HasPrefix(in, []byte("%PDF-")) {
		return schema.FormSchema{}, fmt.Errorf("signfill: input is not a PDF")
	}
	tmp, err := os.MkdirTemp("", "signfill")
	if err != nil {
		return schema.FormSchema{}, fmt.Errorf("signfill: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	p := filepath.Join(tmp, "in.pdf")
	if err := os.WriteFile(p, in, 0o600); err != nil {
		return schema.FormSchema{}, fmt.Errorf("signfill: stage: %w", err)
	}
	s, err := pdf.Extract(p, "")
	if err != nil {
		return schema.FormSchema{}, fmt.Errorf("signfill: extract: %w", err)
	}
	return s, nil
}

// Summary is the compact form of a fill report: what the create endpoint
// stores in the audit payload, and what the API returns with a created
// envelope. The full report stays available to callers that need the geometry
// of every stamp.
type Summary struct {
	Applied  []string `json:"applied"`
	Skipped  []string `json:"skipped,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	Locked   bool     `json:"lockedForm"`
	Notes    int      `json:"notes"`
}

// Summarize reduces a fill report to the fields worth auditing.
func Summarize(rep report.FillReport) Summary {
	s := Summary{Applied: rep.Applied, Warnings: rep.Warnings, Missing: rep.Missing, Locked: rep.Locked}
	for _, sk := range rep.Skipped {
		s.Skipped = append(s.Skipped, sk.Name)
	}
	s.Notes = len(rep.Notes)
	return s
}

// Options controls one fill run.
type Options struct {
	// Strict makes every unresolvable instruction an error. The API creates
	// envelopes in strict mode; the CLI sets it with --strict.
	Strict bool
	// Password is the document's open password, if it has one.
	Password string
	// Path names the source document in the report. It is the file the CLI
	// was given, and the stored sha for an envelope. Fill itself never
	// touches the filesystem.
	Path string
	// Spec names the specification in the report, for the audit trail.
	Spec string
}

// Validate reports whether a fill specification resolves against a schema,
// without producing any bytes. The create endpoint runs this before it
// stores anything, so an unknown field name is answered with 400 and a
// hint, and the envelope row is never created.
func Validate(schemaData schema.FormSchema, spec schema.FillSpec) error {
	byName := make(map[string]schema.Field, len(schemaData.Fields))
	for _, f := range schemaData.Fields {
		byName[f.Name] = f
	}
	for k := range spec.Values {
		if _, ok := byName[k]; !ok {
			return fmt.Errorf("unknown field %q; run extract to list the available fields", k)
		}
	}
	for _, l := range spec.Logos {
		if l.Field != "" {
			if _, ok := byName[l.Field]; !ok {
				return fmt.Errorf("logo %s: unknown field %q", logoLabel(l), l.Field)
			}
		}
		if err := logoAcceptable(l); err != nil {
			return err
		}
	}
	for _, p := range spec.Paints {
		if p.Field != "" {
			if _, ok := byName[p.Field]; !ok {
				return fmt.Errorf("paint %s: unknown field %q", paintLabel(p), p.Field)
			}
		}
	}
	return nil
}

// logoAcceptable checks a logo's artwork against the accepted image formats.
// The bytes come from a file path or from base64 in the spec, so the check
// reads them; this is what Fill will do anyway, and running it here means the
// create endpoint answers 400 before it stores an envelope.
//
// The accepted set is the set the PDF writer can embed: PNG, JPEG, GIF, TIFF.
// A file whose extension says .png and whose bytes say something else is
// refused: a client that renames an executable is not signing a document.
func logoAcceptable(l schema.Logo) error {
	data, err := logoData(l)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("logo %s: image is empty", logoLabel(l))
	}
	if len(data) > MaxImageBytes {
		return fmt.Errorf("logo %s: image is larger than %d KB", logoLabel(l), MaxImageBytes/1024)
	}
	if !isImage(data) {
		return fmt.Errorf("logo %s: image is not PNG, JPEG, GIF or TIFF", logoLabel(l))
	}
	cfg, _, cerr := image.DecodeConfig(bytes.NewReader(data))
	if cerr != nil {
		return fmt.Errorf("logo %s: image cannot be decoded: %v", logoLabel(l), cerr)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return fmt.Errorf("logo %s: image has no size", logoLabel(l))
	}
	if cfg.Width > MaxImageEdge || cfg.Height > MaxImageEdge {
		return fmt.Errorf("logo %s: image is larger than %dx%d pixels",
			logoLabel(l), MaxImageEdge, MaxImageEdge)
	}
	return nil
}

// logoData returns the artwork bytes of a logo, from base64 (with an optional
// data: URL prefix) or from the file the spec names.
func logoData(l schema.Logo) ([]byte, error) {
	if s := strings.TrimSpace(l.ImageData); s != "" {
		if i := strings.Index(s, ","); strings.HasPrefix(s, "data:") && i >= 0 {
			s = s[i+1:]
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("logo %s: imageData is not base64: %w", logoLabel(l), err)
		}
		return b, nil
	}
	name := strings.TrimSpace(l.Image)
	if name == "" {
		return nil, fmt.Errorf("logo %s: set \"image\" (file path) or \"imageData\" (base64)",
			logoLabel(l))
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("logo %s: read image: %w", logoLabel(l), err)
	}
	return b, nil
}

// isImage reports whether the bytes start with the magic bytes of one of the
// accepted formats. The test is on the bytes, not on a name.
func isImage(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return true
	case data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return true
	case data[0] == 'G' && data[1] == 'I' && data[2] == 'F':
		return true
	case bytes.Equal(data[:4], []byte("II*\x00")) || bytes.Equal(data[:4], []byte("MM\x00*")):
		return true
	}
	return false
}

// CountFillable reports how many fields a schema can accept a value for, so
// the create endpoint can reject a template with no form to fill.
func CountFillable(schemaData schema.FormSchema) int {
	n := 0
	for _, f := range schemaData.Fields {
		switch f.Type {
		case schema.TypeText, schema.TypeCheckbox, schema.TypeRadio,
			schema.TypeChoice, schema.TypeCombo:
			n++
		}
	}
	return n
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
			out = append(out, report.SkippedField{Name: k,
				Reason: "signature fields need a digital signature; stamp the artwork with a logo instead"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
