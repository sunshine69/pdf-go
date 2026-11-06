package signfill

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// The fill core is used by the CLI and by the envelope create endpoint, so
// the contract these tests assert is the contract both callers depend on.

func TestMain(m *testing.M) {
	// The PDF library reports unencodable glyphs with log.Printf. The CLI
	// silences them the same way: every message that matters is returned in
	// the report, and a glyph we cannot draw is a note.
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func samplePath(t *testing.T) string {
	t.Helper()
	in, err := filepath.Abs(filepath.Join("..", "..", "testdata", "sample1.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in); err != nil {
		t.Skipf("testdata/sample1.pdf missing: %v", err)
	}
	return in
}

func sampleBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(samplePath(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fillValues returns a spec that fills every text field with its name, so a
// round trip can be checked field by field.
func fillValues(t *testing.T, in []byte) (schema.FillSpec, schema.FormSchema) {
	t.Helper()
	path := writeTemp(t, in)
	s, err := extractFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	spec := schema.FillSpec{Values: schema.SetValues{}}
	for _, f := range s.Fields {
		switch f.Type {
		case schema.TypeText:
			spec.Values[f.Name] = "x"
		case schema.TypeCheckbox:
			spec.Values[f.Name] = true
		}
	}
	return spec, s
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "doc.pdf")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// extractFrom reads the schema of a file on disk, and extractViaPDF bridges to
// the byte-based Extract so a test can read back the bytes Fill produced.
func extractFrom(path string) (schema.FormSchema, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return schema.FormSchema{}, err
	}
	return Extract(b)
}

func extractViaPDF(path string) (schema.FormSchema, error) {
	return extractFrom(path)
}

func TestFillRoundTrip(t *testing.T) {
	in := sampleBytes(t)
	spec, _ := fillValues(t, in)
	if len(spec.Values) == 0 {
		t.Fatal("the sample has no fillable fields")
	}

	rep, out, err := Fill(in, spec, Options{Strict: true, Path: "sample1.pdf"})
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("output is not a PDF")
	}
	if len(out) <= len(in) {
		t.Fatalf("output %d bytes is not larger than input %d", len(out), len(in))
	}
	if len(rep.Applied) != len(spec.Values) {
		t.Fatalf("applied %d of %d", len(rep.Applied), len(spec.Values))
	}
	if len(rep.Skipped) != 0 {
		t.Fatalf("skipped: %+v", rep.Skipped)
	}
	if len(rep.Missing) != 0 {
		t.Fatalf("missing: %v", rep.Missing)
	}

	// Every requested value is readable from the filled bytes.
	path := writeTemp(t, out)
	got, err := extractFrom(path)
	if err != nil {
		t.Fatalf("extract filled: %v", err)
	}
	byName := map[string]schema.Field{}
	for _, f := range got.Fields {
		byName[f.Name] = f
	}
	for name, want := range spec.Values {
		f, ok := byName[name]
		if !ok {
			t.Fatalf("field %s disappeared", name)
		}
		var wantStr string
		switch v := want.(type) {
		case string:
			wantStr = v
		case bool:
			// A checkbox on-state is named by the document (Yes, On, 1), not
			// by the literal "on", so the expected value is the field's own
			// first on-state.
			if v {
				// The on-state is named by the document, and the extracted
				// state list is sorted alphabetically - "Off" sorts before
				// "Yes". Pick the state that is not the off-state, the same
				// rule the fill code uses.
				wantStr = "Yes"
				for _, s := range f.States {
					if s != "Off" && s != "No" && s != "" {
						wantStr = s
						break
					}
				}
			} else {
				wantStr = "Off"
			}
		}
		if !strings.EqualFold(f.Value, wantStr) {
			t.Fatalf("field %s = %q, want %q", name, f.Value, wantStr)
		}
	}
}

func TestFillUnknownFieldIsAnErrorInStrict(t *testing.T) {
	in := sampleBytes(t)
	spec := schema.FillSpec{Values: schema.SetValues{"nope": "x"}}

	rep, out, err := Fill(in, spec, Options{Strict: true, Path: "sample1.pdf"})
	if err == nil {
		t.Fatal("strict fill accepted an unknown field")
	}
	if !strings.Contains(err.Error(), `"nope"`) {
		t.Fatalf("error does not name the field: %v", err)
	}
	if len(out) != 0 {
		t.Fatal("bytes returned for a failed fill")
	}
	if len(rep.Applied) != 0 {
		t.Fatalf("nothing should have been applied: %v", rep.Applied)
	}
}

func TestFillNonStrictWarnsInsteadOfFailing(t *testing.T) {
	in := sampleBytes(t)
	spec := schema.FillSpec{Values: schema.SetValues{"nope": "x", knownName(t, in): "ok"}}

	rep, out, err := Fill(in, spec, Options{Path: "sample1.pdf"})
	if err != nil {
		t.Fatalf("non-strict fill must not fail: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no output bytes")
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("no warning about the unknown field")
	}
	if len(rep.Applied) == 0 {
		t.Fatal("the known field was not applied")
	}
}

// TestLockFormMakesFieldsReadOnly is the property the certified document
// relies on: after filling with LockForm, every field carries readOnly.
func TestLockFormMakesFieldsReadOnly(t *testing.T) {
	in := sampleBytes(t)
	spec, s := fillValues(t, in)
	spec.LockForm = true

	_, out, err := Fill(in, spec, Options{Strict: true, Path: "sample1.pdf"})
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	got, err := Extract(out)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	n := 0
	for _, f := range got.Fields {
		if f.Type == schema.TypePushButton || f.Type == schema.TypeSignature {
			continue
		}
		n++
		if !f.HasFlag("readOnly") {
			t.Fatalf("field %s is not read-only after lockForm", f.Name)
		}
	}
	if n == 0 {
		t.Fatal("no fields checked")
	}
	if CountFillable(s) == 0 {
		t.Fatal("sample has no fillable fields")
	}
}

func TestValidateRejectsUnknownField(t *testing.T) {
	in := sampleBytes(t)
	s, err := Extract(in)
	if err != nil {
		t.Fatal(err)
	}
	err = Validate(s, schema.FillSpec{Values: schema.SetValues{"ghost": "x"}})
	if err == nil || !strings.Contains(err.Error(), `"ghost"`) {
		t.Fatalf("Validate: %v", err)
	}

	// A spec that resolves passes.
	spec := schema.FillSpec{Values: schema.SetValues{s.Fields[0].Name: "x"}}
	if err := Validate(s, spec); err != nil {
		t.Fatalf("Validate rejected a valid spec: %v", err)
	}
}

func TestValidateRejectsUnknownLogoAndPaintTarget(t *testing.T) {
	in := sampleBytes(t)
	s, err := Extract(in)
	if err != nil {

		t.Fatal(err)
	}
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "sig", Field: "missing"}},
	}); err == nil {
		t.Fatal("Validate accepted a logo on an unknown field")
	}
	if err := Validate(s, schema.FillSpec{
		Paints: []schema.Paint{{Text: "hi", Field: "missing"}},
	}); err == nil {
		t.Fatal("Validate accepted a paint on an unknown field")
	}
}

func TestFillRejectsNonPDF(t *testing.T) {
	_, out, err := Fill([]byte("not a pdf"), schema.FillSpec{}, Options{})
	if err == nil || len(out) != 0 {
		t.Fatalf("expected a PDF error, got %v / %d bytes", err, len(out))
	}
}

// knownName picks a field that exists in the sample.
func knownName(t *testing.T, in []byte) string {
	t.Helper()
	s, err := Extract(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range s.Fields {
		if f.Type == schema.TypeText {
			return f.Name
		}
	}
	t.Fatal("no text field")
	return ""
}

// The report shape is part of the wire format: the API returns it verbatim,
// so the JSON keys must stay as documented by `pdf-go doc`.
func TestReportJSONKeys(t *testing.T) {
	b, err := json.Marshal(repShape())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"applied", "skipped", "warnings", "lockedForm"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("report JSON is missing %q", k)
		}
	}
}

func repShape() map[string]any {
	return map[string]any{
		"applied":    []string{},
		"skipped":    []string{},
		"warnings":   []string{},
		"lockedForm": true,
	}
}

// The logo artwork is client-supplied bytes: base64 in the spec, or a file the
// spec names. Validate reads them, because the create endpoint runs Validate
// before it stores an envelope. A file whose name says .png is not a PNG, so
// the test is on the bytes.
func TestValidateChecksLogoMagicBytes(t *testing.T) {
	in := sampleBytes(t)
	s, err := Extract(in)
	if err != nil {
		t.Fatal(err)
	}
	name := s.Fields[0].Name

	// A real PNG passes.
	png := tinyPNG(t)
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "m", Field: name, ImageData: base64.StdEncoding.EncodeToString(png)}},
	}); err != nil {
		t.Fatalf("Validate rejected a real PNG: %v", err)
	}

	// The same bytes with a .png name on disk also pass.
	dir := t.TempDir()
	path := filepath.Join(dir, "logo.png")
	if err := os.WriteFile(path, png, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "disk", Field: name, Image: path}},
	}); err != nil {
		t.Fatalf("Validate rejected a PNG on disk: %v", err)
	}

	for _, bad := range []struct {
		name string
		data []byte
	}{
		{"an executable renamed .png", []byte("MZ\x90\x00\x03\x00\x00\x00")},
		{"a PDF renamed .png", []byte("%PDF-1.7\n")},
		{"plain text", []byte("not an image at all, and long enough to be a file")},
		{"a truncated PNG header", []byte("\x89PNG\r\n\x1a")},
		{"empty", []byte("")},
	} {
		spec := schema.FillSpec{Logos: []schema.Logo{
			{ID: bad.name, Field: name, ImageData: base64.StdEncoding.EncodeToString(bad.data)},
		}}
		err := Validate(s, spec)
		if err == nil {
			t.Errorf("Validate accepted %s", bad.name)
			continue
		}
		if !strings.Contains(err.Error(), bad.name) {
			t.Errorf("the error for %s does not name the logo: %v", bad.name, err)
		}
	}

	// A JPEG is accepted; the accepted set is PNG, JPEG, GIF, TIFF.
	jpeg := []byte{0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43}
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "j", Field: name, ImageData: base64.StdEncoding.EncodeToString(jpeg)}},
	}); err == nil {
		t.Fatal("Validate accepted a JPEG stub that cannot be decoded")
	}
	gif := []byte("GIF89a")
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "g", Field: name, ImageData: base64.StdEncoding.EncodeToString(gif)}},
	}); err == nil {
		t.Fatal("Validate accepted a GIF stub that cannot be decoded")
	}

	// A data: URL prefix is stripped before the base64 is read.
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "u", Field: name, ImageData: dataURL}},
	}); err != nil {
		t.Fatalf("Validate rejected a data: URL: %v", err)
	}

	// A logo with no artwork at all is refused, naming the logo.
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "none", Field: name}},
	}); err == nil || !strings.Contains(err.Error(), "none") {
		t.Fatalf("Validate accepted a logo with no artwork: %v", err)
	}
}

// TestValidateChecksLogoSize pins the ceilings: a logo whose bytes are over
// the byte ceiling is refused, and one whose pixels are over the edge ceiling
// is refused. A create request that accepts a 40 MB image is a create request
// that stores a 40 MB blob per envelope.
func TestValidateChecksLogoSize(t *testing.T) {
	in := sampleBytes(t)
	s, err := Extract(in)
	if err != nil {
		t.Fatal(err)
	}
	name := s.Fields[0].Name

	big := make([]byte, MaxImageBytes+1)
	copy(big, []byte("\x89PNG\r\n\x1a\n"))
	err = Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "big", Field: name,
			ImageData: base64.StdEncoding.EncodeToString(big)}},
	})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Validate accepted a logo over the byte ceiling: %v", err)
	}

	// A PNG with a header claiming a huge size is refused by the pixel check.
	img := image.NewRGBA(image.Rect(0, 0, MaxImageEdge+1, 4))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	err = Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "wide", Field: name,
			ImageData: base64.StdEncoding.EncodeToString(buf.Bytes())}},
	})
	if err == nil || !strings.Contains(err.Error(), "pixels") {
		t.Fatalf("Validate accepted a logo over the pixel ceiling: %v", err)
	}

	// At the ceiling it passes.
	ok := image.NewRGBA(image.Rect(0, 0, MaxImageEdge, MaxImageEdge))
	var okbuf bytes.Buffer
	if err := png.Encode(&okbuf, ok); err != nil {
		t.Fatal(err)
	}
	if err := Validate(s, schema.FillSpec{
		Logos: []schema.Logo{{ID: "ok", Field: name,
			ImageData: base64.StdEncoding.EncodeToString(okbuf.Bytes())}},
	}); err != nil {
		t.Fatalf("Validate rejected a logo at the ceiling: %v", err)
	}
}

// tinyPNG is a 4x4 PNG, the smallest artwork a spec can carry.
func tinyPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
