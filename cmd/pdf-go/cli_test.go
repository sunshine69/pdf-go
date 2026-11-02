package main

import (
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/pdf"
	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/schema"
)

// sample is copied from the PDF library test suite (MIT licence).
func sample(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "sample1.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("test document missing: %v", err)
	}
	return p
}

// runCLI runs the CLI in process and returns its exit code and everything it
// printed. Reports are written to stdout and error envelopes to stderr, so
// both are captured here.
func runCLI(t *testing.T, args ...string) (int, []byte) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "cli")
	if err != nil {
		t.Fatal(err)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	code := run(args)
	os.Stdout, os.Stderr = savedOut, savedErr
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return code, body
}

func TestExtractFillVerify(t *testing.T) {
	in := sample(t)
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.json")
	filled := filepath.Join(dir, "filled.pdf")

	if code, _ := runCLI(t, "extract", in, "-o", spec); code != report.OK {
		t.Fatalf("extract: exit %d", code)
	}
	sch, err := schema.ReadFormSchema(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(sch.Fields) < 10 {
		t.Fatalf("only %d fields extracted", len(sch.Fields))
	}
	values := map[string]any{}
	text, checks := 0, 0
	for _, f := range sch.Fields {
		if strings.Contains(strings.Join(f.Flags, ","), "readOnly") {
			continue
		}
		switch f.Type {
		case schema.TypeText:
			values[f.Name] = textValueFor(f)
			text++
		case schema.TypeCheckbox:
			values[f.Name] = true
			checks++
		}
	}
	if text == 0 || checks == 0 {
		t.Fatalf("expected text and check boxes, got %d/%d", text, checks)
	}
	specFill := filepath.Join(dir, "fill.json")
	body, _ := json.Marshal(map[string]any{"values": values})
	if err := os.WriteFile(specFill, body, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "fill", specFill, in, "-o", filled, "--strict")
	if code != report.OK {
		t.Fatalf("fill: exit %d: %s", code, out)
	}
	var rep report.FillReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("fill report: %v: %s", err, out)
	}
	if len(rep.Applied) != len(values) {
		t.Fatalf("applied %d of %d", len(rep.Applied), len(values))
	}
	if len(rep.Skipped) != 0 {
		t.Fatalf("skipped: %+v", rep.Skipped)
	}

	// Round-trip: the values must be readable from the filled document.
	code, out = runCLI(t, "verify", filled, specFill)
	if code != report.OK {
		t.Fatalf("verify: exit %d: %s", code, out)
	}
	var v report.VerifyReport
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Mismatches) != 0 {
		t.Fatalf("mismatches: %+v", v.Mismatches)
	}
	if len(v.Matches) != len(values) {
		t.Fatalf("matched %d of %d", len(v.Matches), len(values))
	}
}

func TestFillUnknownFieldStrict(t *testing.T) {
	in := sample(t)
	dir := t.TempDir()
	spec := filepath.Join(dir, "v.json")
	if err := os.WriteFile(spec, []byte(`{"values":{"nope":"x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "fill", spec, in, "-o", filepath.Join(dir, "o.pdf"), "--strict")
	if code != report.InputErr {
		t.Fatalf("expected InputErr, got %d: %s", code, out)
	}
	var e report.Error
	if err := json.Unmarshal(out, &e); err != nil || !strings.Contains(e.Error, "nope") {
		t.Fatalf("bad error envelope: %s", out)
	}
	// Non strict: the run succeeds and reports the skipped field.
	code, out = runCLI(t, "fill", spec, in, "-o", filepath.Join(dir, "o2.pdf"))
	if code != report.OK && code != report.Partial {
		t.Fatalf("expected a partial success, got %d: %s", code, out)
	}
	var rep report.FillReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Name != "nope" {
		t.Fatalf("skipped: %+v", rep.Skipped)
	}
}

func TestPaintAndLogoAndBoxes(t *testing.T) {
	in := sample(t)
	dir := t.TempDir()
	spec := filepath.Join(dir, "p.json")
	body := `{"paints":[{"id":"stamp","text":"PAID\n2026","page":1,"box":"crop","position":"top-right","font":"Helvetica-Bold","size":12,"color":"#B00000"}]}`
	if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o.pdf")
	code, out2 := runCLI(t, "fill", spec, in, "-o", out, "--strict")
	if code != report.OK {
		t.Fatalf("paint fill: exit %d: %s", code, out2)
	}
	var rep report.FillReport
	if err := json.Unmarshal(out2, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Paints) != 1 || rep.Paints[0].Page != 1 || rep.Paints[0].Size <= 0 {
		t.Fatalf("paints: %+v", rep.Paints)
	}
	// A bad page must be an error in strict mode.
	if err := os.WriteFile(spec, []byte(`{"paints":[{"text":"x","page":999}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCLI(t, "fill", spec, in, "-o", filepath.Join(dir, "o2.pdf"), "--strict"); code != report.InputErr {
		t.Fatalf("expected InputErr for page 999, got %d", code)
	}
}

func TestBoxesCLI(t *testing.T) {
	in := sample(t)
	code, out := runCLI(t, "pages", in)
	if code != report.OK {
		t.Fatalf("boxes: exit %d: %s", code, out)
	}
	var b []schema.PageGeometry
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[0].Boxes["crop"][2] <= b[0].Boxes["crop"][0] {
		t.Fatalf("boxes: %s", out)
	}
}

func TestDocAndUsage(t *testing.T) {
	if code, out := runCLI(t, "doc"); code != report.OK || !strings.Contains(string(out), "THE LOOP") {
		t.Fatalf("doc: exit %d", code)
	}
	if code, _ := runCLI(t, "nope"); code != report.Usage {
		t.Fatalf("unknown command: exit %d", code)
	}
	if code, _ := runCLI(t, "extract"); code != report.Usage {
		t.Fatalf("extract without args: exit %d", code)
	}
}

// textValueFor picks a value a field can display without clipping: no longer
// than its MaxLen and short enough for its widget.
func textValueFor(f schema.Field) string {
	want := "AB12"
	if f.MaxLen > 0 && f.MaxLen < len(want) {
		return want[:f.MaxLen]
	}
	if len(f.Rect) == 4 {
		// A very narrow widget clips the text: keep the shortest safe value.
		if f.Rect[2]-f.Rect[0] < 30 {
			return want[:2]
		}
	}
	return want
}

func TestPagesAndAddLogo(t *testing.T) {
	in := sample(t)
	dir := t.TempDir()

	geoms, err := pdf.Pages(in, "", []int{2})
	if err != nil {
		t.Fatal(err)
	}
	if len(geoms) != 1 || geoms[0].Index != 2 {
		t.Fatalf("pages: %+v", geoms)
	}
	g := geoms[0]
	if g.Width < 100 || g.Height < 100 {
		t.Fatalf("page size: %+v", g)
	}
	for _, name := range []string{"media", "crop", "content"} {
		r := g.Boxes[name]
		if len(r) != 4 || r[2] <= r[0] || r[3] <= r[1] {
			t.Fatalf("box %s: %v", name, r)
		}
	}
	if _, err := pdf.Pages(in, "", []int{99}); err == nil {
		t.Fatal("expected an error for a page out of range")
	}

	// Stamp the barcode image and check the placement is reported and the
	// image lands inside the page.
	img := filepath.Join(dir, "bar.png")
	if err := writeBarcodePNG(img, 240, 80); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "add-logo", in, img, "--page", "1", "--position", "top-right", "-o", filepath.Join(dir, "stamped.pdf"), "--strict")
	if code != report.OK {
		t.Fatalf("add-logo: exit %d: %s", code, out)
	}
	var rep report.FillReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Logos) != 1 {
		t.Fatalf("logos: %+v", rep.Logos)
	}
	logo := rep.Logos[0]
	crop := g.Boxes["crop"]
	if logo.Page != 1 || logo.Rect[0] < crop[0] || logo.Rect[2] > crop[2] || logo.Rect[3] > crop[3] {
		t.Fatalf("logo outside the page: %+v (crop %v)", logo, crop)
	}
	if logo.Size[0] <= 0 || logo.Size[1] <= 0 {
		t.Fatalf("logo size: %+v", logo)
	}
}

func writeBarcodePNG(path string, w, h int) error {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			c := color.RGBA{255, 255, 255, 255}
			if (x/6)%2 == 0 {
				c = color.RGBA{0, 0, 0, 255}
			}
			img.Set(x, y, c)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// The metadata produced by `extract` must be usable as the input of `fill`
// without translation: that is the contract of the tool.
func TestExtractOutputIsFillInput(t *testing.T) {
	in := sample(t)
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.json")
	if code, _ := runCLI(t, "extract", in, "-o", spec); code != report.OK {
		t.Fatalf("extract: exit %d", code)
	}
	sch, err := schema.ReadFormSchema(spec)
	if err != nil {
		t.Fatal(err)
	}
	if sch.Source != in {
		t.Fatalf("source: %q", sch.Source)
	}
	// Edit the schema in place, the way the guide describes.
	edited := filepath.Join(dir, "edited.json")
	b := string(mustJSON(t, sch))
	var doc map[string]any
	if err := json.Unmarshal([]byte(b), &doc); err != nil {
		t.Fatal(err)
	}
	// Pick one field that can display the value without clipping (the tool
	// clips to maxLen on purpose), and edit only that one.
	for _, raw := range doc["fields"].([]any) {
		f := raw.(map[string]any)
		ro := strings.Contains(strings.Join(toStrings(f["flags"]), ","), "readOnly")
		max, _ := f["maxLen"].(float64)
		if f["type"] == "text" && !ro && (max == 0 || max >= 6) {
			f["value"] = "EDITED"
			break
		}
	}
	if err := os.WriteFile(edited, mustJSON(t, doc), 0o644); err != nil {
		t.Fatal(err)
	}
	filled := filepath.Join(dir, "filled.pdf")
	// No document argument: the source recorded in the schema is used.
	code, out := runCLI(t, "fill", edited, "-o", filled, "--strict")
	if code != report.OK && code != report.Partial {
		t.Fatalf("fill from schema: exit %d: %s", code, out)
	}
	var rep report.FillReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Applied) == 0 {
		t.Fatalf("nothing applied: %s", out)
	}
	if code, _ := runCLI(t, "verify", filled, edited); code != report.OK {
		t.Fatalf("verify schema-shaped spec: exit %d", code)
	}
	var v report.VerifyReport
	_, out = runCLI(t, "verify", filled, edited)
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Matches) != len(rep.Applied) || len(v.Mismatches) != 0 {
		t.Fatalf("matches: %+v", v)
	}
	editedValue := false
	for _, m := range v.Matches {
		if m.Want == "EDITED" {
			editedValue = true
		}
	}
	if !editedValue {
		t.Fatalf("the edited value is not in the report: %+v", v.Matches)
	}
}

func toStrings(v any) []string {
	out := []string{}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
