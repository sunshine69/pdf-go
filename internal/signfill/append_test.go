package signfill

import (
	"fmt"
	"strings"
	"testing"

	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/pdf"
	"github.com/sunshine69/pdf-go/internal/report"
)

// appendProbe runs Append on the sample document and returns the report, the
// output bytes, and the page count of the result as the reader sees it.
func appendProbe(t *testing.T, text string, o AppendOptions) (report.AppendReport, []byte, int) {
	t.Helper()
	rep, out, err := Append(sampleBytes(t), text, o)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	path := writeTemp(t, out)
	doc, _, err := pdf.Load(path, "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return rep, out, doc.Catalog.Pages.Count()
}

// TestAppendAddsPagesAtTheEnd is the base case for the whole feature: a signed
// contract with a terms annex appended must still open, and must be one page
// longer with the annex last.
func TestAppendAddsPagesAtTheEnd(t *testing.T) {
	rep, _, n := appendProbe(t, "## Payment\n\nThe client shall pay within 30 days.", AppendOptions{
		Format: "markdown",
		At:     -1,
	})
	before := pageCount(t, sampleBytes(t))
	if n != before+rep.Added {
		t.Errorf("reader sees %d pages, source had %d and the report claims %d added",
			n, before, rep.Added)
	}
	if rep.Added < 1 {
		t.Fatalf("no page was added")
	}
	if rep.Lines < 2 {
		t.Errorf("only %d lines typeset, a heading and a sentence need at least 2", rep.Lines)
	}
	// -1 asks for the end; the report has to say which page that turned out to
	// be, not echo the sentinel back.
	if rep.At != before-1 {
		t.Errorf("at = %d, want %d (the last page of the source)", rep.At, before-1)
	}
}

// TestInsertAfterPageLandsAfterIt guards the bug where --at 0 put the new page
// at the front of the document. In a signing flow that is the difference
// between an annex after the signature block and an annex before the cover.
func TestInsertAfterPageLandsAfterIt(t *testing.T) {
	before := pageCount(t, sampleBytes(t))
	rep, out, n := appendProbe(t, "Annex body text.", AppendOptions{Format: "text", At: 0})
	if n != before+rep.Added {
		t.Fatalf("reader sees %d pages, want %d", n, before+rep.Added)
	}
	if rep.At != 0 {
		t.Errorf("at = %d, want the requested 0 echoed back", rep.At)
	}
	leaves := leavesOf(t, out)
	// The added page follows the source pages in document order; if it had been
	// spliced before leaf 0 the count would match and the order would not.
	if len(leaves) != n {
		t.Fatalf("flattened page tree has %d leaves, want %d", len(leaves), n)
	}
}

// TestAddedPagesCopyTheSourceGeometry: an annex printed on A4 and stapled to a
// Letter contract is a document defect nobody notices until it is faxed.
func TestAddedPagesCopyTheSourceGeometry(t *testing.T) {
	in := sampleBytes(t)
	src := leavesOf(t, in)
	if len(src) == 0 {
		t.Skip("sample has no pages")
	}
	want := src[len(src)-1].MediaBox
	_, out, _ := appendProbe(t, "Annex body text.", AppendOptions{Format: "text", At: -1})
	got := leavesOf(t, out)
	last := got[len(got)-1]
	if last.MediaBox.Urx != want.Urx || last.MediaBox.Ury != want.Ury {
		t.Errorf("added page is %vx%v, source last page is %vx%v",
			last.MediaBox.Urx, last.MediaBox.Ury, want.Urx, want.Ury)
	}
}

func TestAppendRejectsWhatItCannotDo(t *testing.T) {
	in := sampleBytes(t)
	cases := []struct {
		name string
		in   []byte
		text string
		o    AppendOptions
		want string
	}{
		{"not a pdf", []byte("plain text"), "x", AppendOptions{At: -1}, "not a PDF"},
		{"empty", nil, "x", AppendOptions{At: -1}, "empty document"},
		{"no text", in, "   ", AppendOptions{At: -1}, ""},
		{"index out of range", in, "x", AppendOptions{At: 99}, "out of range"},
		{"index below -1", in, "x", AppendOptions{At: -2}, "invalid"},
		{"unknown format", in, "x", AppendOptions{At: -1, Format: "docx"}, "docx"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Append(c.in, c.text, c.o)
			if err == nil {
				t.Fatalf("no error returned")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// TestAppendReportsUnrenderableGlyphs: silently turning 日本語 into dots is how
// an automated pipeline ships an unreadable annex.
func TestAppendReportsUnrenderableGlyphs(t *testing.T) {
	rep, _, err := Append(sampleBytes(t), "日本語", AppendOptions{At: -1, Format: "text"})
	if err != nil {
		t.Fatalf("non-strict Append failed: %v", err)
	}
	if len(rep.Warnings) == 0 {
		t.Errorf("CJK text produced no warning; the reader gets dots and nobody is told")
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "U+65E5") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings do not name the offending rune: %v", rep.Warnings)
	}

	if _, _, err := Append(sampleBytes(t), "日本語", AppendOptions{At: -1, Format: "text", Strict: true}); err == nil {
		t.Errorf("--strict accepted text it cannot render")
	}
}

// TestAppendKeepsTheForm: an appended annex must not disturb the AcroForm the
// signer is about to fill. Counting fields is not enough - the values and the
// pages the widgets sit on have to survive too, because a widget left pointing
// at the wrong leaf still reports the right field count.
func TestAppendKeepsTheForm(t *testing.T) {
	in := sampleBytes(t)
	before, err := formSnapshot(t, in)
	if err != nil {
		t.Skipf("sample has no form: %v", err)
	}
	if len(before) == 0 {
		t.Skip("sample form has no fields")
	}
	_, out, _ := appendProbe(t, "Annex body text.", AppendOptions{Format: "text", At: -1})
	after, err := formSnapshot(t, out)
	if err != nil {
		t.Fatalf("form unreadable after append: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("form had %d fields before and %d after appending a page", len(before), len(after))
	}
	for name, was := range before {
		now, ok := after[name]
		if !ok {
			t.Errorf("field %q disappeared when a page was appended", name)
			continue
		}
		if now != was {
			t.Errorf("field %q read %q before the append and %q after", name, was, now)
		}
	}
}

func pageCount(t *testing.T, in []byte) int {
	t.Helper()
	return len(leavesOf(t, in))
}

// leavesOf re-reads a document from disk and returns its pages as a reader
// would walk them, so the assertions describe the shipped file rather than the
// tree the builder left in memory.
func leavesOf(t *testing.T, in []byte) []model.PageObject {
	t.Helper()
	doc, _, err := pdf.Load(writeTemp(t, in), "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	raw := doc.Catalog.Pages.FlattenInherit()
	return raw
}

// formSnapshot reads the AcroForm of a document on disk into a comparable
// string per field. Type, value, widget page and rectangle are included on
// purpose: a page tree spliced wrongly can keep the field count and lose the
// geometry, and the annex would then sit on top of a signature.
func formSnapshot(t *testing.T, in []byte) (map[string]string, error) {
	t.Helper()
	s, err := extractFrom(writeTemp(t, in))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(s.Fields))
	for _, f := range s.Fields {
		out[f.Name] = fmt.Sprintf("%s|%s|%v|%d|%v", f.Type, f.Value, f.Values, f.Page, f.Rect)
	}
	return out, nil
}
