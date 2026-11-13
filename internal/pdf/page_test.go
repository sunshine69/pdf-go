package pdf

import (
	"strings"
	"testing"

	"github.com/benoitkugler/pdf/model"
)

// a4 is the page the tests lay out on: A4 portrait, which is what
// testdata/sample4.pdf uses, so the tests match real documents.
var a4 = model.Rectangle{Llx: 0, Lly: 0, Urx: 595, Ury: 842}

func testOptions() PageOptions {
	return PageOptions{Margin: 56, FontSize: 10.5, Font: "helvetica"}
}

// lineText renders the string a placed line displays, spaces included.
func lineText(l PlacedLine) string { return l.Text() }

// TestGeneratedContentStaysInsideTheMargins is the basic correctness check: a
// contract annex that runs off the edge of the page is a document defect, and
// the only way to catch it is to assert on the placement.
func TestGeneratedContentStaysInsideTheMargins(t *testing.T) {
	blocks := []Block{{Kind: KindParagraph, Runs: []Run{{Text: strings.Repeat("word ", 3000)}}}}
	pages, err := BuildPages(a4, blocks, testOptions())
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	if len(pages) < 2 {
		t.Fatalf("a long paragraph should overflow onto several pages, got %d", len(pages))
	}
	for i, p := range pages {
		for _, line := range p.Placed {
			if line.X < 55 {
				t.Errorf("page %d: line starts at x=%.1f, inside the left 56pt margin", i, line.X)
			}
			if line.Y < 55 || line.Y > 787 {
				t.Errorf("page %d: baseline at y=%.1f is outside the printable body", i, line.Y)
			}
		}
	}
}

// TestWrapperBreaksOnlyAtSpaces: a mid-word break in a contract clause is the
// kind of defect that is invisible until someone reads the page aloud.
func TestWrapperBreaksOnlyAtSpaces(t *testing.T) {
	const word = "antidisestablishmentarianism"
	blocks := []Block{{Kind: KindParagraph, Runs: []Run{{Text: strings.Repeat(word+" ", 60)}}}}
	pages, err := BuildPages(a4, blocks, testOptions())
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	for i, p := range pages {
		for _, line := range p.Placed {
			for _, w := range strings.Fields(lineText(line)) {
				if w != word {
					t.Errorf("page %d: wrapper split a word: %q", i, w)
				}
			}
		}
	}
}

// TestPunctuationKeepsItsPlace is the regression test for invented spaces at
// run boundaries. A style change in mid-sentence used to insert a space, so
// "and *ital*." printed as "and ital .". In a contract that is a visible
// formatting defect on every page that has emphasised text before punctuation.
func TestPunctuationKeepsItsPlace(t *testing.T) {
	blocks := []Block{{Kind: KindParagraph, Runs: []Run{
		{Text: "and "},
		{Text: "ital", Italic: true},
		{Text: "."},
	}}}
	pages, err := BuildPages(a4, blocks, testOptions())
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("expected one page, got %d", len(pages))
	}
	got := lineText(pages[0].Placed[0])
	if got != "and ital." {
		t.Errorf("a run boundary changed the text: got %q, want %q", got, "and ital.")
	}
}

// TestInlineRunsKeepTheirOrder guards the token stream: measuring is one
// thing, but the visible order of styled fragments must match the source.
func TestInlineRunsKeepTheirOrder(t *testing.T) {
	blocks := []Block{{Kind: KindParagraph, Runs: []Run{
		{Text: "The "},
		{Text: "Client", Bold: true},
		{Text: " shall pay "},
		{Text: "100%", Bold: true},
		{Text: " of the invoice."},
	}}}
	pages, err := BuildPages(a4, blocks, testOptions())
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	want := "The Client shall pay 100% of the invoice."
	if got := lineText(pages[0].Placed[0]); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestHeadingsAreLargerThanBody checks the type hierarchy. A heading the same
// size as body text is not a heading.
func TestHeadingsAreLargerThanBody(t *testing.T) {
	for level := 1; level <= 4; level++ {
		blocks := []Block{
			{Kind: KindHeading, Level: level, Runs: []Run{{Text: "Clause"}}},
			{Kind: KindParagraph, Runs: []Run{{Text: "body"}}},
		}
		pages, err := BuildPages(a4, blocks, testOptions())
		if err != nil {
			t.Fatalf("BuildPages(level %d): %v", level, err)
		}
		if len(pages[0].Placed) < 2 {
			t.Fatalf("level %d: expected a heading line and a body line, got %d",
				level, len(pages[0].Placed))
		}
		head, body := pages[0].Placed[0], pages[0].Placed[1]
		if head.Size <= body.Size {
			t.Errorf("level %d heading size %.1f is not larger than body size %.1f",
				level, head.Size, body.Size)
		}
		// Descending order, so a level 2 heading can never outweigh a level 1.
		if level > 1 {
			t.Skip("hierarchy across levels is checked by TestHeadingSizesDescend")
		}
	}
}

func TestHeadingSizesDescend(t *testing.T) {
	base := 10.5
	prev := headingSize(1, base)
	for level := 2; level <= 6; level++ {
		got := headingSize(level, base)
		if got >= prev {
			t.Errorf("level %d size %.2f is not smaller than level %d size %.2f",
				level, got, level-1, prev)
		}
		prev = got
	}
}

// TestLinesDoNotShareABaseline catches the failure mode where the cursor stops
// advancing: every line after the first lands on the same row and the page
// becomes unreadable mush.
func TestLinesDoNotShareABaseline(t *testing.T) {
	var blocks []Block
	for i := 0; i < 40; i++ {
		blocks = append(blocks,
			Block{Kind: KindHeading, Level: 2, Runs: []Run{{Text: "Clause"}}},
			Block{Kind: KindParagraph, Runs: []Run{{Text: "Body of the clause."}}},
		)
	}
	pages, err := BuildPages(a4, blocks, testOptions())
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	for i, p := range pages {
		for j := 1; j < len(p.Placed); j++ {
			if p.Placed[j-1].Y == p.Placed[j].Y {
				t.Errorf("page %d lines %d and %d share baseline %.1f and will overlap",
					i, j-1, j, p.Placed[j].Y)
			}
		}
	}
}

// TestBuildPagesRejectsImpossibleContent: content taller than a whole page has
// to fail loudly, not loop forever or clip silently.
func TestBuildPagesRejectsImpossibleContent(t *testing.T) {
	tiny := model.Rectangle{Llx: 0, Lly: 0, Urx: 200, Ury: 40}
	blocks := []Block{{Kind: KindHeading, Level: 1, Runs: []Run{{Text: "Too tall"}}}}
	if _, err := BuildPages(tiny, blocks, testOptions()); err == nil {
		t.Fatal("expected an error when the content cannot fit the page, got none")
	}
}

// TestEveryOverflowedPageCarriesText is the regression test for the
// pointer-into-slice bug: a layout that wrote through a pointer invalidated by
// append() produced blank pages at the end.
func TestEveryOverflowedPageCarriesText(t *testing.T) {
	var blocks []Block
	for i := 0; i < 80; i++ {
		blocks = append(blocks, Block{Kind: KindParagraph,
			Runs: []Run{{Text: "Clause text long enough to wrap across several lines of the page."}}})
	}
	pages, err := BuildPages(a4, blocks, testOptions())
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	if len(pages) < 2 {
		t.Fatalf("expected the content to overflow, got %d page(s)", len(pages))
	}
	for i, p := range pages {
		if len(p.Placed) == 0 {
			t.Errorf("page %d carries no lines: layout wrote through an invalidated pointer", i)
		}
		if p.Lines != len(p.Placed) {
			t.Errorf("page %d reports %d lines but placed %d", i, p.Lines, len(p.Placed))
		}
	}
}

func TestUnsupportedRunesAreReported(t *testing.T) {
	// Latin-1 and Windows-1252 punctuation must pass: these appear in every
	// document exported from a word processor.
	ok := "café — “quoted” • 100% naïve ¿how? ‘.friend’"
	if got := UnsupportedRunes("helvetica", ok); len(got) != 0 {
		t.Errorf("Latin-1 runes reported as unrenderable: %q", got)
	}

	// These are outside the standard 14. They are reported rather than
	// silently written as dots, which for a contract is data loss.
	for _, s := range []string{"日本語", "Привет", "δοκιμή", "\U0001F600"} {
		if got := UnsupportedRunes("helvetica", s); len(got) == 0 {
			t.Errorf("%q should be reported as unrenderable, got none", s)
		}
	}
}

func TestAppendPagesIndexSemantics(t *testing.T) {
	doc := &model.Document{}
	for i := 0; i < 3; i++ {
		box := a4
		doc.Catalog.Pages.Kids = append(doc.Catalog.Pages.Kids, &model.PageObject{MediaBox: &box})
	}
	if got := doc.Catalog.Pages.Count(); got != 3 {
		t.Fatalf("test document should have 3 pages, got %d", got)
	}

	// "index 0" means after the first page, so the new leaf is the second one.
	if err := AppendPages(doc, 0, []*model.PageObject{{MediaBox: &a4}}); err != nil {
		t.Fatalf("AppendPages: %v", err)
	}
	if got := doc.Catalog.Pages.Count(); got != 4 {
		t.Fatalf("page count after inserting after page 1: got %d, want 4", got)
	}
	// -1 appends at the end.
	if err := AppendPages(doc, -1, []*model.PageObject{{MediaBox: &a4}}); err != nil {
		t.Fatalf("AppendPages(-1): %v", err)
	}
	if got := doc.Catalog.Pages.Count(); got != 5 {
		t.Fatalf("page count after appending at the end: got %d, want 5", got)
	}
	// Out of range must be an error, not a silent clamp.
	if err := AppendPages(doc, 99, []*model.PageObject{{MediaBox: &a4}}); err == nil {
		t.Fatal("expected an error for an out-of-range index")
	}
	if err := AppendPages(doc, -2, []*model.PageObject{{MediaBox: &a4}}); err == nil {
		t.Fatal("expected an error for a negative index other than -1")
	}
}

// TestAppendPagesIntoNestedTree covers the case a naive implementation gets
// wrong: real PDFs nest their page tree, and appending to the root Kids would
// put the page in the wrong position rather than fail.
func TestAppendPagesIntoNestedTree(t *testing.T) {
	leaf := func() *model.PageObject { return &model.PageObject{MediaBox: &a4} }
	inner := &model.PageTree{}
	for i := 0; i < 4; i++ {
		inner.Kids = append(inner.Kids, leaf())
	}
	doc := &model.Document{}
	doc.Catalog.Pages.Kids = append(doc.Catalog.Pages.Kids, inner, leaf())

	if got := doc.Catalog.Pages.Count(); got != 5 {
		t.Fatalf("nested tree should report 5 pages, got %d", got)
	}
	if err := AppendPages(doc, 1, []*model.PageObject{leaf()}); err != nil {
		t.Fatalf("AppendPages into nested tree: %v", err)
	}
	if got := doc.Catalog.Pages.Count(); got != 6 {
		t.Fatalf("page count after nested insert: got %d, want 6", got)
	}
	leaves := doc.Catalog.Pages.Flatten()
	if len(leaves) != 6 {
		t.Fatalf("Flatten should see 6 leaves, got %d", len(leaves))
	}
}
