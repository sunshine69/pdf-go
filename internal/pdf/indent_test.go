package pdf

import "testing"

// TestBlockIndentStaysInsideTheMargin pins the fix for a layout bug that was
// invisible in the CLI output: Level means nesting depth for body text, and a
// top-level paragraph carries Level 0. The old formula subtracted one from it,
// so every generated page pulled its body text 18pt into the left margin.
func TestBlockIndentStaysInsideTheMargin(t *testing.T) {
	flush := []Block{
		{Kind: KindParagraph, Runs: []Run{{Text: "x"}}},
		{Kind: KindHeading, Level: 3, Runs: []Run{{Text: "x"}}},
		{Kind: KindHeading, Level: 1, Runs: []Run{{Text: "x"}}},
		{Kind: KindRule},
	}
	for _, blk := range flush {
		if got := blockIndent(blk); got != 0 {
			t.Errorf("%v at level %d indents %.1f, want flush with the content edge",
				blk.Kind, blk.Level, got)
		}
	}

	// Nesting still indents, and never by a negative amount.
	for depth := 1; depth <= 4; depth++ {
		for _, kind := range []BlockKind{KindParagraph, KindListItem, KindQuote, KindCode} {
			got := blockIndent(Block{Kind: kind, Level: depth})
			if got <= 0 {
				t.Errorf("%v at nesting depth %d indents %.1f, want a positive indent",
					kind, depth, got)
			}
		}
	}

	// An explicit indent is the author's, not ours to reinterpret.
	if got := blockIndent(Block{Kind: KindHeading, Level: 2, Style: BlockStyle{Indent: 40}}); got != 40 {
		t.Errorf("an explicit indent was overridden: got %.1f, want 40", got)
	}
}
