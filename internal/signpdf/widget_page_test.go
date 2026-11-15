package signpdf

import "testing"

// The page a signature lands on.
//
// PartyWidget used to return Page: 1 unconditionally, so every envelope in the
// system signed on page 1 however the drafter had placed the signature boxes.
// These tests pin the two things that were wrong: that a base naming a page is
// honoured, and that the stack offsets within that page rather than walking the
// later signatures back onto page 1.

func TestPartyWidgetDefaultReproducesTheFixedColumn(t *testing.T) {
	// A zero base is what every envelope created before there were widget
	// columns reads back as. Its geometry must not drift, or the fix moves
	// every existing document's signatures.
	first := PartyWidget(Widget{}, 0)
	if first.Page != 1 {
		t.Errorf("default first page = %d, want 1", first.Page)
	}
	if first.X != WidgetX || first.Y != WidgetY {
		t.Errorf("default first box = (%v,%v), want (%v,%v)",
			first.X, first.Y, WidgetX, WidgetY)
	}
	if first.W != AppearanceWidth || first.H != AppearanceHeight {
		t.Errorf("default box = %vx%v, want %vx%v",
			first.W, first.H, AppearanceWidth, AppearanceHeight)
	}
	for i := 1; i < 4; i++ {
		want := WidgetY + WidgetStride*float64(i)
		if got := PartyWidget(Widget{}, i).Y; got != want {
			t.Errorf("party %d sits at y=%v, want %v", i, got, want)
		}
	}
}

func TestPartyWidgetHonoursABaseThatNamesAPage(t *testing.T) {
	for _, page := range []int{2, 3, 17} {
		for i := 0; i < 3; i++ {
			w := PartyWidget(Widget{Page: page}, i)
			if w.Page != page {
				t.Errorf("party %d on page %d landed on page %d", i, page, w.Page)
			}
			// The page moves; the column and the stack do not change shape.
			if w.X != WidgetX {
				t.Errorf("party %d on page %d moved to x=%v, want %v", i, page, w.X, WidgetX)
			}
			if want := WidgetY + WidgetStride*float64(i); w.Y != want {
				t.Errorf("party %d on page %d sits at y=%v, want %v", i, page, w.Y, want)
			}
		}
	}
}

func TestPartyWidgetStacksUpwardFromACoordinateBase(t *testing.T) {
	// PDF's origin is the bottom-left, so a stack grows upward. A base of the
	// default corner has to reproduce the default column, which is what makes
	// the two paths one geometry instead of two.
	base := Widget{Page: 2, X: WidgetX, Y: WidgetY}
	for i := 0; i < 3; i++ {
		got := PartyWidget(base, i)
		want := PartyWidget(Widget{}, i)
		if got.X != want.X || got.Y != want.Y {
			t.Errorf("coordinate base party %d = (%v,%v), want the default column (%v,%v)",
				i, got.X, got.Y, want.X, want.Y)
		}
		if got.Page != 2 {
			t.Errorf("coordinate base party %d landed on page %d, want 2", i, got.Page)
		}
	}
	if top, below := PartyWidget(base, 1), PartyWidget(base, 0); top.Y <= below.Y {
		t.Errorf("party 1 at y=%v is not above party 0 at y=%v; the stack walks down into overlap",
			top.Y, below.Y)
	}
	if gap := PartyWidget(base, 1).Y - PartyWidget(base, 0).Y; gap < AppearanceHeight {
		t.Errorf("stack gap = %v, less than the %v pt box height; boxes will overlap",
			gap, AppearanceHeight)
	}
}

func TestPartyWidgetKeepsACallerSizedBox(t *testing.T) {
	w := PartyWidget(Widget{W: 300, H: 120}, 1)
	if w.W != 300 || w.H != 120 {
		t.Errorf("caller box = %vx%v, want 300x120", w.W, w.H)
	}
}

// A named field carries one signature: its own rectangle. Offsetting the stack
// from a field would walk the second party's box off the field, which is worse
// than falling back to the default column.
func TestPartyWidgetAnchorsOnlyTheFirstPartyToAField(t *testing.T) {
	base := Widget{Field: "Signature", Page: 4}
	if got := PartyWidget(base, 0); got.Field != "Signature" {
		t.Errorf("first party field = %q, want the anchor to survive", got.Field)
	}
	if got := PartyWidget(base, 1); got.Field != "" {
		t.Errorf("second party field = %q, want the anchor dropped to the stack", got.Field)
	}
	if got := PartyWidget(base, 1); got.Page != 4 {
		t.Errorf("second party page = %d, want the anchored page kept", got.Page)
	}
	if got := PartyWidget(base, 1); got.Y != WidgetY+WidgetStride {
		t.Errorf("second party y = %v, want the default stack row", got.Y)
	}
}

func TestPartyWidgetNormalisesAJunkPage(t *testing.T) {
	for _, page := range []int{0, -1, -40} {
		if got := PartyWidget(Widget{Page: page}, 0).Page; got != 1 {
			t.Errorf("page %d normalised to %d, want 1", page, got)
		}
	}
}
