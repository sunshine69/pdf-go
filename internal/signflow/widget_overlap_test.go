package signflow

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"
)

// The appearance of a signature is a box, and the boxes of successive parties
// are stacked down the same column. If one box reaches into the next, the later
// signature paints over the earlier one: with a drawn signature image occupying
// the lower half of the box, that is the image covering the party above's typed
// name. The rects written into the finished PDF are the ground truth, so the
// test reads them from the bytes rather than from the code that produced them.
func TestPartySignatureBoxesDoNotOverlap(t *testing.T) {
	f := newBatchFixture(t, 3)
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")

	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	data, err := f.deps.Store.GetPDF(out.Final)
	if err != nil {
		t.Fatalf("read final document: %v", err)
	}

	const sigW = 220.0
	boxes := sigBoxes(t, data)
	if len(boxes) < 3 {
		t.Fatalf("found %d signature boxes of width %g in the signed PDF, want at least 3",
			len(boxes), sigW)
	}
	sortRects(boxes)
	for i := 0; i+1 < len(boxes); i++ {
		lower, upper := boxes[i], boxes[i+1]
		// Two boxes stacked in the same column meet when the top of the lower
		// one passes the bottom of the upper one.
		if overlap := lower.y1 - upper.y0; overlap > 0 {
			t.Errorf("signature box %d (y %.0f..%.0f) overlaps box %d (y %.0f..%.0f) by %.0f pt; "+
				"the later signature paints over the earlier one",
				i, lower.y0, lower.y1, i+1, upper.y0, upper.y1, overlap)
		}
	}
}

// sortRects orders the boxes bottom to top by their lower edge.
func sortRects(rs []rect) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].y0 < rs[j-1].y0; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

type rect struct{ x0, y0, x1, y1 float64 }

var rectRe = regexp.MustCompile(`/Rect\s*\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]`)

// sigBoxes returns the widget rectangles of the signature fields, identified by
// the width every signature widget is placed at. The document's own form fields
// are other sizes, and the certification signature shares the column, so "all
// boxes of the signature width, bottom to top" is exactly the stack under test.
func sigBoxes(t *testing.T, pdf []byte) []rect {
	t.Helper()
	var got []rect
	for _, m := range rectRe.FindAllSubmatch(pdf, -1) {
		r := rect{
			x0: mustFloat(t, m[1]),
			y0: mustFloat(t, m[2]),
			x1: mustFloat(t, m[3]),
			y1: mustFloat(t, m[4]),
		}
		if r.x1-r.x0 == signpdfWidgetWidth {
			got = append(got, r)
		}
	}
	if !bytes.Contains(pdf, []byte("/Sig")) {
		t.Fatal("signed PDF carries no signature field; the boxes found are not signatures")
	}
	return got
}

// signpdfWidgetWidth is the width every signature widget is placed at, mirroring
// partyWidget. It is a copy on purpose: a test that recomputed the width from
// the same function could not notice the width changing.
const signpdfWidgetWidth = 220.0

func mustFloat(t *testing.T, b []byte) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		t.Fatalf("parse %q: %v", b, err)
	}
	return f
}
