package pdf

// This file exposes the layout geometry of a generated page. A caller that
// stamps a page number, a signature line or a logo below generated text needs
// to know where the content actually ended; until now the only way was to
// reverse-engineer it from the rendered bytes.

// PlacedLine is one typeset line, positioned in default user space (origin at
// the page's lower-left corner, y growing up). y is the baseline.
type PlacedLine struct {
	X, Y   float64
	Size   float64
	Align  string
	Width  float64
	Parts  []PlacedPart
	Reason string // non-empty when the line was forced onto a new page
}

// PlacedPart is a run of same-styled text within a line.
type PlacedPart struct {
	Text string
	Font string
	Size float64
	X    float64

	// Gap reports that the source separated this word from the previous one
	// with whitespace. Painting does not need it (X already places the word),
	// but anything reading the text back does: without it the words of a line
	// rejoin as "TheClientshallpay".
	Gap bool
}

// Text re-joins the parts of a line into the string it renders, spaces
// included. pdftotext recovers the same string from the x coordinates; this
// does it without a render.
func (l PlacedLine) Text() string {
	var b []byte
	for _, p := range l.Parts {
		if p.Gap && len(b) > 0 {
			b = append(b, ' ')
		}
		b = append(b, p.Text...)
	}
	return string(b)
}

// PlacedRule is a horizontal line drawn across a page.
type PlacedRule struct {
	X, Y, W float64
	Thick   float64
	Gray    float64
}

func exportLines(in []layoutLine) []PlacedLine {
	if len(in) == 0 {
		return nil
	}
	out := make([]PlacedLine, 0, len(in))
	for _, l := range in {
		pl := PlacedLine{X: l.x, Y: l.y, Size: l.size, Align: l.align, Width: l.width}
		for _, p := range l.parts {
			pl.Parts = append(pl.Parts, PlacedPart{
				Text: p.text, Font: p.fam, Size: p.size, X: p.x, Gap: p.gap,
			})
		}
		out = append(out, pl)
	}
	return out
}

func exportRules(in []layoutRule) []PlacedRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]PlacedRule, 0, len(in))
	for _, r := range in {
		out = append(out, PlacedRule{X: r.x, Y: r.y, W: r.w, Thick: r.thick, Gray: r.gray})
	}
	return out
}
