package pdf

import (
	"fmt"
	"image/color"
	"math"
	"strings"

	cs "github.com/benoitkugler/pdf/contentstream"
	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// PaintPlacement records where a painted text block landed, echoed back in the
// fill report so a caller can confirm placement without opening the file.
type PaintPlacement struct {
	ID       string    `json:"id,omitempty"`
	Page     int       `json:"page"`
	Box      string    `json:"box,omitempty"`
	Position string    `json:"position,omitempty"`
	Field    string    `json:"field,omitempty"`
	Rect     []float64 `json:"rect"`
	Lines    int       `json:"lines"`
	Size     float64   `json:"size"`
	Font     string    `json:"font,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// PaintText draws text directly on a page: reference numbers, dates, captions,
// stamps. Like a logo this is plain page content, not an annotation, so it
// prints identically and cannot be edited in a viewer.
//
// Placement follows the same rules as StampLogo: an explicit rect, the rect of
// a form field, or an anchor (box + position) inside a page.
func PaintText(pageIdx int, page *model.PageObject, p schema.Paint, target *FieldTarget) (PaintPlacement, error) {
	var out PaintPlacement
	out.ID, out.Page, out.Field, out.Font = p.ID, pageIdx, p.Field, p.Font
	out.Box = NormalizeBox(p.Box)
	if out.Box == "" {
		out.Box = BoxMedia
	}
	out.Position = normalizePosition(p.Position)

	if p.Text == "" {
		return out, fmt.Errorf("paint %s: no text", paintLabel(p))
	}
	if page.Resources == nil {
		res := model.NewResourcesDict()
		page.Resources = &res
	}

	// The page font dictionary is used for the metrics and is the object that
	// ends up in the resources, so measurement and output agree.
	fontName := canonicalFontName(p.Font)
	res := ensureFontResources(page, fontName)
	fd := res.Font[model.ObjName(fontName)]
	out.Font = fontName
	bf, err := builtFont(fd)
	if err != nil {
		return out, fmt.Errorf("paint %s: %w", paintLabel(p), err)
	}

	size := model.Fl(p.Size)
	if size <= 0 {
		size = 12
	}
	leading := model.Fl(p.Leading)
	if leading <= 0 {
		leading = size * 1.2
	}

	lines := strings.Split(strings.ReplaceAll(p.Text, "\r\n", "\n"), "\n")
	widths := make([]Fl, 0, len(lines))
	var widest Fl
	for _, line := range lines {
		w := textWidth(bf, line, size)
		widths = append(widths, w)
		if w > widest {
			widest = w
		}
	}
	blockW, blockH := widest, model.Fl(len(lines))*leading

	var rect model.Rectangle
	var err2 error
	// fitted is true when the rectangle was built around the text (the anchor
	// case): by construction the text fits, so no overflow check is needed.
	fitted := false
	switch {
	case len(p.Rect) == 4:
		rect, err2 = ParseRect(p.Rect)
	case target != nil && len(target.Rect) == 4:
		rect, err2 = ParseRect(target.Rect)
	default:
		fitted = true
		var box model.Rectangle
		if box, err2 = ResolveBox(page, out.Box); err2 != nil {
			return out, err2
		}
		if rect, err2 = Anchor(box, blockW, blockH, F(p.Margin), out.Position); err2 != nil {
			return out, err2
		}
		ox, oy := ParseOffset(p.Offset)
		rect = model.Rectangle{
			Llx: rect.Llx + ox, Lly: rect.Lly + oy,
			Urx: rect.Urx + ox, Ury: rect.Ury + oy,
		}
	}
	if err2 != nil {
		return out, err2
	}
	if rect.Urx <= rect.Llx || rect.Ury <= rect.Lly {
		return out, fmt.Errorf("paint %s: target rectangle is empty", paintLabel(p))
	}

	gs := cs.NewGraphicStream(model.Rectangle{
		Llx: rect.Llx - 20, Lly: rect.Lly - 20,
		Urx: rect.Urx + 20, Ury: rect.Ury + 20,
	})
	gs.SaveState()
	if p.Opacity > 0 && p.Opacity < 1 {
		gs.SetFillAlpha(F(p.Opacity))
	}
	if c, ok := parseColor(p.Color); ok {
		gs.SetColorFill(c)
	}
	if p.Rotate != 0 {
		cos, sin := model.Fl(math.Cos(p.Rotate*math.Pi/180)), model.Fl(math.Sin(p.Rotate*math.Pi/180))
		gs.Transform(model.Matrix{cos, sin, -sin, cos, 0, 0})
	}

	gs.BeginText()
	gs.SetFontAndSize(bf, size)
	gs.SetLeading(leading)

	// First baseline: the top of the box, minus the ascender.
	y := rect.Ury - size*0.85
	for i, line := range lines {
		x := rect.Llx
		switch strings.ToLower(p.Align) {
		case "center", "centre", "middle":
			x += (rect.Urx - rect.Llx - widths[i]) / 2
		case "right", "right-aligned":
			x += rect.Urx - rect.Llx - widths[i]
		}
		gs.SetTextMatrix(1, 0, 0, 1, x, y-model.Fl(i)*leading)
		if err := gs.ShowText(line); err != nil {
			return out, fmt.Errorf("paint %s: %w", paintLabel(p), err)
		}
	}
	gs.EndText()
	if err := gs.RestoreState(); err != nil {
		return out, err
	}

	form := gs.ToXFormObject(true)
	name := addXObjectForm(page.Resources, form)
	content := fmt.Sprintf("q\n/%s Do\nQ\n", name)
	page.Contents = append(page.Contents, model.ContentStream{
		Stream: model.NewCompressedStream([]byte(content)),
	})

	out.Rect, out.Lines, out.Size = RectSlice(rect), len(lines), float64(size)
	if !fitted {
		if w, h := rect.Urx-rect.Llx, rect.Ury-rect.Lly; blockW > w || blockH > h {
			out.Note = fmt.Sprintf("text block is %.0fx%.0f pt, the target is %.0fx%.0f pt; it runs past the box",
				float64(blockW), float64(blockH), float64(w), float64(h))
		}
	}
	return out, nil
}

// canonicalFontName maps the friendly names a caller is likely to type onto
// the PDF short names used by the standard 14 fonts.
func canonicalFontName(name string) string {
	switch strings.ToLower(name) {
	case "", "helvetica", "helv", "arial", "sans", "sans-serif":
		return "Helv"
	case "helvetica-bold", "hebo", "arial-bold":
		return "Helvetica-Bold"
	case "helvetica-oblique", "hello", "helvetica-italic", "arial-italic":
		return "Helvetica-Oblique"
	case "helvetica-boldoblique", "arial-bolditalic":
		return "Helvetica-BoldOblique"
	case "times", "times-roman", "tiro", "serif":
		return "Times-Roman"
	case "times-bold", "tib":
		return "Times-Bold"
	case "times-italic", "times-roitalic", "tir":
		return "Times-Italic"
	case "times-bolditalic", "tibo":
		return "Times-BoldItalic"
	case "courier", "cour", "mono", "monospace":
		return "Courier"
	case "courier-bold", "cob":
		return "Courier-Bold"
	case "courier-oblique", "coob":
		return "Courier-Oblique"
	case "symbol", "symbo":
		return "Symbol"
	case "zapfdingbats", "zadb":
		return "ZaDb"
	}
	return name
}

var namedColors = map[string]string{
	"black":  "#000000",
	"white":  "#FFFFFF",
	"red":    "#FF0000",
	"green":  "#008000",
	"blue":   "#0000FF",
	"yellow": "#FFFF00",
	"grey":   "#808080",
	"gray":   "#808080",
	"orange": "#FFA500",
	"navy":   "#000080",
}

// parseColor accepts "#rrggbb" and a handful of colour names.
func parseColor(s string) (color.Color, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if named, ok := namedColors[s]; ok {
		s = named
	}
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return nil, false
	}
	var v [3]uint8
	for i := 0; i < 3; i++ {
		var n int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &n); err != nil {
			return nil, false
		}
		v[i] = uint8(n)
	}
	return color.RGBA{R: v[0], G: v[1], B: v[2], A: 255}, true
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

// addXObjectForm registers a form XObject in the page resources under a fresh
// name.
func addXObjectForm(res *model.ResourcesDict, form *model.XObjectForm) string {
	if res.XObject == nil {
		res.XObject = map[model.ObjName]model.XObject{}
	}
	for i := 0; ; i++ {
		name := model.ObjName(fmt.Sprintf("PTxt%d", i))
		if _, taken := res.XObject[name]; !taken {
			res.XObject[name] = form
			return string(name)
		}
	}
}
