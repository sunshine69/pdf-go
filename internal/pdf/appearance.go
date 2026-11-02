package pdf

import (
	"fmt"
	"image/color"
	"math"
	"strconv"
	"strings"

	cs "github.com/benoitkugler/pdf/contentstream"
	"github.com/benoitkugler/pdf/fonts"
	"github.com/benoitkugler/pdf/fonts/standardfonts"
	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// daSpec is the parsed form of a PDF appearance command (/DA string),
// e.g. "/Helv 9 Tf 0 g".
type daSpec struct {
	font  string
	size  model.Fl
	color color.Color
}

// ParseDA reads the font family, size and colour of a /DA string. It is
// tolerant: missing pieces fall back to Helvetica / 12pt / black.
func ParseDA(da string) daSpec {
	out := daSpec{font: "Helv", size: 12}
	var pending []model.Fl
	for _, tok := range strings.Fields(da) {
		switch {
		case strings.HasPrefix(tok, "/"):
			out.font = strings.TrimPrefix(tok, "/")
		case tok == "Tf" && len(pending) > 0:
			out.size = pending[len(pending)-1]
		case tok == "g" && len(pending) > 0:
			v := byte(clamp01(float64(pending[len(pending)-1])) * 255)
			out.color = color.NRGBA{R: v, G: v, B: v, A: 255}
		case tok == "rg" && len(pending) >= 3:
			out.color = color.NRGBA{
				R: byte(clamp01(float64(pending[len(pending)-3])) * 255),
				G: byte(clamp01(float64(pending[len(pending)-2])) * 255),
				B: byte(clamp01(float64(pending[len(pending)-1])) * 255),
				A: 255,
			}
		case tok == "k" && len(pending) >= 4:
			c, m, y, k := pending[len(pending)-4], pending[len(pending)-3], pending[len(pending)-2], pending[len(pending)-1]
			out.color = color.NRGBA{
				R: byte((1 - float64(c)) * (1 - float64(k)) * 255),
				G: byte((1 - float64(m)) * (1 - float64(k)) * 255),
				B: byte((1 - float64(y)) * (1 - float64(k)) * 255),
				A: 255,
			}
		}
		if f, err := strconv.ParseFloat(tok, 32); err == nil {
			pending = append(pending, model.Fl(f))
		} else {
			pending = pending[:0]
		}
	}
	if out.size <= 0 {
		out.size = 12
	}
	if out.color == nil {
		out.color = color.Black
	}
	if out.font == "" {
		out.font = "Helv"
	}
	return out
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

var (
	dingbatFont   *model.FontDict
	dingbatFontOK bool
)

// zapfFont is the ZapfDingbats font dictionary, used for check box ticks -
// the same convention Acrobat uses.
func zapfFont() *model.FontDict {
	if dingbatFont == nil && !dingbatFontOK {
		dingbatFont = &model.FontDict{Subtype: standardfonts.ZapfDingbats.WesternType1Font()}
		dingbatFontOK = true
	}
	return dingbatFont
}

func builtFont(d *model.FontDict) (fonts.BuiltFont, error) {
	return fonts.BuildFont(d)
}

// Cursor lays out widget-less fields in a predictable, non-overlapping flow.
type Cursor struct {
	box   model.Rectangle
	x, y  model.Fl
	row   model.Fl
	limit model.Fl
}

// NewCursor starts a layout flow at the top-left of the printable area,
// skipping the header band where templates put titles.
func NewCursor(page *model.PageObject) (*Cursor, error) {
	box, err := ResolveBox(page, BoxCrop)
	if err != nil {
		return nil, err
	}
	usable := model.Rectangle{
		Llx: box.Llx + 18, Lly: box.Lly + 18,
		Urx: box.Urx - 18, Ury: box.Ury - 18,
	}
	if header, err := headerFooterBox(page, BoxHeader); err == nil {
		usable.Ury = header.Lly
	}
	return &Cursor{
		box:   usable,
		x:     usable.Llx,
		y:     usable.Ury,
		limit: usable.Llx,
		row:   18,
	}, nil
}

// Take reserves a w x h slot in the flow, wrapping when the row is full and
// starting a new sheet when the page runs out.
func (c *Cursor) Take(w, h model.Fl) model.Rectangle {
	if c.x+w > c.box.Urx {
		c.x = c.limit
		c.y -= c.row
	}
	if c.y-h < c.box.Lly {
		c.x, c.y = c.limit, c.box.Ury
	}
	rect := model.Rectangle{Llx: c.x, Lly: c.y - h, Urx: c.x + w, Ury: c.y}
	c.x += w + 6
	if h > c.row {
		c.row = h
	}
	return rect
}

// EnsureFieldWidget gives a field a widget covering rect, registered on the
// page. The library merges such a leaf field into the annotation when
// writing, so the resulting PDF has a single, valid field/widget object.
func EnsureFieldWidget(page *model.PageObject, fi *model.FormFieldDict, rect model.Rectangle, name string) *model.FormFieldWidget {
	annot := &model.AnnotationDict{
		BaseAnnotation: model.BaseAnnotation{
			Rect: rect,
			F:    model.APrint,
			NM:   "pdf-go:" + name,
		},
		Subtype: model.AnnotationWidget{},
	}
	page.Annots = append(page.Annots, annot)
	w := model.FormFieldWidget{AnnotationDict: annot}
	if fi != nil {
		fi.Widgets = append(fi.Widgets, w)
	}
	return &w
}

// EnsureFieldAppearances bakes the appearance of a filled field: it creates a
// widget when the field has none, then paints the value (or the check mark)
// into the widget appearance streams.
//
// The font named by the /DA string is looked up in the page resources, so the
// appearance stream stays printable as-is. When it is absent, it is added to
// the resources, and a metric-compatible standard font is used.
func EnsureFieldAppearances(pages []*model.PageObject, annotPage map[*model.AnnotationDict]int, fi model.FormFieldInherited, sf schema.Field, value string) error {
	if fi.Field == nil {
		return nil
	}
	da := ParseDA(sf.DefaultAppearance)

	// Fields with no widget (form templates from layout tools) get one, laid
	// out in a flow so several of them do not collide.
	if len(fi.Field.Widgets) == 0 {
		page := pickPage(pages, annotPage, fi.Field)
		if page == nil {
			return nil
		}
		fd, bf := pageFont(page, da.font)
		w, h := widgetSize(bf, da.size, value, sf)
		cur, err := NewCursor(page)
		if err != nil {
			return err
		}
		EnsureFieldWidget(page, fi.Field, cur.Take(w, h), sf.Name)
		_ = fd
	}

	for _, widget := range fi.Field.Widgets {
		if widget.AnnotationDict == nil {
			continue
		}
		pageIdx := annotPage[widget.AnnotationDict]
		if pageIdx == 0 {
			// No page reference: target the page of any other widget,
			// otherwise the first page.
			for _, w := range fi.Field.Widgets {
				if w.AnnotationDict != nil && annotPage[w.AnnotationDict] > 0 {
					pageIdx = annotPage[w.AnnotationDict]
					break
				}
			}
		}
		var page *model.PageObject
		if pageIdx > 0 && pageIdx <= len(pages) {
			page = pages[pageIdx-1]
		} else if len(pages) > 0 {
			page = pages[0]
		}
		if page == nil {
			return nil
		}

		fd, bf := pageFont(page, da.font)
		rect := widget.AnnotationDict.Rect
		if rect.Urx <= rect.Llx || rect.Ury <= rect.Lly {
			continue
		}

		switch sf.Type {
		case schema.TypeCheckbox, schema.TypeRadio:
			paintButton(page, widget, sf, value, rect)
		case schema.TypePushButton, schema.TypeSignature:
			// nothing to paint
		default:
			app, err := textAppearance(bf, da, rect, value, sf)
			if err != nil {
				return err
			}
			setAppearance(widget, "", app)
			if page.Resources == nil {
				res := model.NewResourcesDict()
				page.Resources = &res
			}
			addFont(page.Resources, "F0", fd)
		}
	}
	return nil
}

// pageFont resolves the /DA font inside the page resources, falling back to a
// standard font with the same metrics (Helvetica family).
func pageFont(page *model.PageObject, daFont string) (*model.FontDict, fonts.BuiltFont) {
	if page.Resources != nil {
		if fd, ok := page.Resources.Font[model.ObjName(daFont)]; ok && fd != nil {
			if bf, err := builtFont(fd); err == nil {
				return fd, bf
			}
		}
	}
	fd := stdFont(daFont)
	bf, err := builtFont(fd)
	if err != nil {
		fd = stdFont("Helv")
		bf, _ = builtFont(fd)
	}
	return fd, bf
}

func addFont(res *model.ResourcesDict, name string, fd *model.FontDict) {
	if res.Font == nil {
		res.Font = map[model.ObjName]*model.FontDict{}
	}
	key := model.ObjName(name)
	if _, taken := res.Font[key]; taken {
		return
	}
	res.Font[key] = fd
}

func setAppearance(widget model.FormFieldWidget, key string, app *model.XObjectForm) {
	if widget.AP == nil {
		widget.AP = &model.AppearanceDict{}
	}
	if widget.AP.N == nil {
		widget.AP.N = model.AppearanceEntry{}
	}
	widget.AP.N[model.Name(key)] = app
}

// paintButton selects the on/off state of a check box or radio button.
//
// When the document already defines the appearance keys (the usual case), its
// artwork is kept and only /AS is switched - that preserves the original
// check mark design. Otherwise both states are drawn from scratch.
func paintButton(page *model.PageObject, widget model.FormFieldWidget, sf schema.Field, value string, rect model.Rectangle) {
	keys := map[string]bool{}
	if widget.AP != nil {
		for k, app := range widget.AP.N {
			if app != nil {
				keys[string(k)] = true
			}
		}
	}
	on := value
	if on == "" || on == "Off" {
		on = firstOnState(sf.Options)
	}

	offState := keys["Off"] || len(keys) > 1
	if offState && keys[on] {
		setAppearance(widget, "", widget.AP.N[model.Name(on)])
		widget.AS = model.ObjName(on)
		return
	}

	entry := model.AppearanceEntry{}
	if off, err := checkboxAppearance(rect, false); err == nil {
		entry["Off"] = off
	}
	onApp, err := checkboxAppearance(rect, true)
	if err == nil {
		entry[model.ObjName(on)] = onApp
		entry[""] = onApp
	}
	if len(entry) == 0 {
		return
	}
	widget.AP = &model.AppearanceDict{N: entry}
	widget.AS = model.ObjName(on)

	// ZapfDingbats must be available to the page for the tick to print.
	d := zapfFont()
	if built, err := builtFont(d); err == nil {
		_ = built
		if page.Resources == nil {
			res := model.NewResourcesDict()
			page.Resources = &res
		}
		addFont(page.Resources, "ZaDb", d)
	}
}

// checkboxAppearance draws the box and, when checked, the tick, in a
// self-contained XObject carrying its own font resource.
func checkboxAppearance(rect model.Rectangle, checked bool) (*model.XObjectForm, error) {
	bf, err := builtFont(zapfFont())
	if err != nil {
		return nil, err
	}
	side := rect.Urx - rect.Llx
	if h := rect.Ury - rect.Lly; h < side {
		side = h
	}
	glyphSize := side * 0.9
	if glyphSize <= 0 {
		glyphSize = 8
	}

	gs := cs.NewGraphicStream(rect)
	gs.BeginText()
	gs.SetFontAndSize(bf, glyphSize)
	gs.SetTextMatrix(1, 0, 0, 1, rect.Llx+(rect.Urx-rect.Llx-glyphSize)/2, rect.Lly+(rect.Ury-rect.Lly-glyphSize)/2)
	if err := gs.ShowText(checkboxGlyph(checked)); err != nil {
		return nil, err
	}
	gs.EndText()
	return gs.ToXFormObject(true), nil
}

// checkboxGlyph returns the ZapfDingbats tick, or the hollow box.
func checkboxGlyph(checked bool) string {
	if checked {
		return "\x58" // filled square with a check (ZapfDingbats 0x58)
	}
	return "\x6F" // hollow square (ZapfDingbats 0x6F)
}

func firstOnState(options []string) string {
	for _, o := range options {
		if o != "" && o != "Off" && o != "No" && o != "false" {
			return o
		}
	}
	return "Yes"
}

// textAppearance paints value inside rect with the /DA font, size and
// colour. Long values shrink to fit, and multiline values wrap, so a filled
// value is never silently clipped.
func textAppearance(bf fonts.BuiltFont, da daSpec, rect model.Rectangle, value string, sf schema.Field) (*model.XObjectForm, error) {
	text := strings.ReplaceAll(value, "\r\n", "\n")
	if sf.HasFlag("password") {
		text = strings.Repeat("*", len([]rune(text)))
	}

	border := model.Fl(1)
	w, h := rect.Urx-rect.Llx, rect.Ury-rect.Lly
	inner := model.Rectangle{
		Llx: rect.Llx + border, Lly: rect.Lly + border,
		Urx: rect.Urx - border, Ury: rect.Ury - border,
	}

	gs := cs.NewGraphicStream(rect)
	gs.SaveState()
	gs.SetColorFill(da.color)

	if text == "" {
		gs.RestoreState()
		return gs.ToXFormObject(true), nil
	}

	available := inner.Urx - inner.Llx - 2
	size := da.size
	if size <= 0 {
		size = 12
	}
	lines := wrapText(bf, text, size, available)
	leading := size * 1.2
	for size > 4 && float64(len(lines))*float64(leading) > float64(inner.Ury-inner.Lly) {
		size *= 0.92
		leading = size * 1.2
		lines = wrapText(bf, text, size, available)
	}

	gs.BeginText()
	gs.SetFontAndSize(bf, size)
	gs.SetLeading(leading)

	y := inner.Ury - size*0.85
	if y < inner.Lly+size*0.2 {
		y = inner.Lly + size*0.2
	}
	gs.SetTextMatrix(1, 0, 0, 1, inner.Llx+1, y)

	for i, line := range lines {
		if i > 0 {
			gs.MoveText(0, -leading)
		}
		drawAligned(&gs, bf, size, line, sf.TextAlign, available)
	}
	gs.EndText()

	if sf.HasFlag("multiline") || w > 0 {
		// A hairline frame makes a generated widget readable.
		gs.EndText()
		gs.Ops(
			cs.OpRectangle{X: rect.Llx, Y: rect.Lly, W: w, H: h},
			cs.OpStroke{},
		)
	}

	gs.RestoreState()
	return gs.ToXFormObject(true), nil
}

func drawAligned(gs *cs.GraphicStream, bf fonts.BuiltFont, size model.Fl, line string, q int, available model.Fl) {
	switch q {
	case 1: // centered
		dx := (available - textWidth(bf, line, size)) / 2
		if dx > 0 {
			gs.SaveState()
			gs.Transform(model.Matrix{1, 0, 0, 1, dx, 0})
			_ = gs.ShowText(line)
			gs.RestoreState()
			return
		}
	case 2: // right
		dx := available - textWidth(bf, line, size)
		if dx > 0 {
			gs.SaveState()
			gs.Transform(model.Matrix{1, 0, 0, 1, dx, 0})
			_ = gs.ShowText(line)
			gs.RestoreState()
			return
		}
	}
	_ = gs.ShowText(line)
}

func textWidth(bf fonts.BuiltFont, s string, size model.Fl) model.Fl {
	var w model.Fl
	for _, r := range s {
		w += bf.GetWidth(r, size)
	}
	return w
}

// wrapText breaks on existing line breaks first, then on width.
func wrapText(bf fonts.BuiltFont, text string, size, width model.Fl) []string {
	var out []string
	for _, hard := range strings.Split(text, "\n") {
		out = append(out, breakLine(bf, hard, size, width)...)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

func breakLine(bf fonts.BuiltFont, line string, size, width model.Fl) []string {
	if width <= 0 {
		return []string{line}
	}
	words := strings.Fields(line)
	if len(words) == 0 {
		return []string{""}
	}
	var (
		out  []string
		cur  string
		curW model.Fl
	)
	space := bf.GetWidth(' ', size)
	for _, word := range words {
		ww := textWidth(bf, word, size)
		if cur == "" {
			cur, curW = word, ww
			continue
		}
		if curW+space+ww <= width {
			cur += " " + word
			curW += space + ww
			continue
		}
		out = append(out, cur)
		cur, curW = word, ww
	}
	out = append(out, cur)
	return out
}

var _ = fmt.Sprintf
var _ = math.Pi

// pickPage finds the page a field should be drawn on: the page of one of its
// widgets, otherwise the first page.
func pickPage(pages []*model.PageObject, annotPage map[*model.AnnotationDict]int, f *model.FormFieldDict) *model.PageObject {
	if f != nil {
		for _, w := range f.Widgets {
			if w.AnnotationDict == nil {
				continue
			}
			if idx := annotPage[w.AnnotationDict]; idx > 0 && idx <= len(pages) {
				return pages[idx-1]
			}
		}
	}
	if len(pages) > 0 {
		return pages[0]
	}
	return nil
}

// widgetSize sizes a generated widget: wide enough for the value, with room
// for its border.
func widgetSize(bf fonts.BuiltFont, size model.Fl, value string, sf schema.Field) (model.Fl, model.Fl) {
	if size <= 0 {
		size = 12
	}
	if sf.Type == schema.TypeCheckbox || sf.Type == schema.TypeRadio {
		return size + 8, size + 8
	}
	tw := model.Fl(1)
	for _, r := range value {
		tw += bf.GetWidth(r, size)
	}
	if sf.MaxLen > 0 && len([]rune(value)) == sf.MaxLen {
		tw *= 1.12 // comb fields are roomier
	}
	w := tw + 8
	if w < 40 {
		w = 40
	}
	h := size*1.3 + 4
	if h < 15 {
		h = 15
	}
	return w, h
}
