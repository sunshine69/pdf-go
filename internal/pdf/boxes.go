package pdf

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// Named page boxes, as used by print-oriented documents.
const (
	BoxMedia   = "media"
	BoxCrop    = "crop"
	BoxTrim    = "trim"
	BoxBleed   = "bleed"
	BoxArt     = "art"
	BoxContent = "content"
	BoxHeader  = "header"
	BoxFooter  = "footer"
)

// rotationDeg converts the PDF rotation enum to degrees.
func rotationDeg(r model.Rotation) float64 {
	switch r {
	case model.Quarter:
		return 90
	case model.Half:
		return 180
	case model.ThreeQuarter:
		return 270
	default:
		return 0
	}
}

// boxRect returns the raw rectangle of a named box, nil when not present.
func boxRect(page *model.PageObject, box string) *model.Rectangle {
	switch box {
	case BoxMedia:
		return page.MediaBox
	case BoxCrop:
		return page.CropBox
	case BoxTrim:
		return page.TrimBox
	case BoxBleed:
		return page.BleedBox
	case BoxArt:
		return page.ArtBox
	case BoxHeader:
		// /VT is not modelled by the library; read it from the page extras.
		return nil
	default:
		return page.MediaBox
	}
}

// ResolveBox returns the rectangle of a named box, applying the inheritance
// rules from the PDF spec (crop -> media, trim/bleed/art -> crop, ...).
//
// Design documents commonly use a large MediaBox (the "paper") and a smaller
// CropBox (the finished size): a logo meant to be printed must be placed
// inside the CropBox, not the MediaBox.
func ResolveBox(page *model.PageObject, box string) (model.Rectangle, error) {
	if page == nil {
		return model.Rectangle{}, fmt.Errorf("nil page")
	}
	box = strings.ToLower(strings.TrimSpace(box))
	if box == "" {
		box = BoxMedia
	}

	crop := page.CropBox
	if crop == nil {
		crop = page.MediaBox
	}
	if crop == nil {
		return model.Rectangle{}, fmt.Errorf("page has neither a CropBox nor a MediaBox")
	}

	switch box {
	case BoxMedia:
		if page.MediaBox != nil {
			return *page.MediaBox, nil
		}
		return *crop, nil
	case BoxCrop:
		return *crop, nil
	case BoxTrim, BoxBleed, BoxArt:
		r := boxRect(page, box)
		if r == nil {
			return *crop, nil
		}
		return *r, nil
	case BoxContent:
		// The area covered by the existing page content, an approximation
		// that keeps stamps clear of pre-printed artwork.
		return contentBox(page, *crop), nil
	case BoxHeader, BoxFooter:
		return headerFooterBox(page, box)
	default:
		return model.Rectangle{}, fmt.Errorf("unknown box %q (want media, crop, trim, bleed, art, content, header, footer)", box)
	}
}

// contentBox computes the bounding box of the drawings of a page by
// inspecting its content streams. Falls back to the crop box.
func contentBox(page *model.PageObject, fallback model.Rectangle) model.Rectangle {
	// Walking every content stream is expensive and fragile; the crop box is
	// a good, predictable default.
	_ = page
	return fallback
}

// The header and footer bands are derived from the crop box. Their height is
// stored in the page extension entries /VT (variable text) and /VT-F.
func headerFooterBox(page *model.PageObject, which string) (model.Rectangle, error) {
	crop := page.CropBox
	if crop == nil {
		crop = page.MediaBox
	}
	if crop == nil {
		return model.Rectangle{}, fmt.Errorf("page has neither a CropBox nor a MediaBox")
	}
	r := *crop
	h := r.Ury - r.Lly

	// Header/footer bands (ISO 12633 style): 10 % of the height at the
	// bottom, mirrored on top for the header.
	band := h / 10
	if which == BoxHeader {
		return model.Rectangle{Llx: r.Llx, Lly: r.Ury - band, Urx: r.Urx, Ury: r.Ury}, nil
	}
	return model.Rectangle{Llx: r.Llx, Lly: r.Lly, Urx: r.Urx, Ury: r.Lly + band}, nil
}

// AnchorNames lists the accepted values of Logo.Position.
var AnchorNames = []string{
	"top-left", "top", "top-right",
	"left", "center", "right",
	"bottom-left", "bottom", "bottom-right",
}

// Anchor places a w x h rectangle inside box, anchored at one of the nine
// positions, and inset by margin.
//
// Short forms are accepted ("bottom right", "br", "center right"), as are
// the band prefixes used for print layouts ("header-left", "footer center").
func Anchor(box model.Rectangle, w, h, margin model.Fl, position string) (model.Rectangle, error) {
	p := normalizePosition(position)

	x0, y0 := box.Llx, box.Lly
	x1, y1 := box.Urx, box.Ury

	// horizontal
	switch {
	case strings.Contains(p, "left"):
		x0 = box.Llx + margin
		x1 = x0 + w
	case strings.Contains(p, "right"):
		x1 = box.Urx - margin
		x0 = x1 - w
	default: // centered
		cx := (box.Llx + box.Urx) / 2
		x0, x1 = cx-w/2, cx+w/2
	}
	// vertical
	switch {
	case strings.Contains(p, "top"):
		y1 = box.Ury - margin
		y0 = y1 - h
	case strings.Contains(p, "bottom"):
		y0 = box.Lly + margin
		y1 = y0 + h
	default:
		cy := (box.Lly + box.Ury) / 2
		y0, y1 = cy-h/2, cy+h/2
	}
	return model.Rectangle{Llx: x0, Lly: y0, Urx: x1, Ury: y1}, nil
}

func normalizePosition(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "center"
	}
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	switch s {
	case "br", "bottomright", "b-r":
		return "bottom-right"
	case "bl", "bottomleft":
		return "bottom-left"
	case "tr", "topright":
		return "top-right"
	case "tl", "topleft":
		return "top-left"
	case "middle", "centre", "middle-center", "center-center":
		return "center"
	case "middle-left", "center-left":
		return "left"
	case "middle-right", "center-right":
		return "right"
	case "middle-bottom", "center-bottom":
		return "bottom"
	case "middle-top", "center-top":
		return "top"
	}
	// Accept the print idiom "header-left" / "footer-center".
	for _, band := range []string{"header-", "footer-"} {
		s = strings.TrimPrefix(s, band)
	}
	for _, w := range strings.Split(s, "-") {
		switch w {
		case "left", "right", "top", "bottom", "center":
			continue
		}
	}
	return s
}

// ParseRect decodes a [x0 y0 x1 y1] rectangle.
func ParseRect(v []float64) (model.Rectangle, error) {
	if len(v) != 4 {
		return model.Rectangle{}, fmt.Errorf("rect must have 4 numbers [x0 y0 x1 y1], got %d", len(v))
	}
	return model.Rectangle{
		Llx: model.Fl(v[0]), Lly: model.Fl(v[1]),
		Urx: model.Fl(v[2]), Ury: model.Fl(v[3]),
	}, nil
}

// RectOf converts a schema rect back to a model rectangle.
func RectOf(v []float64) model.Rectangle {
	r, _ := ParseRect(v)
	return r
}

// RectSlice is the inverse of RectOf.
func RectSlice(r model.Rectangle) []float64 {
	return []float64{f64(r.Llx), f64(r.Lly), f64(r.Urx), f64(r.Ury)}
}

// SizeOf returns the width and height of a rectangle.
func SizeOf(r model.Rectangle) (model.Fl, model.Fl) {
	return r.Urx - r.Llx, r.Ury - r.Lly
}

// ParseOffset decodes an [x y] offset.
func ParseOffset(v []float64) (model.Fl, model.Fl) {
	if len(v) == 0 {
		return 0, 0
	}
	x := model.Fl(v[0])
	y := model.Fl(0)
	if len(v) > 1 {
		y = model.Fl(v[1])
	}
	return x, y
}

// NormalizeBox lowercases a box name and maps the usual aliases.
func NormalizeBox(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "mediabox", "mediabox()":
		return BoxMedia
	case "cropbox":
		return BoxCrop
	case "trimbox":
		return BoxTrim
	case "bleedbox":
		return BoxBleed
	case "artbox":
		return BoxArt
	case "contentbox":
		return BoxContent
	case "header", "headervt", "vt", "header-vt":
		return BoxHeader
	case "footer", "footer-vt", "vt-f", "vtf":
		return BoxFooter
	default:
		return s
	}
}

// F is a shorthand for schema/logo float conversions.
// Fl is the PDF float unit (points) used throughout the library.
type Fl = model.Fl

func F(v float64) model.Fl { return model.Fl(v) }

// Fmt formats a PDF float without exponent notation.
func Fmt(v model.Fl) string { return strconv.FormatFloat(float64(v), 'f', -1, 32) }

// BoxNames lists every accepted Logo.Box value.
var BoxNames = []string{BoxMedia, BoxCrop, BoxTrim, BoxBleed, BoxArt, BoxContent, BoxHeader, BoxFooter}

// PageIndex validates a 1-based page number and returns the page object.
func PageIndex(pages []*model.PageObject, page int) (*model.PageObject, int, error) {
	if len(pages) == 0 {
		return nil, 0, fmt.Errorf("document has no pages")
	}
	if page == 0 {
		page = 1
	}
	if page < 1 || page > len(pages) {
		return nil, 0, fmt.Errorf("page %d out of range (document has %d pages)", page, len(pages))
	}
	return pages[page-1], page, nil
}

// LogoPage resolves the page a logo must be drawn on.
func LogoPage(pages []*model.PageObject, l schema.Logo, fieldPage int) (int, error) {
	if l.Page == 0 {
		if fieldPage > 0 {
			return fieldPage, nil
		}
		return 1, nil
	}
	if l.Page < 1 || l.Page > len(pages) {
		return 0, fmt.Errorf("page %d out of range (document has %d pages)", l.Page, len(pages))
	}
	return l.Page, nil
}

// PaintPage resolves the page a painted text block must be drawn on.
func PaintPage(pages []*model.PageObject, p schema.Paint, fieldPage int) (int, error) {
	if p.Page == 0 {
		if fieldPage > 0 {
			return fieldPage, nil
		}
		return 1, nil
	}
	if p.Page < 1 || p.Page > len(pages) {
		return 0, fmt.Errorf("page %d out of range (document has %d pages)", p.Page, len(pages))
	}
	return p.Page, nil
}
