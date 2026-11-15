package signpdf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	pdflib "github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
)

// The appearance is the printed part of a signature: what a reader sees, and
// what a printout carries as evidence. Layout is controlled here, not by
// pdfsign's Standard(): the typed signature text is the party's words, it has
// to be legible, and the machine-readable lines below it are fixed.

const (
	// AppearanceWidth and AppearanceHeight are the widget size every signature
	// uses. 220x80 pt is the de facto size of a signature field, and it fits a
	// signature line plus two small lines.
	AppearanceWidth  = 220
	AppearanceHeight = 80

	// margin is the minimum distance from the widget edge to the crop box
	// edge when the fill spec does not name a signature field.
	margin = 36.0

	// The appearance is drawn in a coordinate space of its own, 220x80. The
	// numbers below are in that space; TestSignatureImageIsVisibleOnThePage
	// measures what reaches the page rather than trusting the geometry to hold.
	//
	// signatureSize, nameSize, dateSize: the three lines of the appearance.
	signatureSize = 26.0
	nameSize      = 9.0
	dateSize      = 8.0

	// The drawn-signature row. An uploaded image sits on its own row under the
	// typed name, with the party name and the signing date beside it: the image
	// is the signature, so it gets a row of its own rather than sharing one with
	// the words. The row starts below the typed line's descenders and the small
	// lines start clear of the image's right edge, so nothing overlaps.
	//
	// imageRowHeight is the height the image is drawn at, not the aspect ratio
	// it keeps: a tall upload is letterboxed into the row, not stretched.
	imageRowX      = 6.0
	imageRowY      = 4.0
	imageRowWidth  = 56.0
	imageRowHeight = 40.0

	// The two columns the appearance draws in: textX for the lines that run the
	// full width, and nameDateXImg for the name and date once an image occupies
	// the left of their row.
	textX        = 6.0
	nameDateXImg = imageRowX + imageRowWidth + 8
)

// WidgetPlacement is where a stack of signature boxes begins and how far apart
// successive boxes sit. A stack places party i at
//
//	Y = WidgetY + WidgetStride*i
//
// The stride has to clear the height of one box: the appearance is
// AppearanceHeight tall, and a stride below that lets one party's signature
// paint over the previous party's. It went unnoticed while the lower half of a
// box was blank, and is unmistakable once that half carries a drawn signature
// image.
const (
	WidgetX      = 60
	WidgetY      = 60
	WidgetStride = AppearanceHeight + 10
)

// PartyWidget is the widget of the index-th signature in a stack. Callers that
// sign more than one party all place them the same way, so a document looks the
// same whatever signed it.
//
// base is what the envelope asked for: the page, and optionally the signature
// field the stack is anchored to. The zero Widget is a legitimate base and
// means "page 1, default corner" — every envelope created before signatures had
// a page to ask for, and every caller that has no opinion.
//
// The index offsets within one page only. A base that names a page moves the
// whole stack to that page; it does not spread it over several.
func PartyWidget(base Widget, index int) Widget {
	w := base
	if w.Page < 1 {
		w.Page = 1
	}
	if w.W <= 0 {
		w.W = AppearanceWidth
	}
	if w.H <= 0 {
		w.H = AppearanceHeight
	}
	// A field anchor places one signature, not a column of them: the stack
	// offset would walk the second party's box off the field it was anchored to.
	// The first party takes the field, the rest fall back to the stack.
	if w.Field != "" && index == 0 {
		return w
	}
	w.Field = ""
	if w.X == 0 && w.Y == 0 {
		// No coordinates asked for: the default column, one box per party.
		w.X = WidgetX
		w.Y = WidgetY + WidgetStride*float64(index)
		return w
	}
	// The caller named a spot. Successive parties still need a row of their own,
	// so the stack grows the same way the default column does — upward, because
	// the origin is the bottom-left of the page. A base of {X:60, Y:60} therefore
	// reproduces the default column exactly, and a base that only names a page
	// differs from the old fixed placement by that page and nothing else.
	w.Y = w.Y + WidgetStride*float64(index)
	return w
}

// PartyIndex is the slot a party occupies in the stack. It is the party's
// position in the envelope's signing order, not its position in the batch that
// is running now: an envelope where party 1 has already signed and party 2 has
// not must leave party 1's signature where it is and place party 2 below it.
// Numbering the stack from the batch instead re-paints the whole column on
// every late signature, and in a partial signing the late party would land on
// top of the one who signed first.
func PartyIndex(orderIdx int) int {
	if orderIdx < 1 {
		return 0
	}
	return orderIdx - 1
}

// normalizeWidget fills in the defaults: page 1, the standard size.
func normalizeWidget(w Widget) Widget {
	if w.W <= 0 {
		w.W = AppearanceWidth
	}
	if w.H <= 0 {
		w.H = AppearanceHeight
	}
	if w.Page < 1 {
		w.Page = 1
	}
	return w
}

// cropBox returns the crop box of page n, falling back to the media box when
// the page has no crop box (legal, and common in generated PDFs). The crop box
// is what gets printed, so it is the box a widget must live inside.
func cropBox(doc *pdfsign.Document, page int) ([4]float64, error) {
	rdr := doc.Reader()
	if rdr == nil {
		return [4]float64{}, errors.New("signpdf: document has no reader")
	}
	if page > rdr.NumPage() {
		return [4]float64{}, fmt.Errorf("signpdf: page %d does not exist (document has %d)", page, rdr.NumPage())
	}
	p := rdr.Page(page)
	// The vendored pdf.Page does not expose CropBox/MediaBox (the methods are
	// commented out upstream), so walk the page dictionary and its parents by
	// hand: a box is inherited from the parent Pages node when the page itself
	// does not declare it.
	v := inheritBox(p.V, "CropBox")
	if v.Kind() != pdflib.Array || v.Len() != 4 {
		v = inheritBox(p.V, "MediaBox")
	}
	if v.Kind() != pdflib.Array || v.Len() != 4 {
		return [4]float64{}, fmt.Errorf("signpdf: page %d has no usable box", page)
	}
	var box [4]float64
	for i := 0; i < 4; i++ {
		box[i] = v.Index(i).Float64()
	}
	if box[2] <= box[0] || box[3] <= box[1] {
		return box, fmt.Errorf("signpdf: page %d box is degenerate: %v", page, box)
	}
	return box, nil
}

// inheritBox walks the page dictionary and its parents looking for a box. A
// page is allowed to inherit its boxes from the page tree, so a page that
// declares no MediaBox is not broken; it inherits one.
func inheritBox(v pdflib.Value, key string) pdflib.Value {
	for !v.IsNull() {
		if b := v.Key(key); b.Kind() == pdflib.Array && b.Len() == 4 {
			return b
		}
		parent := v.Key("Parent")
		if parent.GetPtr() == v.GetPtr() {
			return pdflib.Value{}
		}
		v = parent
	}
	return pdflib.Value{}
}

// placement computes the widget position so the whole appearance sits inside
// the crop box. A caller-supplied X,Y is respected when it fits; the default
// is bottom-right, inset by margin. Clamping is deliberate: a signature drawn
// partly off the printed area is a signature nobody sees.
func placement(doc *pdfsign.Document, w Widget) (x, y float64, err error) {
	w = normalizeWidget(w) // defaults applied here, so callers cannot pass a zero-size widget
	box, err := cropBox(doc, w.Page)
	if err != nil {
		return 0, 0, err
	}
	minX, maxX := box[0]+margin, box[2]-margin-w.W
	minY, maxY := box[1]+margin, box[3]-margin-w.H
	if maxX < minX || maxY < minY {
		return 0, 0, fmt.Errorf("signpdf: page %d crop box %v is too small for a %gx%g signature", w.Page, box, w.W, w.H)
	}
	x, y = w.X, w.Y
	if x <= 0 && y <= 0 {
		return maxX, minY, nil
	}
	if x < minX {
		x = minX
	}
	if x > maxX {
		x = maxX
	}
	if y < minY {
		y = minY
	}
	if y > maxY {
		y = maxY
	}
	return x, y, nil
}

// appearance builds the visual. `text` is the typed signature (the consent
// text), `name` the party name, `now` the signing time shown on line 3. The
// handwriting font is embedded from fontData, so the file prints the same on a
// machine that does not have the font installed. When `image` is present it
// goes on the left and the text starts to its right.
func (s *Service) appearance(doc *pdfsign.Document, text, name string, now time.Time, image []byte) *pdfsign.Appearance {
	app := pdfsign.NewAppearance(AppearanceWidth, AppearanceHeight)
	app.Border(1, 0x80, 0x80, 0x80)

	// The typed signature keeps the top line and the full width whether or not
	// an image was uploaded, so the no-image appearance is laid out exactly as
	// it was before the image row existed.
	left := textX
	if len(s.fontData) > 0 && text != "" {
		font := doc.AddFont(s.fontName, s.fontData)
		app.Text(text).Font(font, signatureSize).Position(textX, AppearanceHeight-30)
	}

	// The image takes its own row under the typed name, with the two small
	// lines beside it. The name and date keep their baselines either way and
	// only move right, so the pair reads as one block against the image rather
	// than underneath it.
	if len(image) > 0 {
		if img := doc.AddImage(imageName(image), image); img != nil {
			app.Image(img).
				Rect(imageRowX, imageRowY, imageRowWidth, imageRowHeight).
				ScaleFit()
			left = nameDateXImg
		}
	}

	if name != "" {
		app.Text(name).
			Font(pdfsign.StandardFont(pdfsign.Helvetica), nameSize).
			SetColor(0x40, 0x40, 0x40).
			Position(left, AppearanceHeight-46)
	}
	date := now.UTC().Format("2006-01-02 15:04:05Z")
	app.Text("Signed: "+date).
		Font(pdfsign.StandardFont(pdfsign.Helvetica), dateSize).
		SetColor(0x60, 0x60, 0x60).
		Position(left, AppearanceHeight-60)
	return app
}

// imageName keys the image by its content hash, so the same handwriting
// uploaded twice is embedded once.
func imageName(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("signimg-%x", sum[:6])
}

func isPNG(d []byte) bool {
	return len(d) > 8 && d[0] == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G'
}

func isJPEG(d []byte) bool {
	return len(d) > 2 && d[0] == 0xFF && d[1] == 0xD8
}
