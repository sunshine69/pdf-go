package pdf

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/gif"  // registered for image.DecodeConfig
	_ "image/jpeg" // registered for image.DecodeConfig
	"math"
	"os"
	"strings"

	cs "github.com/benoitkugler/pdf/contentstream"
	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// LoadImage decodes the artwork of a logo: a file path, a data: URI, or raw
// base64 in imageData. It returns the PDF image XObject and its natural size
// in pixels.
//
// PNG is the recommended format: embedded losslessly, with an alpha channel
// that prints as transparency. JPEG is embedded as-is.
func LoadImage(l schema.Logo) (*model.XObjectImage, float64, float64, error) {
	data, name, err := logoBytes(l)
	if err != nil {
		return nil, 0, 0, err
	}
	img, _, err := cs.ParseImage(bytes.NewReader(data), mimeOf(name, data))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("decode image (%s): %w", describe(l), err)
	}
	if img == nil || img.Image.Width == 0 || img.Image.Height == 0 {
		return nil, 0, 0, fmt.Errorf("image (%s): unsupported format, use PNG, JPEG, GIF or TIFF", describe(l))
	}
	return img, float64(img.Image.Width), float64(img.Image.Height), nil
}

func logoBytes(l schema.Logo) ([]byte, string, error) {
	if strings.TrimSpace(l.ImageData) != "" {
		s := strings.TrimSpace(l.ImageData)
		if i := strings.Index(s, ","); strings.HasPrefix(s, "data:") && i >= 0 {
			s = s[i+1:]
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, "", fmt.Errorf("decode base64 image: %w", err)
		}
		return b, "image.png", nil
	}
	if strings.TrimSpace(l.Image) == "" {
		return nil, "", fmt.Errorf("logo %s: set \"image\" (file path) or \"imageData\" (base64)", describe(l))
	}
	b, err := os.ReadFile(l.Image)
	if err != nil {
		return nil, "", fmt.Errorf("read image: %w", err)
	}
	return b, l.Image, nil
}

func mimeOf(name string, data []byte) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".jpg"), strings.HasSuffix(n, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(n, ".gif"):
		return "image/gif"
	case strings.HasSuffix(n, ".tif"), strings.HasSuffix(n, ".tiff"):
		return "image/tiff"
	}
	if len(data) > 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		return "image/png"
	}
	if len(data) > 2 && data[0] == 0xff && data[1] == 0xd8 {
		return "image/jpeg"
	}
	if len(data) > 3 && data[0] == 'G' && data[1] == 'I' && data[2] == 'F' {
		return "image/gif"
	}
	return "image/png"
}

func describe(l schema.Logo) string {
	switch {
	case l.ID != "":
		return l.ID
	case l.Image != "":
		return l.Image
	case l.Field != "":
		return "field:" + l.Field
	default:
		return "logo"
	}
}

// LogoPlacement reports where a logo was stamped.
type LogoPlacement struct {
	ID       string    `json:"id,omitempty"`
	Page     int       `json:"page"`
	Box      string    `json:"box"`
	Position string    `json:"position,omitempty"`
	Field    string    `json:"field,omitempty"`
	Rect     []float64 `json:"rect"`
	Size     []float64 `json:"size"`
	Rotate   float64   `json:"rotate,omitempty"`
	Opacity  float64   `json:"opacity,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// StampLogo draws one logo on a page and returns where it landed.
//
// The logo is plain page content, not an interactive annotation: that is what
// print production requires - it prints identically, cannot be dragged out of
// place in a viewer, and survives rasterising. When the target field has no
// widget (typical for signature fields), a read-only widget is created so the
// area is reserved and visible.
func StampLogo(pageIdx int, page *model.PageObject, l schema.Logo, target *FieldTarget) (LogoPlacement, error) {
	var out LogoPlacement
	out.ID, out.Page, out.Field, out.Note, out.Rotate, out.Opacity = l.ID, pageIdx, l.Field, l.Note, l.Rotate, l.Opacity
	out.Box = NormalizeBox(l.Box)
	if out.Box == "" {
		out.Box = BoxMedia
	}
	out.Position = normalizePosition(l.Position)

	img, natW, natH, err := LoadImage(l)
	if err != nil {
		return out, err
	}
	if page.Resources == nil {
		res := model.NewResourcesDict()
		page.Resources = &res
	}

	box, err := ResolveBox(page, out.Box)
	if err != nil {
		return out, err
	}
	rot := rotationDeg(page.Rotate)

	var rect model.Rectangle
	switch {
	case len(l.Rect) == 4:
		if rect, err = ParseRect(l.Rect); err != nil {
			return out, err
		}
	case target != nil && len(target.Rect) == 4:
		fr := RectOf(target.Rect)
		w, h := sizeFor(l, natW, natH, fr)
		if rect, err = Anchor(fr, F(w), F(h), F(l.Margin), out.Position); err != nil {
			return out, err
		}
	default:
		w, h := sizeFor(l, natW, natH, box)
		if rect, err = Anchor(box, F(w), F(h), F(l.Margin), out.Position); err != nil {
			return out, err
		}
		ox, oy := ParseOffset(l.Offset)
		rect = model.Rectangle{
			Llx: rect.Llx + ox, Lly: rect.Lly + oy,
			Urx: rect.Urx + ox, Ury: rect.Ury + oy,
		}
	}

	w, h := float64(rect.Urx-rect.Llx), float64(rect.Ury-rect.Lly)
	if w <= 0 || h <= 0 {
		return out, fmt.Errorf("logo %s: resulting size is %sx%s", describe(l), Fmt(rect.Urx-rect.Llx), Fmt(rect.Ury-rect.Lly))
	}

	// Content stream: q, [alpha], cm (translate + rotate + scale), Do, Q
	var b bytes.Buffer
	b.WriteString("q\n")
	if l.Opacity > 0 && l.Opacity < 1 {
		b.WriteString(fmt.Sprintf("/%s gs\n", addAlphaState(page.Resources, l.Opacity)))
	}
	// A form/image XObject with a unit box is scaled to the target size and
	// positioned at its corner; rotation happens around the centre of the
	// target. The scale must be part of a, b, c, d: translating *then*
	// scaling multiplies the position by the size and puts the stamp far
	// outside the page.
	b.WriteString(fmtMatrix(placeMatrix(rect, l.Rotate+rot)))
	b.WriteString(" cm\n")
	b.WriteString(fmt.Sprintf("/%s Do\nQ\n", addXObjectImage(page.Resources, img)))

	page.Contents = append(page.Contents, model.ContentStream{
		Stream: model.NewCompressedStream(b.Bytes()),
	})

	if target != nil && !target.HasWidget {
		EnsureReservedWidget(page, target.Name, RectSlice(rect))
	}

	out.Rect, out.Size = RectSlice(rect), []float64{w, h}
	return out, nil
}

func sizeFor(l schema.Logo, natW, natH float64, box model.Rectangle) (float64, float64) {
	bw, bh := float64(box.Urx-box.Llx), float64(box.Ury-box.Lly)
	switch {
	case l.Width > 0 && l.Height > 0:
		return l.Width, l.Height
	case l.Width > 0:
		return l.Width, l.Width * natH / natW
	case l.Height > 0:
		return l.Height * natW / natH, l.Height
	case natW > bw || natH > bh:
		scale := math.Min(bw/natW, bh/natH)
		return natW * scale, natH * scale
	default:
		return natW, natH
	}
}

// rotMatrix is the PDF counter-clockwise rotation by deg degrees.
func rotMatrix(deg float64) model.Matrix {
	if deg == 0 {
		return model.Matrix{1, 0, 0, 1, 0, 0}
	}
	c, s := model.Fl(math.Cos(deg*math.Pi/180)), model.Fl(math.Sin(deg*math.Pi/180))
	return model.Matrix{c, s, -s, c, 0, 0}
}

// MulMatrix multiplies matrices in PDF order (applied left to right).
func MulMatrix(m ...model.Matrix) model.Matrix {
	out := model.Matrix{1, 0, 0, 1, 0, 0}
	for _, x := range m {
		out = out.Multiply(x)
	}
	return out
}

func fmtMatrix(m model.Matrix) string {
	parts := make([]string, 6)
	for i, v := range m {
		parts[i] = Fmt(v)
	}
	return strings.Join(parts, " ")
}

// addXObjectImage registers an image in the resources under a fresh name.
func addXObjectImage(res *model.ResourcesDict, img *model.XObjectImage) string {
	if res.XObject == nil {
		res.XObject = map[model.ObjName]model.XObject{}
	}
	for i := 0; ; i++ {
		name := model.ObjName(fmt.Sprintf("PTImg%d", i))
		if _, taken := res.XObject[name]; !taken {
			res.XObject[name] = img
			return string(name)
		}
	}
}

// addAlphaState registers a constant non-stroking alpha graphic state.
func addAlphaState(res *model.ResourcesDict, alpha float64) string {
	if res.ExtGState == nil {
		res.ExtGState = map[model.ObjName]*model.GraphicState{}
	}
	for i := 0; ; i++ {
		name := model.ObjName(fmt.Sprintf("PTA%d", i))
		if _, taken := res.ExtGState[name]; taken {
			continue
		}
		res.ExtGState[name] = &model.GraphicState{Ca: model.ObjFloat(F(alpha))}
		return string(name)
	}
}

// EnsureReservedWidget gives a widget-less field a minimal read-only widget
// covering rect, so viewers keep the area visible and print it. The
// appearance stream stays empty: the artwork is stamped as page content.
func EnsureReservedWidget(page *model.PageObject, name string, rect []float64) {
	if page == nil || len(rect) != 4 {
		return
	}
	page.Annots = append(page.Annots, &model.AnnotationDict{
		BaseAnnotation: model.BaseAnnotation{
			Rect: RectOf(rect),
			F:    model.APrint | model.AReadOnly,
			NM:   "pdf-go:" + name,
		},
		Subtype: model.AnnotationWidget{},
	})
}

// ImageSize reports the pixel size of an image file, used to check supplied
// artwork before stamping it.
func ImageSize(path string) (int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return 0, 0, err
	}
	return cfg.Width, cfg.Height, nil
}

// placeMatrix is the `cm` operand that draws a unit-box XObject into rect,
// rotated by deg degrees around the centre of rect.
//
// Order matters: scaling the unit box, rotating, then translating. Building
// the matrix as translate-then-scale scales the translation with the size of
// the stamp, which lands the graphic hundreds of points outside the page.
func placeMatrix(rect model.Rectangle, deg float64) model.Matrix {
	w, h := rect.Urx-rect.Llx, rect.Ury-rect.Lly
	cx, cy := rect.Llx+w/2, rect.Lly+h/2
	// The unit box is centred on its own origin, scaled to the target size,
	// rotated, then moved to the centre of rect. MulMatrix composes in PDF
	// order: the leftmost matrix is applied to the point first.
	return MulMatrix(
		model.Matrix{1, 0, 0, 1, -0.5, -0.5},
		model.Matrix{w, 0, 0, h, 0, 0},
		rotMatrix(deg),
		model.Matrix{1, 0, 0, 1, cx, cy},
	)
}
