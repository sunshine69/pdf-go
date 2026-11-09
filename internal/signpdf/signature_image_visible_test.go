package signpdf

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Whether a signature image reaches the page is a question about pixels, not
// about object counts: a document can carry an image XObject that lands outside
// the widget, under a clip, or squashed to a line nobody can read. The checks
// below sign a real document, render it with the tool a recipient would use, and
// look for the colour of the uploaded image inside the signature box.

func redJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 80, 40))
	for y := 0; y < 40; y++ {
		for x := 0; x < 80; x++ {
			img.Set(x, y, color.NRGBA{R: 230, G: 20, B: 20, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatalf("jpeg: %v", err)
	}
	return buf.Bytes()
}

func greenPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 80, 40))
	for y := 0; y < 40; y++ {
		for x := 0; x < 80; x++ {
			img.Set(x, y, color.NRGBA{R: 20, G: 200, B: 20, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png: %v", err)
	}
	return buf.Bytes()
}

func near(got, want uint8) bool {
	d := int(got) - int(want)
	if d < 0 {
		d = -d
	}
	return d <= 60
}

// hasHue reports whether the raster contains enough pixels of the uploaded
// colour to count as visible. A threshold above one is deliberate: a single
// stray pixel is compression noise, not a signature.
func hasHue(t *testing.T, pngBytes []byte, want color.NRGBA) (int, bool) {
	t.Helper()
	img, _, err := image.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("decode render: %v", err)
	}
	b := img.Bounds()
	n := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if a < 0x8000 {
				continue
			}
			// Compare in 8-bit space with room for anti-aliasing and JPEG
			// chroma subsampling.
			if near(uint8(r>>8), want.R) && near(uint8(g>>8), want.G) && near(uint8(bl>>8), want.B) {
				n++
			}
		}
	}
	return n, n >= 30
}

// signWithImage signs the sample document as one party with the given image and
// returns the finished bytes.
func signWithImage(t *testing.T, s *Service, tsa *testTSA, image []byte, w Widget) []byte {
	t.Helper()
	certified, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("certify: %v", err)
	}
	out, err := s.SignParty(context.Background(), certified.Data, PartyOptions{
		Name:      "Ada Lovelace",
		Email:     "ada@example.test",
		Reason:    "agree",
		Signature: "Ada",
		TSAURL:    tsa.URL,
		Image:     image,
		Now:       time.Now(),
		Widget:    w,
	})
	if err != nil {
		t.Fatalf("sign party: %v", err)
	}
	return out.Data
}

// renderFirstPage rasterises page 1 with pdftoppm, the way a recipient's viewer
// would. Skips when the tool is absent rather than failing a machine with no
// poppler.
func renderFirstPage(t *testing.T, pdf []byte) []byte {
	t.Helper()
	path, err := exec.LookPath("pdftoppm")
	if err != nil {
		t.Skip("pdftoppm not installed; cannot check rendered pixels")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "doc.pdf")
	if err := os.WriteFile(in, pdf, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(path, "-png", "-singlefile", "-r", "150", "-f", "1", "-l", "1",
		in, filepath.Join(dir, "page")).CombinedOutput()
	if err != nil {
		t.Fatalf("pdftoppm: %v\n%s", err, out)
	}
	pngBytes, err := os.ReadFile(filepath.Join(dir, "page.png"))
	if err != nil {
		t.Fatalf("read render: %v", err)
	}
	return pngBytes
}

func TestSignatureImageIsVisibleOnThePage(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	for _, tc := range []struct {
		name  string
		image func(t *testing.T) []byte
		rgb   color.NRGBA
	}{
		{"png", greenPNG, color.NRGBA{R: 20, G: 200, B: 20}},
		{"jpeg", redJPEG, color.NRGBA{R: 230, G: 20, B: 20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := tc.image(t)
			data := signWithImage(t, s, tsa, img, Widget{Page: 1, X: 60, Y: 60, W: 220, H: 30})
			render := renderFirstPage(t, data)
			n, ok := hasHue(t, render, tc.rgb)
			if !ok {
				t.Errorf("uploaded %s signature image is not visible on the rendered "+
					"page: only %d pixels match its colour", tc.name, n)
			}
		})
	}
}

// TestTypedOnlyDocumentHasNoImageColour keeps the probe honest: without an
// upload, no page pixel may carry the image's colour, or the check above proves
// nothing.
func TestTypedOnlyDocumentHasNoImageColour(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	data := signWithImage(t, s, tsa, nil, Widget{Page: 1, X: 60, Y: 60, W: 220, H: 30})
	render := renderFirstPage(t, data)
	n, ok := hasHue(t, render, color.NRGBA{R: 230, G: 20, B: 20})
	if ok {
		t.Errorf("a document signed with no image shows the image's colour anyway "+
			"(%d pixels); the probe is measuring the wrong thing", n)
	}
}
