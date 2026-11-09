package signflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
	"time"
)

// The consent contract stores the signature image as a blob and the batch reads
// it back when it draws the appearance. The blob keeps the extension matching
// its content type; the read has to ask for the same one. A signature image
// that cannot be fetched does not fail the batch — it drops out of the page and
// the signer's document shows the typed name instead, which is what an uploader
// reads as "the image was ignored".
//
// The checks below are measured as a delta, not as an absolute: the sample
// document is a real production PDF that already carries image XObjects, so
// "the signed file contains an image" is true whether or not the signature
// image made it in. What has to be true is that the signed file carries more
// images than the same document signed with the same typed name and no upload.

// testJPEGDataURL is a small real JPEG in the data: URL form the signing page
// sends, so the test exercises the same string the browser puts on the wire.
func testJPEGDataURL(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 40, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 40; x++ {
			img.Set(x, y, color.NRGBA{R: 20, G: 90, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("jpeg: %v", err)
	}
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// consentWith sends one party's consent, with image empty for none.
func (f *batchFixture) consentWith(i int, text, image string) {
	f.t.Helper()
	_, err := f.deps.Consent(context.Background(), f.tokens[i], ConsentInput{
		SignatureText: text,
		Consent:       true,
		DocumentSHA:   f.dsha,
		Image:         image,
		IP:            "10.0.0.1",
		UserAgent:     "signflow-image-test",
	}, time.Now().UTC())
	if err != nil {
		f.t.Fatalf("consent party %d: %v", i+1, err)
	}
}

// signedImageCount runs one party's consent and the batch, then reports how
// many image XObjects the finished document declares.
func signedImageCount(t *testing.T, imagePayload string) int {
	t.Helper()
	f := newBatchFixture(t, 1)
	f.consentWith(0, "Alice Adamson", imagePayload)
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	if out.Signed != 1 {
		t.Fatalf("batch signed %d parties, want 1", out.Signed)
	}
	data, err := f.deps.Store.GetPDF(out.Final)
	if err != nil {
		t.Fatalf("read final document: %v", err)
	}
	return countImageXObjects(data)
}

// countImageXObjects counts image subtype declarations, tolerating both the
// "/Subtype /Image" and "/Subtype/Image" spellings that writers differ on.
func countImageXObjects(data []byte) int {
	n := 0
	for _, needle := range [][]byte{
		[]byte("/Subtype /Image"),
		[]byte("/Subtype/Image"),
	} {
		n += bytes.Count(data, needle)
	}
	return n
}

func TestSignatureImageAddsAnImageToThePage(t *testing.T) {
	none := signedImageCount(t, "")

	for _, tc := range []struct {
		name  string
		image func(t *testing.T) string
	}{
		{"png", pngDataURL},
		{"jpeg", testJPEGDataURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withImage := signedImageCount(t, tc.image(t))
			if withImage <= none {
				t.Errorf("%s signature image: signed document declares %d image "+
					"XObjects, the same document signed with no image declares %d; "+
					"the appearance fell back to the typed name",
					tc.name, withImage, none)
			}
		})
	}
}

// TestConsentImageBlobIsReadableUnderItsOwnExtension pins the storage half of
// the chain on its own, so a failure there is not reported as a renderer bug.
// The blob keeps a .png or .jpg name from the content type it decoded as.
func TestConsentImageBlobIsReadableUnderItsOwnExtension(t *testing.T) {
	for _, tc := range []struct {
		name  string
		image func(t *testing.T) string
		ext   string
	}{
		{"png", pngDataURL, ".png"},
		{"jpeg", testJPEGDataURL, ".jpg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchFixture(t, 1)
			ctx := context.Background()
			f.consentWith(0, "Alice Adamson", tc.image(t))

			c, err := f.deps.Store.GetConsentByParty(ctx, f.partyID[0])
			if err != nil {
				t.Fatalf("read consent: %v", err)
			}
			if c.ImageSHA == "" {
				t.Fatal("consent stored no image sha; the upload never reached the record")
			}
			if _, err := f.deps.Store.GetBlob(c.ImageSHA, tc.ext); err != nil {
				t.Fatalf("stored image is not readable as %s: %v", tc.ext, err)
			}
		})
	}
}
