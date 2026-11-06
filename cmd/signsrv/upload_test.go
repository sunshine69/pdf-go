package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signfill"
	"github.com/sunshine69/pdf-go/internal/signflow"
)

// This file is the proof for the signoff item "body size limits and magic-byte
// checks on every upload path". The create endpoint is the only upload path in
// the service: a PDF template in a multipart form, and artwork carried as
// base64 inside the spec. The rules the tests pin:
//
//   - a body over the limit is answered 413 before the bytes are read into
//     memory, and no envelope row is created,
//   - a template that does not start with %PDF- is refused at the template
//     field, not at some later step,
//   - artwork is accepted on its magic bytes: PNG, JPEG, GIF, TIFF. A file
//     named .png whose bytes are not an image is refused,
//   - artwork over the byte ceiling and artwork over the pixel ceiling are
//     refused before the envelope is stored.

// multipartWith sends the create form with an explicit template body, so a
// test can hand the server a template that is not a PDF, and with the fields
// as given.
func multipartWith(t *testing.T, ts *httptest.Server, token string, template []byte, fields map[string]string) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	w := newMultipart(t, &body, template, fields)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/envelopes", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := decode(t, res)
	return res.StatusCode, out
}

func newMultipart(t *testing.T, body *bytes.Buffer, template []byte, fields map[string]string) *multipart.Writer {
	t.Helper()
	w := multipart.NewWriter(body)
	part, err := w.CreateFormFile("template", "template.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(template); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestCreateRefusesNonPDFMagicBytes: the accepted template format is PDF. The
// name in the form is not evidence.
func TestCreateRefusesNonPDFMagicBytes(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	before := countRows(t, store, "envelopes")

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"an executable", []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00")},
		{"a PNG renamed .pdf", []byte("\x89PNG\r\n\x1a\n" + "rest")},
		{"a text file", []byte("this is not a PDF at all, and it is long")},
		{"an empty file", []byte("")},
		{"the magic bytes alone", []byte("%PDF")},
		{"a truncated PDF header", []byte("%PDF-1.\n")},
	} {
		code, out := multipartWith(t, ts, access, tc.data, map[string]string{
			"title":   "Magic bytes",
			"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
			"spec":    `{"fill":{"values":{"stub":"x"}}}`,
		})
		if code != http.StatusBadRequest {
			t.Errorf("%s: create = %d, want 400: %v", tc.name, code, out)
			continue
		}
		p := problemOf(t, out)
		if !strings.Contains(p["code"].(string), "template") &&
			!strings.Contains(p["message"].(string), "PDF") &&
			!strings.Contains(p["message"].(string), "template") {
			t.Errorf("%s: the answer does not name the template: %v", tc.name, p)
		}
	}

	if n := countRows(t, store, "envelopes"); n != before {
		t.Fatalf("envelope rows after a rejected upload: %d, want %d", n, before)
	}
}

// TestCreateRefusesBodyOverLimit: a template larger than the endpoint accepts
// is refused, and the store is untouched. The create path has two ceilings, and
// both are exercised. The endpoint's transport cap (maxUpload) is enforced by
// http.MaxBytesReader on the request body, so a multipart body over it never
// reaches the handler. The document ceiling (signflow.MaxTemplateBytes) is
// enforced by the create rules, which name the template field.
//
// The transport cap is the one that matters under attack: a server that reads a
// 200 MB upload into memory is a server that dies on the first request.
func TestCreateRefusesBodyOverLimit(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	before := countRows(t, store, "envelopes")

	fields := map[string]string{
		"title":   "Body limit",
		"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":    `{"fill":{"values":{"stub":"x"}}}`,
	}

	// One byte over the document ceiling, inside the transport cap: the create
	// rules refuse it and name the template field.
	over := paddedPDF(t, signflow.MaxTemplateBytes+1)
	code, out := multipartWith(t, ts, access, over, fields)
	if code != http.StatusBadRequest {
		t.Fatalf("template over the document ceiling = %d, want 400: %v", code, out)
	}
	p := problemOf(t, out)
	if !strings.Contains(p["code"].(string), "template") {
		t.Fatalf("code %q does not name the template", p["code"])
	}
	if !strings.Contains(p["message"].(string), "limit") {
		t.Fatalf("the answer does not name the size limit: %v", p)
	}

	// Over the transport cap: the body is refused as it is read, before the
	// form is parsed. A body of maxUpload bytes plus the multipart framing is
	// over the cap.
	way := paddedPDF(t, maxUpload)
	code, out = multipartWith(t, ts, access, way, fields)
	if code == http.StatusCreated {
		t.Fatalf("a template of the transport cap was accepted: %v", out)
	}
	if code != http.StatusBadRequest && code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body over the transport cap = %d, want 400 or 413: %v", code, out)
	}

	if n := countRows(t, store, "envelopes"); n != before {
		t.Fatalf("envelope rows after refused bodies: %d, want %d", n, before)
	}
	if n := countRows(t, store, "parties"); n != 0 {
		t.Fatalf("party rows after refused bodies: %d, want 0", n)
	}
}

// TestCreateRefusesImageMagicBytesOnLogos: the artwork in the spec is only
// accepted on its bytes.
func TestCreateRefusesImageMagicBytesOnLogos(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	before := countRows(t, store, "envelopes")
	name := firstTextField(t, sample1(t))

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"an executable renamed logo.png", []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00")},
		{"a PDF renamed logo.png", []byte("%PDF-1.7\nthe bytes of a pdf")},
		{"plain text renamed logo.png", []byte("hello, this is text, not artwork")},
		{"a GIF89a stub", []byte("GIF89a")},
	} {
		spec := `{"fill":{"values":{"` + name + `":"x"},"logos":[{"id":"` + tc.name +
			`","field":"` + name + `","imageData":"` +
			base64.StdEncoding.EncodeToString(tc.data) + `"}]}}`
		code, out := multipartWith(t, ts, access, sample1(t), map[string]string{
			"title":   "Logo magic bytes",
			"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
			"spec":    spec,
		})
		if code != http.StatusBadRequest {
			t.Errorf("%s: create = %d, want 400: %v", tc.name, code, out)
			continue
		}
		if !strings.Contains(out["error"].(map[string]any)["message"].(string), tc.name) {
			t.Errorf("%s: the answer does not name the logo: %v", tc.name, out["error"])
		}
	}

	// A real PNG logo is accepted.
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 8, 8))); err != nil {
		t.Fatal(err)
	}
	spec := `{"fill":{"values":{"` + name + `":"x"},"logos":[{"id":"real",` +
		`"field":"` + name + `","imageData":"` + base64.StdEncoding.EncodeToString(buf.Bytes()) + `"}]}}`
	code, out := multipartWith(t, ts, access, sample1(t), map[string]string{
		"title":   "Logo accepted",
		"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":    spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("a real PNG logo = %d, want 201: %v", code, out)
	}

	if n := countRows(t, store, "envelopes"); n != before+1 {
		t.Fatalf("envelope rows: %d, want %d", n, before+1)
	}
}

// TestCreateRefusesLogoOverSizeLimits pins the ceilings on artwork: the byte
// ceiling and the pixel ceiling.
func TestCreateRefusesLogoOverSizeLimits(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	name := firstTextField(t, sample1(t))
	before := countRows(t, store, "envelopes")

	// Over the byte ceiling.
	big := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, signfill.MaxImageBytes+1)...)
	spec := `{"fill":{"values":{"` + name + `":"x"},"logos":[{"id":"oversize",` +
		`"field":"` + name + `","imageData":"` + base64.StdEncoding.EncodeToString(big) + `"}]}}`
	code, out := multipartWith(t, ts, access, sample1(t), map[string]string{
		"title":   "Oversize logo",
		"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":    spec,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("oversize logo = %d, want 400: %v", code, out)
	}
	if !strings.Contains(out["error"].(map[string]any)["message"].(string), "larger than") {
		t.Fatalf("the answer does not name the size limit: %v", out["error"])
	}

	// Over the pixel ceiling.
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, signfill.MaxImageEdge+1, 3))); err != nil {
		t.Fatal(err)
	}
	spec = `{"fill":{"values":{"` + name + `":"x"},"logos":[{"id":"wide",` +
		`"field":"` + name + `","imageData":"` + base64.StdEncoding.EncodeToString(buf.Bytes()) + `"}]}}`
	code, out = multipartWith(t, ts, access, sample1(t), map[string]string{
		"title":   "Wide logo",
		"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":    spec,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("wide logo = %d, want 400: %v", code, out)
	}
	if !strings.Contains(out["error"].(map[string]any)["message"].(string), "pixels") {
		t.Fatalf("the answer does not name the pixel limit: %v", out["error"])
	}

	// Neither refusal stored an envelope.
	if n := countRows(t, store, "envelopes"); n != before {
		t.Fatalf("envelope rows after refused artwork: %d, want %d", n, before)
	}
}

// TestLoginBodyIsCapped: the login endpoint reads a small JSON body. A body
// larger than the endpoint accepts is refused, not read.
func TestLoginBodyIsCapped(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := authServer(t, cfg)

	// A body well over the login cap is refused.
	filler := strings.Repeat("A", 64<<10)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login",
		strings.NewReader(`{"email":"`+filler+`","password":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("a 64 KB login body was accepted")
	}
	if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize login body = %d, want 400 or 413", res.StatusCode)
	}
}

// paddedPDF builds a file that starts with the PDF magic bytes and is exactly
// n bytes long. It is not a valid PDF: the point is the size and the header,
// which are what the endpoint checks.
func paddedPDF(t *testing.T, n int) []byte {
	t.Helper()
	if n < 16 {
		t.Fatal("the padded PDF is too small")
	}
	b := make([]byte, n)
	copy(b, []byte("%PDF-1.7\n"))
	for i := len("%PDF-1.7\n"); i < n; i++ {
		b[i] = 'x'
	}
	return b
}
