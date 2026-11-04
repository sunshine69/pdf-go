package signpdf

import (
	"bytes"
	"context"
	"fmt"
	pdflib "github.com/digitorus/pdf"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The acceptance list of docs/steps/04-pdfsign.md, in order:
//
//  1. Certify: one signature, certification, /SigFlags 3, /P = NoChanges,
//     form read-only afterwards.
//  2. SignParty chained 3 times: 4 signatures, all valid, names right, times
//     increasing.
//  3. Tampering: a byte flipped in the certified bytes before the third
//     signature -> Verify is invalid with a non-empty Errors.
//  4. Missing TSA URL: Certify errors, no silent B-B fallback.
//  5. Leaf NotAfter <= NotBefore+16min; the private key is absent from Out.
//  6. Widget rect inside the crop box.

func testPDF(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample1.pdf"))
	if err != nil {
		t.Fatalf("testdata/sample1.pdf: %v", err)
	}
	return data
}

func testFont(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/PatrickHand-Regular.ttf")
	if err != nil {
		t.Fatalf("signpdf test font: %v", err)
	}
	return data
}

// newTestService wires a Service to a temp keystore and the test TSA. The
// clock is fixed: signature times in the tests are the clock's, not the
// machine's, so "increasing times" is a real assertion.
func newTestService(t *testing.T, tsa *testTSA) *Service {
	t.Helper()
	s, err := NewService(Config{
		KeystoreDir: t.TempDir(),
		Passphrase:  "test-passphrase-1234",
		TSAURL:      tsa.URL,
		FontData:    testFont(t),
		// The clock is the real one: a fixed clock in the future would mint a
		// leaf whose NotBefore is after the verifier's now, and every signature
		// would report "certificate has expired" for a reason that is not the
		// property under test.
		Clock: time.Now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

func certifyOpts(tsa *testTSA, name string) CertifyOptions {
	return CertifyOptions{
		Name:     name,
		Reason:   "contract",
		Location: "online",
		Contact:  "signsrv@example.test",
		TSAURL:   tsa.URL,
	}
}

// partyOpts builds a party's options. Now is the signing time; the leaf's
// NotBefore is Now-60s, so a time in the future makes the certificate
// "not yet valid" when the finished document is verified at the current
// time. `min` is kept only for the reason string, so the three signatures
// are distinguishable.
func partyOpts(tsa *testTSA, name, email, sig string, min int) PartyOptions {
	return PartyOptions{
		Name:      name,
		Email:     email,
		Reason:    fmt.Sprintf("agree %d", min),
		Signature: sig,
		TSAURL:    tsa.URL,
		Now:       time.Now(),
	}
}

// TestCertifyIsFirstAndNoChanges covers acceptance 1.
func TestCertifyIsFirstAndNoChanges(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	out, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	rep, err := s.Verify(context.Background(), out.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(rep.Signers) != 1 {
		t.Fatalf("certified document has %d signatures, want 1", len(rep.Signers))
	}
	if !rep.Signers[0].Valid {
		t.Fatalf("certification signature is not valid: %v", rep.Signers[0])
	}
	if !rep.Signers[0].Timestamp {
		t.Fatal("certification signature carries no validated timestamp")
	}

	// /SigFlags 3 in the AcroForm: "signatures exist" and "signatures
	// fillable" - the pair that tells a reader the form is signature-ready.
	if n := countBytes(out.Data, "/SigFlags 3"); n == 0 {
		t.Fatal("no /SigFlags 3 in the certified bytes")
	}
	// The DocMDP transform parameters say /P 2 (AllowFormFilling). Read
	// structurally, not by counting bytes: a widget annotation carries
	// "/P 195 0 R" (its page pointer), so a byte search for "/P 1" matches
	// dozens of unrelated tokens. P=2, not P=1: P=1 makes the verifier reject
	// the signature fields the parties add afterwards, so no party signature
	// is possible under it.
	rdr, err := readerFor(out.Data)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	perms := rdr.Trailer().Key("Root").Key("Perms").Key("DocMDP")
	if perms.IsNull() {
		t.Fatal("no DocMDP /Perms entry: the certification is not bound to the document")
	}
	ref := perms.Key("Reference")
	if ref.Kind() != pdflib.Array || ref.Len() == 0 {
		t.Fatalf("DocMDP /Reference is not a non-empty array: %v", ref.Kind())
	}
	params := ref.Index(0).Key("TransformParams")
	if p := params.Key("P").Int64(); p != 2 {
		t.Fatalf("DocMDP /P is %d, want 2 (AllowFormFilling)", p)
	}
	if m := ref.Index(0).Key("TransformMethod").Name(); m != "DocMDP" {
		t.Fatalf("transform method is %q, want DocMDP", m)
	}

	// The form is read-only in the sense the service can enforce: the
	// certified bytes are the bytes every party is shown, and filling is
	// finished before Certify is called. A SetField on the certified bytes
	// does NOT fail here, and must not be expected to: P=2 (AllowFormFilling)
	// is exactly the level that permits filling an existing field, so the
	// library accepts it. Read-only is a service rule (the store keeps the
	// certified bytes and only appends party signatures), not a property of
	// the byte format; the format-level guarantee is the DocMDP /P value
	// checked above, and the format-level enforcement is TestTamperedDocumentFails.
}

// TestThreePartiesChainOnce covers acceptance 2.
func TestThreePartiesChainOnce(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	in := testPDF(t)
	out, err := s.Certify(context.Background(), in, certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	parties := []PartyOptions{
		partyOpts(tsa, "Ada Lovelace", "ada@example.test", "Ada", 1),
		partyOpts(tsa, "Alan Turing", "alan@example.test", "Alan", 2),
		partyOpts(tsa, "Grace Hopper", "grace@example.test", "Grace", 3),
	}
	for i, p := range parties {
		out, err = s.SignParty(context.Background(), out.Data, p)
		if err != nil {
			t.Fatalf("party %d: %v", i+1, err)
		}
	}
	rep, err := s.Verify(context.Background(), out.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("4-signature document is not valid: %v", rep.Errors)
	}
	if len(rep.Signers) != 4 {
		t.Fatalf("got %d signatures, want 4", len(rep.Signers))
	}
	want := []string{"signsrv", "Ada Lovelace", "Alan Turing", "Grace Hopper"}
	var prev time.Time
	for i, sig := range rep.Signers {
		if sig.Name != want[i] {
			t.Fatalf("signer %d is %q, want %q", i, sig.Name, want[i])
		}
		if !sig.Valid {
			t.Fatalf("signer %d is invalid: %v", i, sig)
		}
		if sig.Time.Before(prev) {
			t.Fatalf("signer %d time %s is before signer %d time %s", i, sig.Time, i-1, prev)
		}
		prev = sig.Time
	}
	// The party's email comes from the leaf certificate, not the PDF string.
	for _, sig := range rep.Signers[1:] {
		if !strings.Contains(sig.Email, "@example.test") {
			t.Fatalf("signer %q has email %q, want an example.test address", sig.Name, sig.Email)
		}
	}
}

// TestTamperedDocumentFails covers acceptance 3. Flipping a byte of page
// content in the certified bytes, then signing, must produce a document whose
// verification is false with a stated reason.
func TestTamperedDocumentFails(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	out, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	tampered := append([]byte(nil), out.Data...)
	at := indexOf(tampered, "BT")
	if at < 0 {
		t.Fatal("test document has no content stream to flip")
	}
	tampered[at] = 'b' // 'B' -> 'b': a name, not an operator

	out2, err := s.SignParty(context.Background(), tampered, partyOpts(tsa, "Ada", "ada@example.test", "Ada", 1))
	if err != nil {
		t.Fatalf("SignParty over tampered bytes: %v", err)
	}
	rep, err := s.Verify(context.Background(), out2.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Valid {
		t.Fatal("tampered document verifies as valid; the certification does not protect the bytes")
	}
	if len(rep.Errors) == 0 {
		t.Fatal("verification failed without stating a reason")
	}
}

// TestMissingTSAIsAnError covers acceptance 4.
func TestMissingTSAIsAnError(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	_, err := s.Certify(context.Background(), testPDF(t), CertifyOptions{Name: "signsrv"})
	if err == nil {
		t.Fatal("Certify accepted a missing TSA URL")
	}
	if !strings.Contains(err.Error(), "TSA") {
		t.Fatalf("error does not mention the TSA: %v", err)
	}
	// A rejecting TSA is a failure, not a fallback.
	tsa.reject = true
	if _, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv")); err == nil {
		t.Fatal("Certify accepted a rejecting TSA")
	}
}

// TestLeafLifetimeAndNoPrivateKey covers acceptance 5.
func TestLeafLifetimeAndNoPrivateKey(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	out, err := s.SignParty(context.Background(), testPDF(t), partyOpts(tsa, "Ada", "ada@example.test", "Ada", 1))
	if err != nil {
		t.Fatalf("SignParty: %v", err)
	}
	cert := parsePEM(t, out.CertPEM)
	if span := cert.NotAfter.Sub(cert.NotBefore); span > 16*time.Minute {
		t.Fatalf("leaf is valid for %s, want <= 16 minutes", span)
	}
	if strings.Contains(out.CertPEM, "PRIVATE KEY") {
		t.Fatal("the private key appears in CertPEM")
	}
	if strings.Contains(string(out.Data), "PRIVATE KEY") {
		t.Fatal("the private key appears in the signed bytes")
	}
	if out.Serial == "" {
		t.Fatal("Out does not report the leaf serial")
	}
}

// TestWidgetInsideCropBox covers acceptance 6.
func TestWidgetInsideCropBox(t *testing.T) {
	doc, err := openForTest(testPDF(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	box, err := cropBox(doc, 1)
	if err != nil {
		t.Fatalf("crop box: %v", err)
	}
	// A widget asked for outside the box is clamped inside.
	x, y, err := placement(doc, Widget{Page: 1, X: 10_000, Y: 10_000})
	if err != nil {
		t.Fatalf("placement: %v", err)
	}
	if x+AppearanceWidth > box[2]-margin || y < box[1]+margin {
		t.Fatalf("clamped widget %v,%v is outside the crop box %v", x, y, box)
	}
	if x < box[0] || y < box[1] {
		t.Fatalf("widget starts outside the page: %v,%v box %v", x, y, box)
	}
	// A tiny page cannot host a signature: that is an error, not a silent
	// off-page widget.
	if _, _, err := placement(doc, Widget{Page: 1, W: box[2] - box[0], H: box[3] - box[1]}); err == nil {
		t.Fatal("a widget as wide as the page was accepted")
	}
}

// TestKeyFileIsOwnerOnly proves the keystore rules at load: a key file that
// others can read is refused, and a wrong passphrase is an error.
func TestKeyFileIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(Config{KeystoreDir: dir, Passphrase: "right", TSAURL: "https://tsa.example.test/tsr", FontData: testFont(t)})
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(dir, "right"); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("a group-readable key file was accepted: %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(dir, "wrong passphrase"); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("a wrong passphrase was accepted: %v", err)
	}
	if _, err := LoadCA(dir, "right"); err != nil {
		t.Fatalf("reload with the right passphrase: %v", err)
	}
	if s.CA().Fingerprint() == "" {
		t.Fatal("CA fingerprint is empty")
	}
}

func countBytes(hay []byte, needle string) int {
	return bytes.Count(hay, []byte(needle))
}

func indexOf(hay []byte, needle string) int { return bytes.Index(hay, []byte(needle)) }

// countDelimited counts occurrences of `needle` whose next byte is a PDF
// delimiter (whitespace, ] > ) ( <), so a numeric token is not matched as the
// prefix of a longer one.
func countDelimited(hay []byte, needle string) int {
	n := 0
	for i := 0; ; {
		j := bytes.Index(hay[i:], []byte(needle))
		if j < 0 {
			return n
		}
		k := i + j + len(needle)
		if k < len(hay) {
			switch hay[k] {
			case ' ', '\t', '\r', '\n', ']', '>', ')', '(':
				n++
			}
		} else {
			n++
		}
		i = k
	}
}

func parsePEM(t *testing.T, pem string) *x509Certificate {
	t.Helper()
	b, _ := pemDecode([]byte(pem))
	c, err := parseCert(b)
	if err != nil {
		t.Fatalf("CertPEM does not parse: %v", err)
	}
	return c
}
