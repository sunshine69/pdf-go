package signpdf

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The typed signature is the signer's own words, captured on the consent page
// and stored in the consent record. It has to survive into the artefact: a
// signed PDF whose stamp shows only a generated name and a timestamp does not
// record what the party actually agreed to.
//
// These tests read the finished page back with pdftotext rather than checking
// the appearance struct, because every failure mode we have hit -- a missing
// font file in a release image, a font declared with the wrong encoding --
// looks correct in the struct and wrong on the page.

// pageText extracts page 1 of a PDF as text, collapsing whitespace. Returns
// "" and skips the test when poppler is not installed.
func pageText(t *testing.T, pdf []byte) string {
	t.Helper()
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext not installed; cannot check rendered text")
	}
	f := filepath.Join(t.TempDir(), "doc.pdf")
	if err := os.WriteFile(f, pdf, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("pdftotext", "-f", "1", "-l", "1", f, "-").Output()
	if err != nil {
		t.Fatalf("pdftotext: %v", err)
	}
	return strings.Join(strings.Fields(string(out)), " ")
}

func signedWithTypedText(t *testing.T, tsa *testTSA, font []byte, typed string) string {
	t.Helper()
	s, err := NewService(Config{
		KeystoreDir: t.TempDir(), Passphrase: "test-passphrase-1234",
		TSAURL: tsa.URL, FontData: font, Clock: time.Now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	certified, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("certify: %v", err)
	}
	signed, err := s.SignParty(context.Background(), certified.Data, PartyOptions{
		Name: "Steve Kieu", Email: "steve@example.test", Reason: "I agree",
		Signature: typed, TSAURL: tsa.URL, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("SignParty: %v", err)
	}
	return pageText(t, signed.Data)
}

// TestTypedSignatureIsOnPage is the regression test for the bug where the
// signer's typed words never reached the stamp because no font was loaded.
func TestTypedSignatureIsOnPage(t *testing.T) {
	tsa := newTSA(t)
	page := signedWithTypedText(t, tsa, nil, "Hai Kieu")
	if !strings.Contains(page, "Hai Kieu") {
		t.Errorf("typed signature missing from the page.\npage text: %q", page)
	}
	// The generated lines belong there too; the typed text must not have
	// displaced them.
	if !strings.Contains(page, "Steve Kieu") {
		t.Errorf("party name missing from the page.\npage text: %q", page)
	}
	if !strings.Contains(page, "Signed:") {
		t.Errorf("signing time missing from the page.\npage text: %q", page)
	}
}

// TestBundledFontIsUsedWithNoConfig pins the behaviour that makes the bug
// impossible to ship: a service built without any font wiring still draws the
// typed line, because the font is compiled in. The release artefacts contain
// only the binary, so anything read from a path is absent in production.
func TestBundledFontIsUsedWithNoConfig(t *testing.T) {
	if _, _, ok := BundledFont(); !ok {
		t.Fatal("no font compiled in: the go:embed asset is missing from the build")
	}
	if !strings.Contains(BundledFontLicense, "SIL OPEN FONT LICENSE") {
		t.Error("bundled font licence text missing: OFL requires the licence to travel with the font")
	}
	tsa := newTSA(t)
	page := signedWithTypedText(t, tsa, nil, "I agree to this contract")
	if !strings.Contains(page, "I agree to this contract") {
		t.Errorf("default service dropped the typed signature.\npage text: %q", page)
	}
}

// TestNonASCIIStampIsDroppedNotGarbled pins the drop policy. The appearance
// writer declares its font as a simple WinAnsi font and writes the string's raw
// bytes, so a rune above U+007F cannot be represented and used to print one
// typed character as three wrong ones. It is now dropped instead, whole line,
// and the generated lines still print.
//
// The mojibake forms are asserted by content rather than by "the typed string is
// absent", because absence is also what a different bug -- the font not loading
// at all -- would produce.
func TestNonASCIIStampIsDroppedNotGarbled(t *testing.T) {
	for _, tc := range []struct{ label, typed, garbled string }{
		// Scripts with no WinAnsi code points at all. An accented Latin name is
		// no longer in this list: it encodes to a cp1252 byte and renders, so it
		// is asserted the other way round in TestAccentedTextRendersOnPage.
		{"vietnamese", "Đặng Văn Toàn", "Ä•áº·ng"},
		{"cyrillic", "Сигнатура", "Ð¡Ð¸"},
		{"cjk", "合同", "å•ˆ"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			page := signedWithTypedText(t, newTSA(t), nil, tc.typed)
			if strings.Contains(page, tc.garbled) {
				t.Errorf("stamp shows mojibake %q for %q; the line was meant to be dropped.\npage: %q",
					tc.garbled, tc.typed, page)
			}
			if strings.Contains(page, tc.typed) {
				t.Errorf("%q rendered, which contradicts the drop policy; the "+
					"threshold may have moved. page: %q", tc.typed, page)
			}
			// Only the typed line is dropped. The party name and the time are
			// generated, not typed, and stay.
			if !strings.Contains(page, "Steve Kieu") || !strings.Contains(page, "Signed:") {
				t.Errorf("dropping the typed line took the generated lines with it.\npage: %q", page)
			}
		})
	}
}

// TestStampTextPolicy is the unit half of the same rule: the boundary is
// printable ASCII, and the whole string goes rather than the offending rune.
func TestStampTextPolicy(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"Hai Kieu", "Hai Kieu"},
		{"O'Brien & Co.", "O'Brien & Co."},
		{"  spaced  ", "  spaced  "},
		{"", ""},
		// A diacritic inside WinAnsiEncoding is drawn, as the single cp1252 byte
		// the font addresses. "é" typed is 0xE9 drawn, not the two UTF-8 bytes.
		{"André", "Andr\xe9"},
		{"Kiều", ""},
		{"中", ""},
		// A tab or newline is not drawable either; the consent validator has
		// always refused control characters, so this is belt-and-braces.
		{"a\nb", ""},
		{"a\tb", ""},
		// Invalid UTF-8 decodes to U+FFFD and is dropped rather than guessed.
		{"bad\xffbyte", ""},
	} {
		if got := StampText(tc.in); got != tc.want {
			t.Errorf("StampText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, tc := range []struct {
		in      string
		dropped bool
	}{
		{"Hai Kieu", false}, {"", false}, {"Kiều", true},
	} {
		if got := StampTextDropped(tc.in); got != tc.dropped {
			t.Errorf("StampTextDropped(%q) = %v, want %v", tc.in, got, tc.dropped)
		}
	}
}

// TestAccentedTextRendersOnPage is the other half of the same page: a name with
// a diacritic inside WinAnsiEncoding is drawn, not dropped, and drawn as the
// one character the party typed rather than the two bytes UTF-8 would have put
// there. Before the encoder existed this line printed as "AndrÃ© Dupont".
func TestAccentedTextRendersOnPage(t *testing.T) {
	for _, tc := range []struct{ label, typed, mojibake string }{
		{"french", "André Dupont", "AndrÃ©"},
		{"german", "Müller", "MÃ¼ller"},
		{"spanish", "Señor", "SeÃ±or"},
		// A curly apostrophe and an en dash arrive from a word processor and
		// land in cp1252's 0x80-0x9F block.
		{"curly-quote", "O’Brien", "Oâ€™"},
		{"en-dash", "Kieu–Smith", "Kieuâ€“"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			page := signedWithTypedText(t, newTSA(t), nil, tc.typed)
			if !strings.Contains(page, tc.typed) {
				t.Errorf("typed %q did not render.\npage: %q", tc.typed, page)
			}
			if strings.Contains(page, tc.mojibake) {
				t.Errorf("stamp shows %q for %q: the bytes are UTF-8, not WinAnsi.\npage: %q",
					tc.mojibake, tc.typed, page)
			}
		})
	}
}

// TestStampNameLabelsAnUnencodableName: the name line is the service's label for
// the signer, so it is never left blank for want of a code point. A name outside
// WinAnsi is labelled in its unaccented Latin spelling; the receipt keeps the
// exact registered name.
func TestStampNameLabelsAnUnencodableName(t *testing.T) {
	tsa := newTSA(t)
	page := signedWithTypedText(t, tsa, nil, "I agree")
	// The fixture signs as "Steve Kieu", which is pure ASCII and must be drawn
	// exactly, without transliteration.
	if !strings.Contains(page, "Steve Kieu") {
		t.Fatalf("ASCII name was rewritten: %q", page)
	}

	s, err := NewService(Config{
		KeystoreDir: t.TempDir(), Passphrase: "test-passphrase-1234",
		TSAURL: tsa.URL, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	certified, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.SignParty(context.Background(), certified.Data, PartyOptions{
		Name: "Đặng Văn Toàn", Email: "steve@example.test", Reason: "I agree",
		Signature: "Đặng Văn Toàn", TSAURL: tsa.URL, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	page = pageText(t, signed.Data)
	if !strings.Contains(page, "Dang Van Toan") {
		t.Errorf("page does not label the signer in Latin letters.\npage: %q", page)
	}
	if strings.Contains(page, "Ä•áº·ng") {
		t.Errorf("name line is mojibake.\npage: %q", page)
	}
}
