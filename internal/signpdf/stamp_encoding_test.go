package signpdf

import (
	"testing"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// StampText hands the appearance writer WinAnsi bytes, so a wanted value in
// these tests is a byte string: "Andr\xe9" is the single cp1252 byte for
// "e with acute", while the Go literal "André" is the two-byte UTF-8 form the
// writer would have drawn as two wrong glyphs.

// referenceWinAnsi encodes a string to cp1252, or fails when a rune has no byte
// in the character set. It is the table the hand-written one is checked against.
func referenceWinAnsi(s string) (string, bool) {
	out, _, err := transform.String(charmap.Windows1252.NewEncoder(), s)
	if err != nil {
		return "", false
	}
	return out, true
}

// TestStampTextIsCp1252Exactly checks the hand-written table against a
// reference Windows-1252 encoder for every scalar value Unicode has. A missing
// entry is not cosmetic: it drops a whole signature line, so a name like
// "Andr<eacute>" or a pasted en dash would vanish from the page while the
// receipt claimed the stamp carried it. charmap.Windows1252 is the authoritative
// table, in the module already required for the transliteration, so the check
// needs no test data and no external process.
//
// The one deliberate difference: control characters and DEL are refused here
// even though cp1252 has bytes for them. They have no drawable glyph, and the
// consent validator has always rejected control characters in a signature.
func TestStampTextIsCp1252Exactly(t *testing.T) {
	for r := rune(1); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		s := string(r)
		got := StampText(s)
		want, ok := referenceWinAnsi(s)

		if r < ' ' || r == 0x7F {
			if got != "" {
				t.Errorf("U+%04X: control character drew %q, want the line dropped", r, got)
			}
			continue
		}
		if !ok {
			if got != "" {
				t.Errorf("U+%04X: cp1252 has no byte for it, StampText drew %q", r, got)
			}
			continue
		}
		if got == "" {
			t.Errorf("U+%04X: cp1252 encodes to 0x%02X, StampText dropped the line",
				r, want[0])
			continue
		}
		if got != want {
			t.Errorf("U+%04X: StampText drew %q, cp1252 says %q", r, got, want)
		}
	}

	for _, s := range []string{
		"Andr\u00e9 Dupont", "M\u00fcller", "Se\u00f1or", "Zo\u00eb",
		"\u201cAgree\u201d \u2014 2026", "100\u2026", "\u00bc \u00bd \u00be",
		"\u00a35 \u00b7 \u20ac7", "O\u2019Brien", "\u0152uvre \u0153il",
	} {
		want, ok := referenceWinAnsi(s)
		if !ok {
			t.Fatalf("reference cannot encode %q", s)
		}
		if got := StampText(s); got != want {
			t.Errorf("StampText(%q) = %q, want the cp1252 bytes %q", s, got, want)
		}
	}
}

// TestStampNameLabelsAnyLatinName: the name line is the service's label for the
// signer, so it is never left blank for want of a code point. A name WinAnsi
// cannot address is labelled in its unaccented Latin spelling, the same form the
// name takes in any system that does not carry diacritics.
func TestStampNameLabelsAnyLatinName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		// Encodable names are drawn as typed, not rewritten.
		{"Steve Kieu", "Steve Kieu"},
		{"Andr\u00e9 Dupont", "Andr\xe9 Dupont"},
		{"M\u00fcller", "M\xfcller"},
		// S with caron has a cp1252 byte, so it is encoded rather than
		// transliterated away.
		{"\u017divot", "\x8Eivot"}, // Z with caron is cp1252 byte 0x8E
		// Diacritics outside cp1252 fall back to the bare letters.
		{"\u0110\u1EB7ng V\u0103n To\u00e0n", "Dang Van Toan"},
		{"Nguy\u1ec5n Th\u1ecb H\u01b0\u01a1ng", "Nguyen Thi Huong"},
		{"\u0130stanbul", "Istanbul"},
		{"D\u00fcrenberg", "D\xfcrenberg"},
		// Letters that survive mark removal because they carry no diacritic to
		// remove. The stroke letters and the comma-below pair are common in
		// surnames, and each was a whole missing name line before it had an
		// entry of its own.
		{"\u0141ukasz Nowak", "Lukasz Nowak"},
		{"\u0218tefan \u021airiac", "Stefan Tiriac"},
		// Latin letters WinAnsi does address are drawn as typed, not
		// transliterated: the sharp s is byte 0xDF, not "ss", and the Norwegian
		// and Icelandic letters are WinAnsi bytes of their own.
		{"Stra\u00dfe", "Stra\xdfe"},
		{"\u00c6r\u00f8", "\xc6r\xf8"},
		{"\u00d8degaard", "\xd8degaard"},
		{"\u00deorsson", "\xdeorsson"},
		{"\u00c5ngstr\u00f6m", "\xc5ngstr\xf6m"},
		// Not Latin at all: no Latin spelling exists, so the line is left out
		// rather than drawn as something the party never signed.
		{"\u0421\u0438\u0433\u043d\u0430\u0442\u0443\u0440\u0430", ""},
		{"\u7530\u4e2d\u592a\u90ce", ""},
		{"", ""},
	} {
		if got := StampName(tc.in); got != tc.want {
			t.Errorf("StampName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestStampNameAlwaysDrawsWinAnsi is the property the name line exists to
// guarantee: whatever a party is called, the bytes handed to the appearance
// writer are inside WinAnsiEncoding. A byte outside it is mojibake.
func TestStampNameAlwaysDrawsWinAnsi(t *testing.T) {
	for r := rune(0); r <= 0xFFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		name := "A" + string(r) + " z"
		drawn := StampName(name)
		if drawn == "" {
			continue // no Latin spelling: the line is omitted, which is allowed
		}
		// drawn is a byte string, so it is checked by DECODING it: every byte
		// must be one cp1252 defines. Re-encoding it would read the bytes as
		// UTF-8, which is the very confusion this policy exists to avoid.
		if _, _, err := transform.String(charmap.Windows1252.NewDecoder(), drawn); err != nil {
			t.Errorf("StampName(%q) drew %q, which is not valid cp1252", name, drawn)
		}
	}
}

// TestStampNameIsNotTransliteratedWhenItNeedNotBe guards the direction of the
// rule: transliteration is the fallback, never the default. A name typed with
// an accent keeps its accent.
func TestStampNameIsNotTransliteratedWhenItNeedNotBe(t *testing.T) {
	for _, s := range []string{
		"André Dupont", "Müller", "Señor", "Zoë", "Ångström", "Renée",
	} {
		got := StampName(s)
		want, ok := referenceWinAnsi(s)
		if !ok {
			t.Fatalf("reference cannot encode %q", s)
		}
		if got != want {
			t.Errorf("StampName(%q) = %q, want the same bytes as typed (%q)", s, got, want)
		}
		// Reading the drawn bytes back with the same character set has to give
		// the name the party registered. That is the whole point of encoding:
		// what the reader sees is what was typed.
		back, _, err := transform.String(charmap.Windows1252.NewDecoder(), got)
		if err != nil || back != s {
			t.Errorf("reading back StampName(%q) gives %q (err %v)", s, back, err)
		}
	}
}
