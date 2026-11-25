package signpdf

import (
	_ "embed"
)

// The handwriting font used for the typed line in a signature appearance.
//
// It is compiled into the binary rather than read from disk because every
// deployment artifact we ship (the Docker image, the .deb) contains only the
// binary: a font at a filesystem path is present in a developer checkout and
// missing in a release, and a missing font silently drops the typed signature
// from the page -- the signer's own words vanish from the signed file with no
// error anywhere.
//
// Patrick Hand is (c) 2012 Patrick Wagesreiter, licensed under the SIL Open
// Font License 1.1 (see OFL.txt alongside this file, and the same notice in
// the font's own name table). OFL permits embedding in an executable without
// the executable becoming OFL-licensed, provided the licence text travels with
// the font; that is why the licence is embedded as an asset here rather than
// dropped at build time.
// BundledFontName is the PDF resource name the font is registered under. It is
// an internal resource name, not the family name shown to a viewer.
const BundledFontName = "signsrv-hand"

// BundledFontLicense is the licence notice plus the licence text. A binary that
// embeds an OFL font must ship the licence with it, so this is exposed for the
// admin page and for the .deb copyright file.
var BundledFontLicense = "Patrick Hand is Copyright (c) 2012 Patrick Wagesreiter " +
	"<mail@patrickwagesreiter.at> and is licensed under the SIL Open Font License, " +
	"Version 1.1. The full licence text is included below.\n\n" + bundledOFL

//go:embed assets/PatrickHand-Regular.ttf
var bundledFontTTF []byte

//go:embed assets/OFL.txt
var bundledOFL string

// BundledFont returns the compiled-in handwriting font. The boolean reports
// whether the font was compiled in; it is always true in a normal build, and
// callers use it to decide whether to draw the typed line at all.
func BundledFont() ([]byte, string, bool) {
	if len(bundledFontTTF) == 0 {
		return nil, "", false
	}
	return bundledFontTTF, BundledFontName, true
}
