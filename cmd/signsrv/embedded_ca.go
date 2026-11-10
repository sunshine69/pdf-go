package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// The trust anchor a recipient's run uses, so that `checkpdf FILE` on its own
// says something about authorship and not only about integrity. Verification
// with no anchor accepts any chain that holds together, including one rooted at
// a certificate the document brought with it; a reader who then saw
// "valid": true would be deceived. Baking the CA into the released binary is
// what lets the instruction be a single command with no config, no second
// download and no URL to type.
//
// The value is the CA's DER, base64 on one line, injected by
// scripts/build-release.sh:
//
//	go build -ldflags "-X 'github.com/sunshine69/pdf-go/cmd/signsrv.embeddedCA=<base64>'"
//
// Two constraints shaped this representation. It has to be a string, because
// `go build -X` can only set a string variable — as a []byte the release build
// would inject nothing, and every recipient binary would silently carry no
// anchor. And it has to be one line, because the linker takes the value
// literally and a PEM's newlines cannot survive the argument.
//
// A binary built without an anchor still verifies, and reports trust: none.
var embeddedCA string

// anchor returns the certificate this run requires a signing certificate to
// have been issued by, plus a description of where it came from for the report.
// The file named by -pin wins; failing that it is the CA baked into this
// binary. A nil certificate means no anchor, and callers must say so in their
// output rather than treating it as a passed check.
func anchor(path string) (*x509.Certificate, string, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("read -pin %s: %w", path, err)
		}
		crt, err := firstCert(b)
		if err != nil {
			return nil, "", fmt.Errorf("-pin %s: %w", path, err)
		}
		return crt, "-pin " + path, nil
	}
	if embeddedCA == "" {
		return nil, "", nil
	}
	der, err := base64.StdEncoding.DecodeString(embeddedCA)
	if err != nil {
		return nil, "", errors.New("this binary carries a malformed trust anchor")
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", errors.New("this binary carries a malformed trust anchor")
	}
	return crt, "this binary", nil
}

// issuedBy is the counterpart of signpdf's check, at the CLI boundary: an
// anchor that cannot issue certificates would mark every document untrusted,
// which reads as a bad document rather than as a wrong flag.
func anchorIsUsable(c *x509.Certificate, src string) error {
	if c == nil || c.IsCA {
		return nil
	}
	return fmt.Errorf("%s is not a certificate authority, so it cannot pin a signature", src)
}

// firstCert parses the first certificate in a PEM bundle, or a bare DER file.
func firstCert(b []byte) (*x509.Certificate, error) {
	if len(b) > 0 && b[0] != '-' {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("no certificate found: %w", err)
		}
		return c, nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no certificate found")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("no certificate found: %w", err)
	}
	return c, nil
}
