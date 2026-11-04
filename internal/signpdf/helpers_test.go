package signpdf

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"

	pdflib "github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
)

// Small helpers the tests use: open a document without signing it, and read a
// PEM certificate. They live in the test file so they cannot be reached from
// the service.

func openForTest(data []byte) (*pdfsign.Document, error) {
	return pdfsign.Open(bytes.NewReader(data), int64(len(data)))
}

// readerFor opens `data` as a plain PDF reader, for assertions that need the
// document structure (a /Perms entry, a widget) rather than the signature.
func readerFor(data []byte) (*pdflib.Reader, error) {
	return pdflib.NewReader(bytes.NewReader(data), int64(len(data)))
}

func pemDecode(data []byte) ([]byte, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	return b.Bytes, nil
}

type x509Certificate = x509.Certificate

func parseCert(der []byte) (*x509Certificate, error) { return x509.ParseCertificate(der) }
