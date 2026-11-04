package signflow

import (
	"github.com/sunshine69/pdf-go/internal/schema"
	"github.com/sunshine69/pdf-go/internal/signfill"
	"github.com/sunshine69/pdf-go/internal/signpdf"
)

// The helpers every test in this package reuses. The wiring (store, TSA,
// Deps) lives in envelope_test.go.

// signpdfService builds a signing service backed by the test TSA.
func signpdfService(dir, passphrase, tsa string) (*signpdf.Service, error) {
	return signpdf.NewService(signpdf.Config{
		KeystoreDir: dir,
		Passphrase:  passphrase,
		TSAURL:      tsa,
	})
}

// signfillExtract is the in-memory form schema of a PDF, so a test can read
// back a document the service produced.
func signfillExtract(in []byte) (schema.FormSchema, error) {
	return signfill.Extract(in)
}

// linkFor finds the link of one party by its order.
func linkFor(links []Link, order int) Link {
	for _, l := range links {
		if l.Order == order {
			return l
		}
	}
	return Link{}
}
