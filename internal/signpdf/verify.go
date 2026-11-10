package signpdf

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/digitorus/pdfsign"
)

// Verify is the gate before delivery: a document is sent to parties only when
// every signature on it verifies. It is a pure function - it opens the bytes,
// reads them, and returns a report; it never writes, never mutates the input.

// Report is the verification result of one document.
type Report struct {
	Valid    bool
	Signers  []SignerInfo
	Errors   []string
	Pages    int
	Producer string
}

// SignerInfo is one signature as verification saw it.
type SignerInfo struct {
	Name, Email, Reason string
	Time                time.Time
	Valid               bool
	Trusted             bool
	Revoked             bool
	Serial              string
	Timestamp           bool // the signature carries a validated TSA token
}

// Verify reads `in` and reports every signature. Parameters are fixed by
// policy, not by the caller:
//
//   - Trust anchor: with a pinned pool (Service.roots, from Config.RootsPEM)
//     the chain must lead to one of those certificates and embedded self-signed
//     roots are refused. Without one, TrustSelfSigned(true): the CA is
//     self-signed and not in any system store, so chain trust is asserted by
//     the service rather than the OS. Whichever mode is in force, the Report
//     says which, because `Valid` only means "signed by us" in the pinned mode.
//   - ExternalChecks(false): verification must work in a sealed network and
//     must not depend on a responder being up. Leaf certificates carry no
//     CRLDP/OCSP pointer, so there is nothing to fetch.
//   - MinRSAKeySize(2048), MinECDSAKeySize(256): a 256-bit ECDSA key is the
//     key this service issues; smaller keys are refused.
//   - RequireDigitalSignature(true): the leaf must carry the digital signature
//     key usage.
//
// The context bounds any network request the builder would make; with
// ExternalChecks off there is none, and the context is still passed so a
// deadline cancels a long parse.
func (s *Service) Verify(ctx context.Context, in []byte) (*Report, error) {
	if !bytes.HasPrefix(in, []byte("%PDF-")) {
		return nil, errors.New("signpdf: verify input is not a PDF")
	}
	doc, err := pdfsign.Open(bytes.NewReader(in), int64(len(in)))
	if err != nil {
		return nil, fmt.Errorf("signpdf: open: %w", err)
	}
	// The library always runs the structural check: the digest has to match the
	// document, and the signature has to match the certificate carried inside
	// it. That answers "is this document intact, and did these signatures match
	// it at signing time" - a real answer, but silent on who ran the CA, and a
	// self-signed root inside the document satisfies it just as well as ours
	// does. The anchor is what turns the verdict into one about authorship: see
	// Service.anchor and the TrustedChain/issuedBy check below.
	vb := doc.Verify()
	vb = vb.TrustSelfSigned(true).ExternalChecks(false).
		MinRSAKeySize(2048).
		MinECDSAKeySize(256).
		RequireDigitalSignature(true).
		HTTPTimeout(10 * time.Second).
		Context(ctx)

	report := &Report{Valid: vb.Valid(), Pages: vb.Document().Pages, Producer: vb.Document().Producer}
	if vb.Err() != nil {
		report.Errors = append(report.Errors, vb.Err().Error())
	}
	for _, sig := range vb.Signatures() {
		info := SignerInfo{
			Name:      sig.SignerName,
			Valid:     sig.Valid,
			Trusted:   sig.TrustedChain,
			Revoked:   sig.Revoked,
			Time:      sig.SigningTime,
			Reason:    sig.Reason,
			Timestamp: sig.TimestampValid && sig.Timestamp != nil,
		}
		if sig.Certificate != nil {
			info.Serial = strings.ToUpper(hex.EncodeToString(sig.Certificate.SerialNumber.Bytes()))
			if len(sig.Certificate.EmailAddresses) > 0 {
				info.Email = sig.Certificate.EmailAddresses[0]
			}
			if s.anchor != nil {
				info.Trusted = issuedBy(sig.Certificate, s.anchor)
				if !info.Trusted {
					report.Errors = append(report.Errors, fmt.Sprintf(
						"signature by %s was not issued by %s",
						info.Name, s.anchor.Subject.CommonName))
					info.Valid = false
					report.Valid = false
				}
			}
		}
		for _, e := range sig.Errors {
			if e != nil {
				report.Errors = append(report.Errors, e.Error())
				info.Valid = false
			}
		}
		report.Signers = append(report.Signers, info)
	}
	if len(report.Signers) == 0 && report.Errors == nil {
		report.Errors = append(report.Errors, "no signatures found")
		report.Valid = false
	}
	return report, nil
}

// issuedBy reports whether leaf was issued by anchor. It checks the signature
// the issuing CA put on the leaf rather than building a chain: this PKI is two
// levels deep (CA signs leaves directly), so a direct signature is the whole
// chain, and Go's chain builder enforces an extended-key-usage policy this PKI
// does not satisfy and would reject our own documents.
func issuedBy(leaf, anchor *x509.Certificate) bool {
	if anchor.IsCA {
		return leaf.CheckSignatureFrom(anchor) == nil
	}
	// A certificate that cannot issue certificates cannot have issued this one.
	// Refusing here is what stops -pin pointing at some unrelated certificate
	// and reporting every document as untrusted rather than as a bad anchor.
	return false
}
