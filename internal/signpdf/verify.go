package signpdf

import (
	"bytes"
	"context"
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
//   - TrustSelfSigned(true): the CA is self-signed and not in any system
//     store, so chain trust is asserted by the service, not by the OS.
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
	vb := doc.Verify().
		TrustSelfSigned(true).
		ExternalChecks(false).
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
	if !report.Valid {
		return report, nil
	}
	return report, nil
}
