package signpdf

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/digitorus/pdfsign"
)

// Signing is the only part of the service that touches a PDF signature
// dictionary. Two operations: Certify freezes the document the parties
// review, SignParty adds one approval signature per party. Both take bytes and
// return bytes; neither knows what an envelope is.

// CertifyOptions is the input of Certify.
type CertifyOptions struct {
	Name     string // service identity in the signature, e.g. "signsrv"
	Reason   string
	Location string
	Contact  string
	TSAURL   string // required; empty is an error, not a silent B-B fallback
	Now      time.Time
	Widget   Widget
}

// PartyOptions is the input of SignParty.
type PartyOptions struct {
	Name      string // party name: certificate CN and signature /Name
	Email     string // party email: certificate and /Contact
	Reason    string
	Location  string
	Signature string // the typed signature text (the consent text)
	Image     []byte // optional PNG/JPEG, drawn on the left of the widget
	TSAURL    string
	Now       time.Time
	Widget    Widget
}

// Widget is the on-page placement of a signature appearance.
type Widget struct {
	Page int // 1-based; 0 means 1
	X, Y float64
	W, H float64
}

// Out is the result of one signing pass.
type Out struct {
	Data    []byte
	SHA256  string
	Serial  string // hex serial of the certificate used
	CertPEM string // leaf certificate; Certify returns the CA certificate
}

// Service holds the signing state: CA, TSA, appearance font, clock. It is
// safe for concurrent use: every operation opens its own document, and the CA
// key is only read to sign, never mutated.
type Service struct {
	ca       *CA
	tsaURL   string
	fontName string
	fontData []byte
	clock    func() time.Time

	// anchor, when set, is the certificate every signing certificate in a
	// verified document must have been issued by. Verify checks that directly
	// (the leaf's signature against the anchor's key) rather than building a
	// chain, because our CA signs leaves in one hop and because Go's chain
	// builder applies an extended-key-usage policy this PKI does not satisfy,
	// which would reject our own documents.
	anchor *x509.Certificate
}

// Config is the wiring NewService needs.
type Config struct {
	KeystoreDir string
	Passphrase  string
	TSAURL      string
	FontData    []byte
	FontName    string
	Clock       func() time.Time

	// CASubject identifies the CA when a keystore is created on first
	// start. Ignored when the keystore already exists. Leave nil for the
	// built-in defaults.
	CASubject *CASubject

	// Roots, when non-nil, is the set of certificates a chain must lead to.
	// Used by NewVerifier only; signing does not look at it.
	// Anchor is the certificate every signing certificate in a verified
	// document must have been issued by. See Service.anchor.
	Anchor *x509.Certificate
}

// NewService loads (or creates) the CA and prepares the appearance font.
func NewService(cfg Config) (*Service, error) {
	ca, err := LoadCAWith(cfg.KeystoreDir, cfg.Passphrase, cfg.CASubject)
	if err != nil {
		return nil, err
	}
	if cfg.TSAURL == "" {
		return nil, errors.New("signpdf: TSA URL is required: v1 has no unsigned-signature fallback")
	}
	s := &Service{ca: ca, tsaURL: cfg.TSAURL, fontName: cfg.FontName, fontData: cfg.FontData, clock: cfg.Clock}
	if s.fontName == "" {
		s.fontName = "signsrv-hand"
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

// NewVerifier builds a Service that can only verify. Verification reads the
// signature and the certificate chain inside the document and consults nothing
// else -- Verify touches no field of the Service except the ones it does not
// read at all -- so this constructor opens no keystore, loads no key and
// creates no CA.
//
// That is the point. A recipient running `signsrv checkpdf FILE` has no keystore
// and no business creating one: NewService would happily mint a fresh CA in the
// working directory, and the fingerprint of that CA then looks like evidence in
// the report when it is evidence of nothing.
//
// CA() returns nil on a verifier. Only verification is supported; the signing
// methods would fault, and nothing in this package calls them on a verifier.
func NewVerifier(cfg Config) (*Service, error) {
	s := &Service{
		tsaURL:   cfg.TSAURL,
		fontName: cfg.FontName,
		fontData: cfg.FontData,
		clock:    cfg.Clock,
		anchor:   cfg.Anchor,
	}
	if s.fontName == "" {
		s.fontName = "signsrv-hand"
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

// PinToCA makes a service that holds a CA require its documents to have been
// signed under that CA, so a document signed by an unrelated self-signed
// authority is refused. A service with no anchor accepts any well-formed chain,
// which is a much weaker statement than the report appears to make.
func (s *Service) PinToCA() {
	if s.ca == nil || s.ca.Cert == nil {
		return
	}
	s.anchor = s.ca.Cert
}

// CA exposes the authority so the store layer can record its fingerprint.
func (s *Service) CA() *CA { return s.ca }

// TSAURL is the configured timestamp authority.
func (s *Service) TSAURL() string { return s.tsaURL }

// Roots returns the trust anchor this service verifies against, nil when it
// accepts a chain that terminates anywhere. A caller printing a verdict has to
// say which mode is in force: pinned means the signature leads to a named CA,
// unpinned means the chain only had to hold together.
// Anchor returns the certificate every signing certificate must have been
// issued by, nil when the service accepts any well-formed chain. A caller
// printing a verdict has to say which mode is in force: an anchor makes
// "valid" a statement about who signed, without one it is only a statement
// that the document is intact.
func (s *Service) Anchor() *x509.Certificate { return s.anchor }

// SetAnchor installs a trust anchor after construction, for a caller that
// learns it later than the config does. Safe to call before the first Verify.
func (s *Service) SetAnchor(c *x509.Certificate) { s.anchor = c }

// Certify freezes `in` with a certification signature carrying
// Permission(NoChanges). Filling happens before this call: the result is the
// bytes every party is shown, and the bytes every approval signature is added
// to. Adding approval signatures is the only change NoChanges permits.
func (s *Service) Certify(ctx context.Context, in []byte, o CertifyOptions) (*Out, error) {
	if o.TSAURL == "" {
		return nil, errors.New("signpdf: certify requires a TSA URL (refusing a signature without a signing time)")
	}
	if !bytes.HasPrefix(in, []byte("%PDF-")) {
		return nil, errors.New("signpdf: certify input is not a PDF")
	}
	now := o.Now
	if now.IsZero() {
		now = s.clock()
	}
	if o.Name == "" {
		o.Name = "signsrv"
	}
	doc, err := pdfsign.Open(bytes.NewReader(in), int64(len(in)))
	if err != nil {
		return nil, fmt.Errorf("signpdf: open: %w", err)
	}
	// The certification signature is invisible. pdfsign refuses a visible
	// certification ("visible signatures are only allowed for approval
	// signatures"), and the document's visible markings are the party
	// signatures, which come later.
	//
	// Permission is AllowFormFilling (P=2), not NoChanges. Two facts decided
	// this, both from the vendored library:
	//   - a certification signature at P=1 makes the verifier reject the
	//     addition of a signature field ("DocMDP P=1 does not permit"), so
	//     the party signatures that follow make the document invalid;
	//   - filling is finished before this call, so the form state P=2
	//     permits is exactly what the parties do afterwards: add signature
	//     fields, nothing else.
	// P=2 freezes every byte the parties review; the only object that may
	// change is a signature field.
	doc.Sign(s.ca.Key, s.ca.Cert).
		Type(pdfsign.CertificationSignature).
		Permission(pdfsign.AllowFormFilling). // the constant, not a caller-supplied value
		Format(pdfsign.PAdES_B_T).
		Timestamp(o.TSAURL).
		Digest(crypto.SHA256).
		SignerName(o.Name).
		Reason(o.Reason).
		Location(o.Location).
		Contact(o.Contact).
		Context(ctx)
	return s.finish(doc, s.ca.Cert)
}

// SignParty adds one approval signature over `in`, which must be the certified
// bytes (or the bytes an earlier party produced). The key is generated for
// this call and dropped when Write returns; it is never written, returned, or
// logged.
func (s *Service) SignParty(ctx context.Context, in []byte, o PartyOptions) (*Out, error) {
	if o.TSAURL == "" {
		o.TSAURL = s.tsaURL
		if o.TSAURL == "" {
			return nil, errors.New("signpdf: party signing requires a TSA URL")
		}
	}
	if !bytes.HasPrefix(in, []byte("%PDF-")) {
		return nil, errors.New("signpdf: sign input is not a PDF")
	}
	if o.Name == "" {
		return nil, errors.New("signpdf: party name is required")
	}
	now := o.Now
	if now.IsZero() {
		now = s.clock()
	}
	if len(o.Image) > 0 && !isPNG(o.Image) && !isJPEG(o.Image) {
		return nil, errors.New("signpdf: signature image is not PNG or JPEG")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signpdf: party key: %w", err)
	}
	leaf, err := s.issueLeaf(key, o.Name, o.Email, now)
	if err != nil {
		return nil, err
	}
	doc, err := pdfsign.Open(bytes.NewReader(in), int64(len(in)))
	if err != nil {
		return nil, fmt.Errorf("signpdf: open: %w", err)
	}
	w := normalizeWidget(o.Widget)
	wx, wy, err := placement(doc, w)
	if err != nil {
		return nil, err
	}
	app := s.appearance(doc, o.Signature, o.Name, now, o.Image)
	doc.Sign(key, leaf, s.ca.Cert).
		Type(pdfsign.ApprovalSignature).
		Format(pdfsign.PAdES_B_T).
		Timestamp(o.TSAURL).
		Digest(crypto.SHA256).
		SignerName(o.Name).
		Reason(o.Reason).
		Location(o.Location).
		Contact(o.Email).
		Appearance(app, wx, wy).
		Page(w.Page).
		Context(ctx)
	out, err := s.finish(doc, leaf)
	// The key leaves scope here; nothing keeps a reference to it.
	key = nil
	return out, err
}

// finish writes the staged document and returns the result. The certificate
// that signed this pass is returned in PEM so it can be recorded; the private
// key is never part of the output.
func (s *Service) finish(doc *pdfsign.Document, cert *x509.Certificate) (*Out, error) {
	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		return nil, fmt.Errorf("signpdf: write: %w", err)
	}
	data := buf.Bytes()
	sum := sha256.Sum256(data)
	return &Out{
		Data:    data,
		SHA256:  hex.EncodeToString(sum[:]),
		Serial:  strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())),
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}, nil
}

// issueLeaf mints a short-lived signing certificate for one signature. Validity
// is deliberately minutes long: the key exists only for the signing call, and
// a leaf that outlives the signature is a key sitting around to be stolen.
// leafOrg is the Organization on every leaf certificate. It is taken from the
// CA so a reader sees one identity across the chain rather than the configured
// organisation on the CA and "signsrv" on each signer.
func (s *Service) leafOrg() []string {
	if len(s.ca.Cert.Subject.Organization) > 0 {
		return s.ca.Cert.Subject.Organization
	}
	return []string{"signsrv"}
}

func (s *Service) issueLeaf(pub *ecdsa.PrivateKey, name, email string, now time.Time) (*x509.Certificate, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("signpdf: leaf serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   n,
		Subject:        pkix.Name{CommonName: name, Organization: s.leafOrg()},
		EmailAddresses: []string{email},
		NotBefore:      now.Add(-60 * time.Second),
		NotAfter:       now.Add(15 * time.Minute),
		// ContentCommitment is the X.509 name of the nonRepudiation bit.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		// Email protection is the recognized EKU this service uses; the
		// Document Signing OID is added alongside it so the certificate is
		// RFC 9336 conforming. crypto/x509 has no constant for that OID.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{documentSigningOID},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.Cert, &pub.PublicKey, s.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("signpdf: leaf cert: %w", err)
	}
	return x509.ParseCertificate(der)
}
