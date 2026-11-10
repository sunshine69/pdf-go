package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sunshine69/pdf-go/internal/signpdf"
)

// signSelftest is the `signsrv sign-selftest` command: certify, sign three
// parties, verify, and print the JSON report. Exit 0 only when the finished
// document is valid. It is the acceptance harness for docs/steps/04-pdfsign.md
// and the sanity check an operator runs after a deploy.
//
// Nothing is written to the database: the command opens the keystore, uses the
// configured TSA, and reads `in` (default testdata/sample1.pdf). The output
// file is written only when -out is given.
// The arguments are positional: `signsrv sign-selftest [-config FILE] [IN]
// [OUT]`. splitArgs keeps flags out of `rest`, so -in/-out as words would
// never arrive here; positional arguments are the ones that do.
func signSelftest(configPath, tsaOverride string, rest []string) int {
	inPath := "testdata/sample1.pdf"
	outPath := ""
	switch len(rest) {
	case 0:
	case 1:
		inPath = rest[0]
	case 2:
		inPath = rest[0]
		outPath = rest[1]
	default:
		fmt.Fprintf(os.Stderr, "signsrv: sign-selftest takes at most IN and OUT\n")
		return 2
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv: configuration:", err)
		if cfg != nil {
			for _, p := range cfg.Problems() {
				fmt.Fprintln(os.Stderr, "  problem:", p)
			}
		}
		return 1
	}

	if tsaOverride != "" {
		// "-" is the explicit no-TSA case, so the acceptance script can
		// prove the error path without writing a config file.
		cfg.TSAURL = tsaOverride
		if tsaOverride == "-" {
			cfg.TSAURL = ""
		}
	}

	in, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: read %s: %v\n", inPath, err)
		return 1
	}

	fontData, fontName := selftestFont(cfg)
	s, err := signpdf.NewService(signpdf.Config{
		KeystoreDir: cfg.Keystore,
		CASubject:   cfg.CASubject,
		Passphrase:  cfg.KeystorePassphrase(),
		TSAURL:      cfg.TSAURL,
		FontData:    fontData,
		FontName:    fontName,
		Clock:       time.Now,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: signing service: %v\n", err)
		return 1
	}
	// The document was signed under this instance's CA, and the point of the
	// selftest is to prove the whole loop, so the verification it prints has to
	// require the same anchor. Unpinned, the selftest would still pass if the
	// signing path produced a document signed by something else entirely.
	s.PinToCA()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := s.Certify(ctx, in, signpdf.CertifyOptions{
		Name:     "signsrv",
		Reason:   "selftest",
		Location: "selftest",
		Contact:  "selftest@localhost",
		TSAURL:   cfg.TSAURL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: certify: %v\n", err)
		return 1
	}

	parties := []struct{ name, email, sig string }{
		{"Ada Lovelace", "ada@example.test", "Ada"},
		{"Alan Turing", "alan@example.test", "Alan"},
		{"Grace Hopper", "grace@example.test", "Grace"},
	}
	for i, p := range parties {
		out, err = s.SignParty(ctx, out.Data, signpdf.PartyOptions{
			Name:      p.name,
			Email:     p.email,
			Reason:    "selftest",
			Signature: p.sig,
			TSAURL:    cfg.TSAURL,
			Widget:    signpdf.PartyWidget(i),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "signsrv: party %d: %v\n", i+1, err)
			return 1
		}
	}

	rep, err := s.Verify(ctx, out.Data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: verify: %v\n", err)
		return 1
	}

	report := selftestReport{
		Valid:     rep.Valid,
		In:        inPath,
		SHA256:    hexSha(out.Data),
		Pages:     rep.Pages,
		Producer:  rep.Producer,
		CA:        hexSha(s.CA().Cert.Raw),
		TSAURL:    s.TSAURL(),
		Signers:   rep.Signers,
		Errors:    rep.Errors,
		ByteSize:  len(out.Data),
		CertStart: len(in),
	}
	applyTrust(&report, s, "keystore in "+cfg.Keystore, false)
	if err := printReport(report); err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, out.Data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "signsrv: write %s: %v\n", outPath, err)
			return 1
		}
	}
	if !rep.Valid {
		return 1
	}
	return 0
}

// checkPDF is `signsrv checkpdf FILE`: run the same verification the
// delivery path uses over a document on disk, print the report, and exit
// non-zero when it is not valid. The operator's tool for "is this file the
// one we signed, and is it intact".
func checkPDF(configPath, tsaOverride, pinPath string, rest []string) int {
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "signsrv: checkpdf takes exactly one FILE")
		return 2
	}
	inPath := rest[0]

	// With no config file, this is a recipient's run: they have the PDF, the
	// binary and nothing else. Verification reads the document, so the service
	// settings do not apply and there is no keystore to open. Requiring them
	// would force a person checking a document to write a six-line config file
	// first, and NewService would then create a CA in their working directory.
	if configPath == "" {
		return checkPDFVerifyOnly(inPath, tsaOverride, pinPath)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv: configuration:", err)
		if cfg != nil {
			for _, p := range cfg.Problems() {
				fmt.Fprintln(os.Stderr, "  problem:", p)
			}
		}
		return 1
	}
	if tsaOverride != "" {
		cfg.TSAURL = tsaOverride
		if tsaOverride == "-" {
			cfg.TSAURL = ""
		}
	}

	in, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: read %s: %v\n", inPath, err)
		return 1
	}
	// Verification makes no network request (ExternalChecks is off), so the
	// TSA URL here is only reported. NewService requires one because it is
	// built for signing; a check-only run supplies a marker so an unconfigured
	// service can still verify a file.
	tsa := cfg.TSAURL
	if tsa == "" {
		tsa = "not-configured"
	}
	s, err := signpdf.NewService(signpdf.Config{
		KeystoreDir: cfg.Keystore,
		CASubject:   cfg.CASubject,
		Passphrase:  cfg.KeystorePassphrase(),
		TSAURL:      tsa,
		Clock:       time.Now,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: signing service: %v\n", err)
		return 1
	}
	// A run that has a keystore has a trust anchor already, so it uses it:
	// -config implies "signed by us", not merely "self-consistent". -pin can
	// still override, for checking a document from another instance.
	crt, src, err := anchor(pinPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: %v\n", err)
		return 1
	}
	if crt != nil {
		if err := anchorIsUsable(crt, src); err != nil {
			fmt.Fprintf(os.Stderr, "signsrv: %v\n", err)
			return 1
		}
		s.SetAnchor(crt)
	} else {
		// -config implies "signed by us", not merely "self-consistent", so the
		// CA this instance holds is the anchor when no other was named.
		s.PinToCA()
		src = "keystore in " + cfg.Keystore
	}
	return runVerify(s, inPath, in, src)
}

// checkPDFVerifyOnly is the no-config path: NewVerifier, then the same
// verification. Nothing is written to disk, and the report carries no
// ca_sha256, because the run has no CA of its own and the CA that signed the
// document is inside the document.
func checkPDFVerifyOnly(inPath, tsaOverride, pinPath string) int {
	in, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: read %s: %v\n", inPath, err)
		return 1
	}
	tsa := tsaOverride
	if tsa == "-" { // same meaning as in the config path: no timestamp authority
		tsa = ""
	}
	if tsa == "" {
		// Same marker the config path uses, so one value means "this report
		// does not say which timestamp authority was configured, because this
		// run had no configuration". The document's own timestamp is reported
		// per signer as Timestamp: true, and that is the field that matters.
		tsa = "not-configured"
	}
	crt, src, err := anchor(pinPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: %v\n", err)
		return 1
	}
	if err := anchorIsUsable(crt, src); err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: %v\n", err)
		return 1
	}
	s, err := signpdf.NewVerifier(signpdf.Config{TSAURL: tsa, Clock: time.Now, Anchor: crt})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: verifier: %v\n", err)
		return 1
	}
	return runVerify(s, inPath, in, src)
}

// applyTrust fills in the fields that tell a reader what the verdict is
// evidence of. `src` says where the anchor came from. When there is none, the
// warning goes to stderr as well as the JSON: a person watching a run that
// prints "valid": true without checking who signed would otherwise read a
// stronger claim than was made.
func applyTrust(r *selftestReport, s *signpdf.Service, src string, warn bool) {
	if a := s.Anchor(); a != nil {
		r.Trust = "pinned"
		r.Anchor = hexSha(a.Raw)
		r.AnchorSrc = src
		return
	}
	r.Trust = "none"
	if warn {
		fmt.Fprintln(os.Stderr, "signsrv: WARNING: no trust anchor, so this run did not check who signed."+
			" Use a binary built by scripts/build-release.sh, or pass -pin FILE.")
	}
}

// runVerify is the shared tail: verify, print the report, exit on the verdict.
// Whether a signing certificate had to lead back to a named CA is read off the
// service and printed as `trust`, because that decides what `valid` means and a
// reader cannot infer it from the rest of the JSON. `src` names where the anchor
// came from, so the report can show its evidence instead of just its verdict.
func runVerify(s *signpdf.Service, inPath string, in []byte, src string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rep, err := s.Verify(ctx, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: verify: %v\n", err)
		return 1
	}
	report := selftestReport{
		Valid:    rep.Valid,
		In:       inPath,
		SHA256:   hexSha(in),
		Pages:    rep.Pages,
		Producer: rep.Producer,
		TSAURL:   s.TSAURL(),
		Signers:  rep.Signers,
		Errors:   rep.Errors,
		ByteSize: len(in),
	}
	// Only when the run has a CA of its own. A recipient's run does not, and
	// printing the local CA's fingerprint there would look like evidence of the
	// document's origin when it is evidence of nothing.
	if ca := s.CA(); ca != nil {
		report.CA = hexSha(ca.Cert.Raw)
	}
	// Loud where a person is watching, not only in the JSON: without an anchor
	// the verdict means "intact and self-consistent", not "signed by us", and
	// the difference is the whole point of running the tool.
	applyTrust(&report, s, src, true)
	if err := printReport(report); err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	if !rep.Valid {
		return 1
	}
	return 0
}

// selftestReport is the JSON the two commands print. The same shape for both
// so a script can read either with jq.
type selftestReport struct {
	Valid    bool   `json:"valid"`
	In       string `json:"in"`
	SHA256   string `json:"sha256"`
	Pages    int    `json:"pages"`
	Producer string `json:"producer"`
	// Omitted rather than printed empty when the run has no CA of its own,
	// which is the case for `checkpdf` with no config. An empty ca_sha256 next
	// to a line full of hashes reads as a check that failed.
	CA string `json:"ca_sha256,omitempty"`
	// Trust says whether this run had a trust anchor, because that decides what
	// `valid` means: "pinned" = every chain had to lead to a named CA, so the
	// verdict is evidence of who signed; "none" = a chain only had to hold
	// together, which says nothing about who ran the CA. A reader cannot infer
	// this from the rest of the JSON, so the report has to state it.
	Trust string `json:"trust"`
	// Anchor is the fingerprint of the certificate every signing certificate had
	// to have been issued by; AnchorSrc names where that certificate came from
	// (the file given with -pin, or the binary itself). Both are empty when
	// trust is "none". A reader comparing a PDF against a fingerprint published
	// on the signing service's own site needs the value, not just "pinned".
	Anchor    string               `json:"anchor_sha256,omitempty"`
	AnchorSrc string               `json:"anchor_source,omitempty"`
	TSAURL    string               `json:"tsa_url"`
	Signers   []signpdf.SignerInfo `json:"signers"`
	Errors    []string             `json:"errors,omitempty"`
	ByteSize  int                  `json:"bytes"`
	CertStart int                  `json:"certified_bytes,omitempty"`
}

func printReport(r selftestReport) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func hexSha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// selftestFont loads the handwriting font when it is available. Without a
// font the appearance falls back to a standard PDF font.
func selftestFont(cfg *Config) ([]byte, string) {
	for _, p := range []string{cfg.StorageDir + "/fonts/PatrickHand-Regular.ttf",
		"internal/signpdf/testdata/PatrickHand-Regular.ttf"} {
		data, err := os.ReadFile(p)
		if err == nil {
			return data, "signsrv-hand"
		}
	}
	return nil, ""
}
