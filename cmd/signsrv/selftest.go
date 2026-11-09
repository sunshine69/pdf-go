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
func checkPDF(configPath, tsaOverride string, rest []string) int {
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "signsrv: checkpdf takes exactly one FILE")
		return 2
	}
	inPath := rest[0]

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
		CA:       hexSha(s.CA().Cert.Raw),
		TSAURL:   s.TSAURL(),
		Signers:  rep.Signers,
		Errors:   rep.Errors,
		ByteSize: len(in),
	}
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
	Valid     bool                 `json:"valid"`
	In        string               `json:"in"`
	SHA256    string               `json:"sha256"`
	Pages     int                  `json:"pages"`
	Producer  string               `json:"producer"`
	CA        string               `json:"ca_sha256"`
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
