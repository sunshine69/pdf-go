package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sunshine69/pdf-go/internal/signpdf"
)

// signCmd is `signsrv sign NAME EMAIL IN [OUT]`: certify `IN` and add one
// approval signature for NAME/EMAIL. It is the CLI path for the same two calls
// the API uses, so a document can be signed from the command line with a
// named party, and the acceptance script can prove the chain works outside the
// test harness.
//
// The keystore passphrase comes from the config; the party key is generated
// for the call and dropped when the signature is written, exactly as in the
// service. Nothing is written to the database.
func signCmd(configPath, tsaOverride string, rest []string) int {
	if len(rest) < 3 {
		fmt.Fprintln(os.Stderr, "signsrv: sign takes NAME EMAIL IN [OUT]")
		return 2
	}
	name, email, inPath := rest[0], rest[1], rest[2]
	outPath := ""
	if len(rest) > 3 {
		outPath = rest[3]
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

	fontData, fontName := selftestFont(cfg)
	s, err := signpdf.NewService(signpdf.Config{
		KeystoreDir: cfg.Keystore,
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
		Reason:   "certified",
		Location: "signsrv",
		Contact:  cfg.MailFrom,
		TSAURL:   cfg.TSAURL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: certify: %v\n", err)
		return 1
	}

	out, err = s.SignParty(ctx, out.Data, signpdf.PartyOptions{
		Name:      name,
		Email:     email,
		Reason:    "signed",
		Signature: name,
		TSAURL:    cfg.TSAURL,
		Widget:    signpdf.Widget{Page: 1, Y: 60, W: 220, H: 30},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: sign: %v\n", err)
		return 1
	}

	rep, err := s.Verify(ctx, out.Data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: verify: %v\n", err)
		return 1
	}

	printReport(selftestReport{
		Valid:     rep.Valid,
		In:        inPath,
		SHA256:    hexSha(out.Data),
		Pages:     rep.Pages,
		CA:        hexSha(s.CA().Cert.Raw),
		TSAURL:    s.TSAURL(),
		Signers:   rep.Signers,
		Errors:    rep.Errors,
		ByteSize:  len(out.Data),
		CertStart: len(in),
	})

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
