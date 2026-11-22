// Command signsrv is the PDF signing service: it fills and certifies a
// document, invites the parties by email with expiring single-use links,
// records their consents, signs the document in one batch once everyone has
// consented, verifies the result and delivers it to every party.
//
// It serves three faces from one process: the JSON API, the two embedded
// single-page apps (signers at /s/, admins at /admin/), and a background
// worker that drains the mail and signing queues and runs the sweeps.
//
// Run `signsrv help` for the command list and `signsrv checkconfig` to
// validate a configuration before starting the server.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const version = "0.0.1"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("signsrv", flag.ContinueOnError)
	fs.Usage = usage
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to a config file")
	// -tsa overrides the configured timestamp authority, so `sign-selftest`
	// can be pointed at a local TSA and at the "no TSA" case. It exists for
	// the acceptance script; a running service never uses it.
	tsaOverride := fs.String("tsa", "", "override tsa_url (sign-selftest)")
	// -pin is the trust anchor for `checkpdf` with no config file: a file
	// containing the instance CA in PEM. The released binary carries its own
	// (scripts/build-release.sh bakes it in), so a recipient does not need
	// this flag; it exists for an operator pointing the tool at another
	// instance's CA. No URL form on purpose: a verification must not need the
	// network, and fetching the anchor over HTTPS trusts the DNS anyway.
	pinPath := fs.String("pin", "", "path to a PEM certificate a chain must lead to (checkpdf)")
	fs.Usage = usage
	// Flags are accepted on either side of the subcommand: both
	// `signsrv -config f serve` and `signsrv serve -config f` work.
	cmd, flags, rest := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if cmd == "" {
		cmd = "serve"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Commands that take arguments of their own.
	switch cmd {
	case "admin":
		return adminCmd(ctx, *configPath, rest)
	case "client":
		return clientCmd(ctx, *configPath, rest)
	case "user":
		return userCmd(ctx, *configPath, rest)
	case "secrets":
		return secretsCmd(*configPath, rest)
	case "sign-selftest":
		return signSelftest(*configPath, *tsaOverride, rest)
	case "checkpdf":
		return checkPDF(*configPath, *tsaOverride, *pinPath, rest)
	case "sign":
		return signCmd(*configPath, *tsaOverride, rest)
	case "worker":
		return workerCmd(ctx, *configPath)
	case "batch":
		return batchCmd(ctx, *configPath, argAt(rest, 0))
	case "mail-test":
		return mailTestCmd(*configPath, rest)
	case "audit-verify":
		return auditCmd(ctx, *configPath, "audit-verify", rest)
	case "audit-write":
		return auditCmd(ctx, *configPath, "audit-write", rest)
	}
	if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "signsrv: unexpected argument %q\n\n", rest[0])
		usage()
		return 2
	}

	switch cmd {
	case "serve", "server", "":
		return serve(ctx, *configPath)
	case "version", "--version":
		fmt.Println("signsrv", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	case "checkconfig":
		return checkConfig(*configPath)
	case "migrate":
		return migrateCmd(ctx, *configPath)
	case "sweep":
		return sweepCmd(ctx, *configPath)
	case "dbstatus":
		return dbstatusCmd(ctx, *configPath)
	default:
		fmt.Fprintf(os.Stderr, "signsrv: unknown command %q\n\n", cmd)
		usage()
		return 2
	}
}

// splitArgs finds the subcommand and collects the flags on both sides of
// it, so `signsrv -config f serve` and `signsrv serve -config f` behave the
// same. Flags are any argument starting with '-', together with the value
// that follows a flag listed in valueFlags.
// argAt returns the i-th positional argument, or "" when there is none.
func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// valueFlags are the flags that take a value. splitArgs has to know them,
// because it separates flags from the subcommand and its arguments, and a
// value it does not recognize as belonging to a flag becomes a positional
// argument — `checkpdf -tsa URL file` would then look like two files.
var valueFlags = map[string]bool{"-config": true, "-tsa": true, "-pin": true}

func splitArgs(args []string) (cmd string, flags, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// A flag that takes a value has to carry it into the flag set,
			// and the value must not be read as a positional argument:
			// `checkpdf -tsa URL file` names one file, not two.
			if _, ok := valueFlags[a]; ok && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		if cmd == "" {
			cmd = a
			continue
		}
		rest = append(rest, a)
	}
	return cmd, flags, rest
}

func usage() {
	fmt.Println(`signsrv - PDF signing service ` + version + `

  signsrv serve [-config FILE]
      Run the API, the signing app, the admin app and the worker.

  signsrv checkconfig [-config FILE]
      Validate the effective configuration. Exits non-zero with every
      problem listed. Secrets are masked in the printed output.

  signsrv migrate [-config FILE]
      Apply the pending schema migrations, print the version reached, and run
      integrity_check. Running it again is a no-op.

  signsrv sweep [-config FILE]
      Run the sweeps by hand: expire the tokens and envelopes whose deadline
      has passed, delete the expired revocations, requeue the batch leases that
      were left over from a crash, and mark the failed batches.

  signsrv audit-verify [-config FILE]
      Walk the audit files in date order and check the hash chain: every line's
      hash matches its content, every prev_hash matches the line before it, and
      the event ids strictly increase. Prints the number of events verified, or
      the first break, and exits non-zero on a break.

  signsrv audit-write [-config FILE] [DAY]
      Append the events newer than the last written position to the audit file
      for DAY (default: today, YYYY-MM-DD). The nightly job in runbook.md.

  signsrv dbstatus [-config FILE]
      Report the schema version and the row counts of every table.

  signsrv admin add EMAIL [-config FILE]
  signsrv admin list [-config FILE]
      Create an admin (the password is read from ADMIN_PASSWORD, or
      from the terminal with the echo silenced) and list the admins.

  signsrv admin passwd EMAIL [-config FILE]
      Change an admin password. The change stamps the credential epoch, so
      access tokens minted under the old password stop working, and the
      refresh chain is deleted. This is the action to take when a token is
      stolen.

  signsrv client add NAME [SCOPES...] [-config FILE]
  signsrv client list [-config FILE]
  signsrv client revoke ID [-config FILE]
      Create a machine client. Prints the issued key once; the database keeps
      only its digest. Revoking a client ends its tokens.

  signsrv secrets init [-config FILE]
      Write the missing config secrets (keystore_pass, admin_password) into the
      config file, keeping the ones already set. Values are prompted
      with the keyboard echo silenced; the file ends up mode 0600.

  signsrv sign NAME EMAIL IN [OUT] [-config FILE]
      Certify IN and add one approval signature for NAME/EMAIL. Writes OUT
      (default: the report only). The party key is generated for the call and
      dropped; it is never written to disk. Prints the verification report.

  signsrv sign-selftest [IN [OUT]] [-config FILE] [-tsa URL]
      Certify, sign three test parties, verify. Exits 0 only when the finished
      document is valid. The acceptance harness for docs/steps/04-pdfsign.md.

  signsrv checkpdf FILE [-config FILE] [-pin FILE] [-tsa URL]
      Verify a document on disk and print the report. Exits non-zero when it
      is not valid. No config file is required: the certificate chain is read
      from the document, nothing is created on disk, and no network is used.

      The report says which trust rule was in force:
        "trust": "pinned"  a chain had to lead to a named CA, so the verdict
                           also says who signed the document
        "trust": "none"    no anchor was available, so the verdict says the
                           document is intact and the signatures hold together,
                           and nothing about who ran the CA

      The anchor comes from -pin FILE, or from the CA baked into a binary built
      by scripts/build-release.sh, or from the keystore when -config is given.
      Without one the run prints a warning on stderr.

  signsrv version

Configuration comes from the environment (the config key uppercased:
PUBLIC_URL, KEYSTORE_PASS, ADMIN_PASSWORD) and, with -config, from a file.
The environment wins. See config.example.env.`)
}
