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

const version = "0.1.0"

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
	case "secrets":
		return secretsCmd(*configPath, rest)
	case "sign-selftest":
		return signSelftest(*configPath, *tsaOverride, rest)
	case "checkpdf":
		return checkPDF(*configPath, *tsaOverride, rest)
	case "sign":
		return signCmd(*configPath, *tsaOverride, rest)
	case "worker":
		return workerCmd(ctx, *configPath)
	case "mail-test":
		return mailTestCmd(*configPath, rest)
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
// same. Flags are any argument starting with '-' (and the value that
// follows -config when written as two arguments).
func splitArgs(args []string) (cmd string, flags, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if a == "-config" && i+1 < len(args) {
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

  signsrv dbstatus [-config FILE]
      Report the schema version and the row counts of every table.

  signsrv admin add EMAIL [-config FILE]
  signsrv admin list [-config FILE]
      Create an admin (the password is read from SIGNSRV_ADMIN_PASSWORD, or
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

  signsrv checkpdf FILE [-config FILE]
      Verify a document on disk and print the report. Exits non-zero when it
      is not valid.

  signsrv version

Configuration comes from the environment (SIGNSRV_ prefix) and, with
-config, from a file. The environment wins. See config.example.env.`)
}
