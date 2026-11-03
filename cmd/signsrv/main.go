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

	if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "signsrv: unexpected argument %q\n\n", rest[0])
		usage()
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

  signsrv version

Configuration comes from the environment (SIGNSRV_ prefix) and, with
-config, from a file. The environment wins. See config.example.env.`)
}
