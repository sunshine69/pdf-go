package main

// The admin verb group. Every verb here is a question an operator asks of a
// running service — is the database alive, what is the schema, run the sweep,
// is the audit chain intact, is the configuration sound, does the mail path
// work — and every one of them is answered by a route on the service.
//
//		pdf-go admin dbstatus   --server https://srv --username ci
//		pdf-go admin sweep      --server https://srv --username ci
//		pdf-go admin audit-verify --server https://srv --username ci
//		pdf-go admin mail-test  --server https://srv --username ci --to ops@example.com
//
// The reason this is HTTP and not a local verb: the service runs on a server
// and the CLI runs on a desk. `signsrv dbstatus -config …` on the desk reads
// the desk's config and the desk's database, which is not the thing you are
// asking about. One endpoint per chore, and one verb per endpoint, so the
// runbook step is the same on both sides of the network.
//
// The credential is the same one the envelope verbs use: a username and the
// shared secret of its row, signed here in the process memory, or a client
// token exchanged at the token endpoint. Which one is in hand decides nothing
// about the answer — the service answers with the scopes its rows grant, so an
// account without admin:read gets a 403 here and a 403 on the admin app.

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sunshine69/pdf-go/internal/report"
)

// adminRoutes is the verb table: CLI name -> route, method, and the flag each
// verb needs beyond the shared set. It is a table because the list is the
// contract: one chore, one route, one verb, and `pdf-go admin help` prints
// exactly what is wired.
type adminRoute struct {
	verb   string
	method string
	path   string
	// bodyOf builds the request body for a POST, empty for a GET. The value
	// comes from one flag, so the table keeps the mapping visible.
	bodyOf func(*adminArgs) (string, error)
	// pathOf overrides the path when the verb carries an id.
	pathOf func(*adminArgs) (string, error)
	needs  string
	help   string
}

var adminRoutes = []adminRoute{
	{verb: "dbstatus", method: http.MethodGet, path: "/api/v1/admin/dbstatus",
		help: "row counts and reachability of the service's database"},
	{verb: "schema", method: http.MethodGet, path: "/api/v1/admin/schema",
		help: "stored schema version against the version this binary wants"},
	{verb: "config-check", method: http.MethodGet, path: "/api/v1/admin/configcheck",
		help: "the service's own config check: problems, warnings, redacted settings"},
	{verb: "sweep", method: http.MethodPost, path: "/api/v1/admin/sweep",
		help: "run the expiry sweep and report what it moved"},
	{verb: "audit-verify", method: http.MethodPost, path: "/api/v1/admin/audit/verify",
		help: "verify the hash chain of the audit files against the events table"},
	{verb: "audit-write", method: http.MethodPost, path: "/api/v1/admin/audit/write",
		bodyOf: func(a *adminArgs) (string, error) { return jsonString(map[string]any{"day": a.day}) },
		help:   "write one day's audit file (default today); -day YYYY-MM-DD"},
	{verb: "mail-test", method: http.MethodPost, path: "/api/v1/admin/mail-test",
		bodyOf: func(a *adminArgs) (string, error) { return jsonString(map[string]any{"to": a.to}) },
		needs:  "-to",
		help:   "send one test message through the service's mail transport; -to required"},
	{verb: "users", method: http.MethodGet, path: "/api/v1/admin/users",
		help: "list the accounts that may sign API requests (never their secrets)"},
	{verb: "revoke-user", method: http.MethodDelete,
		pathOf: func(a *adminArgs) (string, error) {
			if a.id == "" {
				return "", fmt.Errorf("revoke-user needs -id <user id>")
			}
			return "/api/v1/admin/users/" + url.PathEscape(a.id), nil
		},
		needs: "-id",
		help:  "close an account: both doors at once, web login and API tokens"},
}

// adminArgs is what one admin verb carries beyond the shared flags.
type adminArgs struct {
	day string
	to  string
	id  string
}

// adminCommand dispatches `pdf-go admin <verb> …`.
func adminCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "admin: needs a verb")
		adminUsage()
		return report.Usage
	}
	name, rest := args[0], args[1:]
	if name == "help" || name == "-h" || name == "--help" {
		adminUsage()
		return report.OK
	}
	for _, rt := range adminRoutes {
		if rt.verb != name {
			continue
		}
		return runAdminVerb(rt, rest)
	}
	fmt.Fprintf(os.Stderr, "admin: unknown verb %q\n\n", name)
	adminUsage()
	return report.Usage
}

// runAdminVerb runs one chore over HTTP: parse, resolve the credential, build
// the body, call, print. There is no local path here on purpose — a chore that
// can be answered locally is a chore about the wrong machine.
func runAdminVerb(rt adminRoute, args []string) int {
	fs := flag.NewFlagSet("admin "+rt.verb, flag.ContinueOnError)
	var ef envelopeFlags
	var a adminArgs
	ef.register(fs)
	fs.StringVar(&a.day, "day", "", "day to write, YYYY-MM-DD (audit-write)")
	fs.StringVar(&a.to, "to", "", "address to test the mail path with (mail-test)")
	fs.StringVar(&a.id, "id", "", "user id (revoke-user)")
	if err := fs.Parse(args); err != nil {
		return report.Usage
	}
	if err := ef.resolve(); err != nil {
		return fail(err, "admin "+rt.verb)
	}
	if rt.needs != "" {
		// A verb that needs a value and is not given one is a usage error, not
		// a request: sending {"to":""} would spend a rate-limit token to learn
		// what the CLI could have said for free.
		switch rt.needs {
		case "-to":
			if strings.TrimSpace(a.to) == "" {
				return fail(fmt.Errorf("mail-test needs -to <address>"), "admin "+rt.verb)
			}
		case "-id":
			if strings.TrimSpace(a.id) == "" {
				return fail(fmt.Errorf("revoke-user needs -id <user id>"), "admin "+rt.verb)
			}
		}
	}

	path := rt.path
	if rt.pathOf != nil {
		p, err := rt.pathOf(&a)
		if err != nil {
			return fail(err, "admin "+rt.verb)
		}
		path = p
	}

	var body string
	if rt.bodyOf != nil {
		b, err := rt.bodyOf(&a)
		if err != nil {
			return fail(err, "admin "+rt.verb)
		}
		body = b
	}

	code, out, err := ef.call(rt.method, path, strings.NewReader(body), jsonContentType)
	if err != nil {
		// The service's problem document is the answer the operator wants: the
		// code, the message, the hint. Print it as received, then the CLI's own
		// advice on the same subject.
		if len(out) > 0 && ef.jsonOut {
			var pretty map[string]any
			if json.Unmarshal(out, &pretty) == nil {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(pretty)
			} else {
				os.Stdout.Write(out)
			}
		}
		return adminFail(err, code, rt.verb)
	}
	if ef.jsonOut {
		// The service's own bytes, pretty-printed. Re-marshalling a map would
		// sort the keys and drop the order the service chose, and the order is
		// the reading order of the answer.
		var pretty map[string]any
		if json.Unmarshal(out, &pretty) == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(pretty)
		} else {
			os.Stdout.Write(out)
		}
	}
	if code >= 400 {
		return report.InputErr
	}
	return report.OK
}

// adminFail turns a refusal into an exit code and one line of advice. The
// service's document has already been printed; this adds the operator's next
// step, in the vocabulary of the local tools, which is the part a service
// cannot know.
func adminFail(err error, code int, verb string) int {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		// The two codes have one cause each: no row (or a revoked one), and a
		// row without the scope. The secret cannot tell them apart, so the hint
		// names both.
		return fail(fmt.Errorf("%w: the account needs the admin scope, and a revoked account has nothing: check `signsrv user list`", err), "admin "+verb)
	case http.StatusTooManyRequests:
		return fail(fmt.Errorf("%w: the service is rate limiting this endpoint", err), "admin "+verb)
	default:
		return fail(err, "admin "+verb)
	}
}

// jsonString encodes a body. An empty value is omitted rather than sent as an
// empty string: the service reads an empty day as "today" and an empty address
// as a missing address, and the CLI should not send a field it has no opinion
// about.
func jsonString(v map[string]any) (string, error) {
	for k, val := range v {
		if s, ok := val.(string); ok && s == "" {
			delete(v, k)
		}
	}
	if len(v) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

const jsonContentType = "application/json"

// adminUsage prints the verb table. The text comes from the table, so the help
// cannot drift from the routes.
func adminUsage() {
	fmt.Fprintln(os.Stderr, "usage: pdf-go admin <verb> [--server URL] [--username NAME --jwt-secret-env VAR]")
	fmt.Fprintln(os.Stderr, "       pdf-go admin <verb> [--server URL] --token-env TOKEN")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Every verb calls the service; none of them reads a local file.")
	fmt.Fprintln(os.Stderr, "Each needs the admin scope on the account in hand.")
	fmt.Fprintln(os.Stderr, "")
	for _, rt := range adminRoutes {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", rt.verb, rt.help)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Credential: --username plus the secret in JWT_SECRET (the CLI signs")
	fmt.Fprintln(os.Stderr, "the token, nothing leaves the machine), or a client token in TOKEN.")
}
