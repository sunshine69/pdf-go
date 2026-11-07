//go:build e2e

// Step 13: the account table, the CLI that signs its own tokens, and the chore
// endpoints.
//
// The phase runs against the service the acceptance run already started, using
// the real binaries, and asserts the four properties the shape of step 13 stands
// on:
//
//   - a row's secret lets the CLI sign its own access token, with no token round
//     trip at all;
//   - the scopes of such a request come from the row, and the admin surface is
//     closed to a caller-minted token whatever the row's scopes column says;
//   - `signsrv user rotate` and `pdf-go admin revoke-user` close the door at the
//     next request, not at token expiry;
//   - every chore verb of `pdf-go admin` reaches the route it names, and the
//     service's answer is what the operator sees.
//
// The negative half of each rule is in negatives.go. The security property here
// is the second bullet: it is the one a refactor is most likely to lose, because
// it looks like a scope check that the row's scopes column ought to satisfy.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const dispatchUser = "e2e-dispatch"

// compactJSON removes the pretty-printing the CLI applies to the service's
// answer. A check that looks for a composite field like "ok":true has to compare
// against the compact form, because the writer puts a newline and two spaces
// between the key and the value.
func compactJSON(b []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return string(b)
	}
	return buf.String()
}

// userAccountsPhase is the step-13 phase of the acceptance run.
func userAccountsPhase() error {
	// 1. Mint an account. The local command is the only way a secret enters the
	// system, and it prints the secret once.
	out, err := run(root, bin("signsrv"), "user", "add", dispatchUser,
		"envelope:read", "envelope:write", "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("user add: %v\n%s", err, out)
	}
	evidence("user-add", out)
	secret := fieldFrom(out, "jwt_secret: ")
	userID := wordFrom(out, "user ")
	if secret == "" {
		return fmt.Errorf("user add printed no jwt_secret:\n%s", out)
	}
	if userID == "" {
		return fmt.Errorf("user add printed no user id:\n%s", out)
	}
	fmt.Printf("   account %s (id %s) created, secret shown once\n", dispatchUser, userID)

	// 1b. The admin scope cannot be granted to a row at all. The guard refuses a
	// caller-minted token on an admin route whatever the row says, so a scopes
	// column promising admin:read would be a lie — and the CLI refuses to write
	// the lie in the first place.
	out, err = run(root, bin("signsrv"), "user", "add", "e2e-wannabe", "admin:read", "-config", cfgPath)
	if err == nil {
		return fmt.Errorf("user add granted admin:read:\n%s", out)
	}
	if !strings.Contains(string(out), "admin:read cannot be granted") {
		return fmt.Errorf("user add with admin:read refused for the wrong reason:\n%s", out)
	}
	evidence("user-add-admin-refused", out)

	// 2. A document route answers a token the CLI signed itself. Nothing was
	// asked of the service first: the signature was checked against the row.
	code, body := cliRun(cliAs(dispatchUser, secret), "envelope", "get",
		"-insecure", envID)
	if code != 0 {
		return fmt.Errorf("envelope get with a self-minted token exited %d:\n%s", code, body)
	}
	if !strings.Contains(string(body), envID) {
		return fmt.Errorf("the answer does not name the envelope: %s", body)
	}
	evidence("user-token-document-route", body)

	// 2b. The same credential is refused on the admin surface, and the code says
	// why. A leaked dispatch secret is a document credential, not an
	// administrator, and the row's scopes column cannot change that.
	code, body = cliRun(cliAs(dispatchUser, secret), "admin", "dbstatus", "-insecure")
	if code == 0 {
		return fmt.Errorf("a self-minted token read the admin surface:\n%s", body)
	}
	if !strings.Contains(string(body), "insufficient_scope") {
		return fmt.Errorf("the admin surface refused a caller-minted token for the wrong reason (%d):\n%s", code, body)
	}
	evidence("user-token-admin-refused", body)

	// 3. Every chore verb, with a service-minted admin token. These are the
	// operator's questions, so the check is that the answer carries the fact
	// asked about, not that the status was 200.
	verbs := []struct {
		verb string
		args []string
		want []string
	}{
		{"dbstatus", nil, []string{`"envelopes"`, `"users_active"`, `"schema"`}},
		{"schema", nil, []string{`"version"`, `"migration_open"`, `"pending"`}},
		{"config-check", nil, []string{`"settings"`, `"warnings"`, `"audit_dir"`}},
		{"users", nil, []string{`"has_secret"`, `"scopes"`, dispatchUser}},
		{"sweep", nil, []string{`"envelopes_expired"`, `"mail_requeued"`}},
		// audit-write then audit-verify, in that order, and in one run: the
		// writer flushes on a schedule, so a verify of a live service reads a
		// log that is behind the table. The pair is the chore — flush, then
		// prove the chain — and asserting the chain is intact here is the point.
		{"audit-write", nil, []string{`"path"`, `"lines"`}},
		{"audit-verify", nil, []string{`"ok":true`, `"dir"`}},
	}
	for _, v := range verbs {
		args := append([]string{"admin", v.verb}, v.args...)
		code, body = cliRun(cliAsAdmin(), args...)
		if code != 0 {
			return fmt.Errorf("pdf-go admin %s exited %d:\n%s", v.verb, code, body)
		}
		for _, want := range v.want {
			if !strings.Contains(compactJSON(body), want) {
				return fmt.Errorf("admin %s answer has no %s:\n%s", v.verb, want, body)
			}
		}
		evidence("admin-"+v.verb, body)
	}
	fmt.Printf("   %d chore verbs answered with the fields asked for\n", len(verbs))

	// 3b. mail-test: the dev transport writes a .eml and the verb reports the
	// file. The count is measured before and after, so a "sent":true that wrote
	// nothing is a failure.
	before := countEML(filepath.Join(work, "outbox"))
	code, body = cliRun(cliAsAdmin(), "admin", "mail-test", "-to", "ops@e2e.test", "-insecure")
	if code != 0 {
		return fmt.Errorf("admin mail-test exited %d:\n%s", code, body)
	}
	for _, want := range []string{`"sent":true`, `"transport":"outbox"`} {
		if !strings.Contains(compactJSON(body), want) {
			return fmt.Errorf("admin mail-test answer has no %s:\n%s", want, body)
		}
	}
	if after := countEML(filepath.Join(work, "outbox")); after <= before {
		return fmt.Errorf("mail-test reported success and the outbox still holds %d messages", after)
	}
	evidence("admin-mail-test", body)

	// 3c. The list reports that a row has a secret and never the secret itself.
	code, body = cliRun(cliAsAdmin(), "admin", "users", "-insecure")
	if code != 0 {
		return fmt.Errorf("admin users exited %d:\n%s", code, body)
	}
	if strings.Contains(string(body), secret) {
		return fmt.Errorf("the users list carried the account's secret")
	}
	if strings.Contains(string(body), `"jwt_secret"`) {
		return fmt.Errorf("the users list has a jwt_secret field at all:\n%s", body)
	}

	// 4. Rotate. Every token signed with the old secret stops verifying at the
	// next request, which is the answer to a leaked secret.
	out, err = run(root, bin("signsrv"), "user", "rotate", dispatchUser, "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("user rotate: %v\n%s", err, out)
	}
	evidence("user-rotate", out)
	fresh := fieldFrom(out, "jwt_secret: ")
	if fresh == "" || fresh == secret {
		return fmt.Errorf("rotate printed no new secret:\n%s", out)
	}
	if code, body := cliRun(cliAs(dispatchUser, secret), "envelope", "get", "-insecure", envID); code == 0 {
		return fmt.Errorf("a token signed with the rotated-away secret still works:\n%s", body)
	}
	if code, body := cliRun(cliAs(dispatchUser, fresh), "envelope", "get", "-insecure", envID); code != 0 {
		return fmt.Errorf("the new secret does not sign a working token (%d):\n%s", code, body)
	}
	fmt.Printf("   rotate stopped the old secret at the next request\n")

	// 5. Revoke, from the desk: the CLI verb, over HTTP, no shell on the server.
	code, body = cliRun(cliAsAdmin(), "admin", "revoke-user", "-id", userID, "-insecure")
	if code != 0 {
		return fmt.Errorf("admin revoke-user exited %d:\n%s", code, body)
	}
	if !strings.Contains(compactJSON(body), `"revoked":true`) {
		return fmt.Errorf("revoke-user answer: %s", body)
	}
	evidence("admin-revoke-user", body)

	// The token minted a moment ago with the new secret is refused, and the code
	// names the revocation rather than a bad signature.
	code, body = cliRun(cliAs(dispatchUser, fresh), "envelope", "get", "-insecure", envID)
	if code == 0 {
		return fmt.Errorf("a revoked account still signs working tokens:\n%s", body)
	}
	if !strings.Contains(string(body), "token_revoked") {
		return fmt.Errorf("the refusal does not name the revocation (%d):\n%s", code, body)
	}
	evidence("user-token-after-revoke", body)

	// The row survives, stamped: the audit trail of what its secret signed stays
	// verifiable, and `user list` shows the stamp and not the secret.
	out, err = run(root, bin("signsrv"), "user", "list", "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("user list: %v\n%s", err, out)
	}
	line := lineFor(out, dispatchUser)
	if !strings.Contains(line, "revoked=2") {
		return fmt.Errorf("the row is not stamped as revoked: %q", line)
	}
	if strings.Contains(string(out), fresh) {
		return fmt.Errorf("user list printed a secret:\n%s", out)
	}
	evidence("user-list-after-revoke", out)

	// 6. The users table is in the row counts the operator reads, so the
	// dbstatus answer names the accounts this phase created. The check runs
	// here, at the end, because it is about the state the phase leaves behind:
	// one live row and one revoked one.
	code, body = cliRun(cliAsAdmin(), "admin", "dbstatus", "-insecure")
	if code != 0 {
		return fmt.Errorf("dbstatus after the step-13 set (%d):\n%s", code, body)
	}
	// The phase created exactly one account and revoked it, so the honest answer
	// is zero live and one revoked. Revocation is a state on a row, not a
	// deletion: the operator can see that the account they are chasing is still
	// in the table, which is the difference between "revoked" and "never existed".
	if !strings.Contains(compactJSON(body), `"users_active":0`) {
		return fmt.Errorf("the revoked account left a live row behind:\n%s", body)
	}
	if !strings.Contains(compactJSON(body), `"users_revoked":1`) {
		return fmt.Errorf("the revoked account is not counted in dbstatus:\n%s", body)
	}
	evidence("dbstatus-after-step13", body)
	fmt.Printf("   dbstatus shows the account as revoked, not as gone\n")
	return nil
}

// cliCredential is the CLI's view of who is calling: a username and a secret, or
// one service-minted token. Both go through the environment, which is the
// documented way and keeps them out of argv and out of the evidence files.
type cliCredential struct {
	env     map[string]string
	flags   []string
	pattern string
}

// cliAs is the self-minted credential: the username and the row's secret.
func cliAs(username, secret string) *cliCredential {
	return &cliCredential{
		env: map[string]string{
			"SIGNSRV_USERNAME":   username,
			"SIGNSRV_JWT_SECRET": secret,
			// The client key must not be visible: the CLI prefers a
			// self-minted token, and the run proves that by leaving the
			// exchange credential unset.
			"SIGNSRV_TOKEN": "",
		},
	}
}

// cliAsAdmin is the service-minted admin token, which is the only credential the
// chore routes accept.
// cliAsAdmin is the CLI carrying the run's admin access token, which is the
// shape a chore script uses: a token in the environment, no secret on disk. The
// token is sent as it is — the CLI reads SIGNSRV_TOKEN as a bearer token, not
// as a client key, and so one verb costs one request. That matters here: the
// run's rate buckets are shared, and a verb that exchanged a key each time would
// spend the budget of the phases that follow.
func cliAsAdmin() *cliCredential {
	return &cliCredential{
		env: map[string]string{
			"SIGNSRV_TOKEN":      adminTok,
			"SIGNSRV_USERNAME":   "",
			"SIGNSRV_JWT_SECRET": "",
		},
	}
}

// cliRun runs the CLI against this run's service. The server URL is appended
// last, after the flags, because the flag set of a subcommand stops at the first
// positional argument — so any positional the caller passes must come after it.
func cliRun(c *cliCredential, args ...string) (int, []byte) {
	full := append([]string{}, args...)
	full = insertServerFlag(full)
	out, err := runEnv(c.env, root, bin("pdf-go"), full...)
	if err == nil {
		return 0, out
	}
	if ee, ok := err.(interface{ ExitCode() int }); ok {
		return ee.ExitCode(), out
	}
	return -1, out
}

// insertServerFlag puts "-server <url>" in front of the first positional
// argument, which is the word after a known verb group. Go's flag package stops
// parsing at the first non-flag word, so passing the URL last would make it a
// positional and the call would fail with "needs --server".
// insertServerFlag puts the run's URL in front of the subcommand's own flags,
// and -insecure with it: the acceptance run's service is plain HTTP on
// loopback, and the CLI refuses to send a credential over plain HTTP unless it
// is told to.
func insertServerFlag(args []string) []string {
	args = append(append([]string{}, args...), "-insecure")
	skip := 0
	switch {
	case len(args) >= 2 && (args[0] == "envelope" || args[0] == "admin"):
		// Both groups are "verb group + subcommand", so the flags start at 2.
		skip = 2
	}
	out := append([]string{}, args[:skip]...)
	out = append(out, "-server", base)
	return append(out, args[skip:]...)
}

// fieldFrom returns the value after a prefix, on the line that starts with it.
// Both the CLI and the service print facts as "key: value" lines, so this is a
// prefix cut rather than a parse.
func fieldFrom(out []byte, prefix string) string {
	for _, l := range strings.Split(string(out), "\n") {
		if v := strings.TrimPrefix(l, prefix); v != l {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// wordFrom is fieldFrom cut at the first space: the "user 3 created: x" line.
func wordFrom(out []byte, prefix string) string {
	v := fieldFrom(out, prefix)
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		return v[:i]
	}
	return v
}

// lineFor is the row of a table that names a value.
func lineFor(out []byte, want string) string {
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, want) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// countEML counts the messages the dev transport wrote.
func countEML(dir string) int {
	fs, _ := os.ReadDir(dir)
	n := 0
	for _, f := range fs {
		if strings.HasSuffix(f.Name(), ".eml") {
			n++
		}
	}
	return n
}

// readLimit is io.ReadAll with a ceiling: a service answer that is enormous is
// not worth the memory of the harness.
func readLimit(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, 1<<20))
	return b
}

// negCallerMintedTokens is the negative half of step 13: the refusals, each with
// what it leaves behind.
func negCallerMintedTokens() error {
	// A token signed with a secret no row holds is refused as an invalid token.
	// The answer must not say whether the username exists: it is not this
	// endpoint's to say. A revoked account is the exception by design — the
	// holder of its secret is told the truth, because the truth is the thing
	// they need to know.
	code, body := cliRun(cliAs("e2e-nobody", "c2VjcmV0LXRoYXQtbm8tcm93LWhvbGRzLWF0LWFsbC0zMmJ5dGVz"),
		"envelope", "get", "-insecure", envID)
	if code == 0 {
		return fmt.Errorf("a token signed with a secret no row holds was accepted:\n%s", body)
	}
	for _, leak := range []string{"no such user", "not found", "unknown username"} {
		if strings.Contains(strings.ToLower(string(body)), leak) {
			return fmt.Errorf("the refusal leaks whether the username exists:\n%s", body)
		}
	}
	evidence("neg-unknown-secret", body)

	// A bearer token that is not a token at all.
	req, _ := http.NewRequest("GET", base+"/api/v1/admin/dbstatus", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	b := readLimit(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("a made-up bearer token got %s: %s", res.Status, b)
	}

	// The chore routes need a service-minted credential. The run's
	// envelope-scoped client key is refused on the admin surface.
	req, _ = http.NewRequest("GET", base+"/api/v1/admin/dbstatus", nil)
	req.Header.Set("Authorization", "Bearer "+clientAccess)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	b = readLimit(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		return fmt.Errorf("the envelope-scoped client key read the admin surface with %s: %s", res.Status, b)
	}

	// A day that is a path is refused: the audit directory is not a place a
	// request body can point at.
	code, body = cliRun(cliAsAdmin(), "admin", "audit-write", "-day", "../../etc/passwd", "-insecure")
	if code == 0 || !strings.Contains(string(body), "invalid_day") {
		return fmt.Errorf("audit-write accepted a path-shaped day (%d):\n%s", code, body)
	}

	// A mail-test with no address is refused before the network is touched: the
	// rate bucket of the endpoint is finite, and a typo should not spend it.
	code, body = cliRun(cliAsAdmin(), "admin", "mail-test", "-insecure")
	if code == 0 {
		return fmt.Errorf("mail-test with no address succeeded:\n%s", body)
	}
	if !strings.Contains(string(body), "needs -to") {
		return fmt.Errorf("mail-test with no address was not refused as a missing argument (%d):\n%s", code, body)
	}
	// The service refuses it too, for a caller that is not the CLI: the check
	// belongs to the endpoint, not to the flag parser.
	code, body = cliRun(cliAsAdmin(), "admin", "mail-test", "-to", "not an address", "-insecure")
	if code == 0 {
		return fmt.Errorf("mail-test accepted an address that is not one:\n%s", body)
	}
	return nil
}
