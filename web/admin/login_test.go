package admin

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/web"
)

// The login page used to offer one credential pair — email and password — for
// everything. A machine client's key is a different credential that goes to a
// different endpoint, and typing it into the password box answered 401 with no
// hint of why. These assert the page now distinguishes the two.

func loginBody(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(web.SPA("admin"), "app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	return string(b)
}

// Both endpoints must be reachable from the page, and the key endpoint is the
// one a machine client needs.
func TestLoginUsesBothAuthEndpoints(t *testing.T) {
	b := loginBody(t)
	for _, path := range []string{"/auth/login", "/auth/token", "/auth/logout", "/auth/refresh"} {
		if !strings.Contains(b, "\""+path+"\"") {
			t.Fatalf("app.js never calls %s", path)
		}
	}
	if !strings.Contains(b, `key ? "/auth/token" : "/auth/login"`) {
		t.Fatal("app.js must pick the endpoint from the credential kind, not always /auth/login")
	}
}

// The key is shown as its real shape (db.go mints "key_" plus 32 hex bytes),
// so an operator who pastes a client id instead of the secret can see the
// difference rather than reading a bare "the key is not valid".
func TestLoginExplainsAWrongKey(t *testing.T) {
	b := loginBody(t)
	for _, want := range []string{
		"function loginHint",
		"key_[0-9a-f]{64}",
		"looks like a client id or name",
		"after key_ it is",
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("app.js has no %q; a rejected key needs to say which part is wrong", want)
		}
	}
}

// A client session holds envelope scopes only (admin.go grants exactly those),
// so the operator views must not be offered to it: they fetch /admin/* and
// answer 403. Both the nav and the route table have to know this.
func TestLoginHidesAdminViewsFromAClient(t *testing.T) {
	b := loginBody(t)
	if !strings.Contains(b, `sessionRole === "client"`) {
		t.Fatal("app.js never reads the role the login answered")
	}
	if !strings.Contains(b, `if (sessionRole !== "client") links.push(`) {
		t.Fatal("the nav offers every view to a client session")
	}
	for _, want := range []string{
		`{ path: "/admin/clients", view: showClients, admin: true }`,
		`{ path: "/admin/settings", view: showSettings, admin: true }`,
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("app.js is missing %q; without admin: true a client session can open the operator view", want)
		}
	}
	if !strings.Contains(b, "function routeAllows") {
		t.Fatal("app.js has no route gate")
	}
}

// A client dashboard is a different view from the operator dashboard: it reads
// /envelopes, which a client scope can answer, and never /admin/stats.
func TestClientDashboardReadsOnlyEnvelopeScopes(t *testing.T) {
	b := loginBody(t)
	if !strings.Contains(b, "async function showClientDashboard") {
		t.Fatal("app.js has no client dashboard")
	}
	// Cut the function out and check what it fetches.
	start := strings.Index(b, "async function showClientDashboard")
	if start < 0 {
		t.Fatal("showClientDashboard not found")
	}
	end := strings.Index(b[start:], "\n}")
	if end < 0 {
		t.Fatal("showClientDashboard does not close")
	}
	body := b[start : start+end]
	if strings.Contains(body, "/admin/") {
		t.Fatal("the client dashboard fetches an /admin/ path, which its scopes cannot read")
	}
	if !strings.Contains(body, `getJSON("/envelopes`) {
		t.Fatal("the client dashboard does not fetch /envelopes")
	}
}

// The login card shows one credential pair and hides the other, and that has to
// actually happen. app.js sets f.hidden, but a field is a <label class="field">
// and app.css declares .field { display: block }. The browser's own
// [hidden] { display: none } lives in the user-agent sheet, which every author
// rule outranks; and a plain [hidden] rule in this sheet has the same
// specificity as .field yet sits earlier in the file, so source order hands the
// win to .field. Either way the hidden attribute does nothing, and the operator
// who selected "Client key" was left staring at three boxes at once — email and
// password still on screen, which is exactly the confusion that was reported.
// The rule that makes it work needs !important, and app.js has to disable the
// unused pair as well as hide it, so a Tab cannot land in a box that is not in
// play and a stale value cannot be sent to the other endpoint.
func TestLoginHidesTheUnusedCredential(t *testing.T) {
	css := mustRead(t, "app.css")

	// The rule, not the prose: the comment above it quotes the user-agent's own
	// [hidden] { display: none }, so a plain substring search finds that first.
	// A rule starts a line.
	decl := regexp.MustCompile(`(?m)^\[hidden\]\s*\{([^}]*)\}`).FindStringSubmatch(css)
	if decl == nil {
		t.Fatal("app.css has no [hidden] rule, so app.js's f.hidden is a no-op against .field")
	}
	rule := decl[1]
	if !strings.Contains(rule, "display:") || !strings.Contains(rule, "none") {
		t.Fatalf("the [hidden] rule declares %q; it must set display:none", rule)
	}
	if !strings.Contains(rule, "!important") {
		t.Fatal("the [hidden] rule needs !important: .field { display: block } is later in " +
			"the sheet at the same specificity and otherwise wins, leaving hidden fields on screen")
	}

	js := loginBody(t)
	// The unused pair is hidden and disabled in both directions.
	for _, want := range []string{
		"f.hidden = key",
		"f3.hidden = !key",
		"email.disabled = key",
		"pw.disabled = key",
		"cred.disabled = !key",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js is missing %q; one credential pair has to be out of the layout "+
				"and out of the tab order while the other is in use", want)
		}
	}
}
