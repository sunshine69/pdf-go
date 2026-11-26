package admin

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/web"
)

// The rules of docs/steps/09-admin-ui.md that can be checked without a browser
// are asserted here, the same way web/spa asserts the signer app's rules. The
// admin app is the one that holds the operator's token, so the rules that
// matter most are the ones about where that token may live.

func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(web.SPA("admin"), name)
	if err != nil {
		t.Fatalf("read embedded %q: %v", name, err)
	}
	return string(b)
}

func TestAdminFilesExist(t *testing.T) {
	fsys := web.SPA("admin")
	if fsys == nil {
		t.Fatal("web.SPA(\"admin\") returned nil; the files are not embedded")
	}
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		if _, err := fs.ReadFile(fsys, name); err != nil {
			t.Fatalf("embedded file %q: %v", name, err)
		}
	}
}

// Acceptance 8: no external URL anywhere in the admin app. Every request the
// page makes is a relative path, so there is nowhere for a token to be sent.
func TestAdminNoExternalURLs(t *testing.T) {
	re := regexp.MustCompile(`https?://`)
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		b := mustRead(t, name)
		if re.MatchString(b) {
			t.Fatalf("%s contains an external http(s) URL", name)
		}
	}
}

// Acceptance 8: no innerHTML, no localStorage. The token is a variable in a
// closure, so a page reload loses it; nothing the server returns is ever
// parsed as markup.
func TestAdminAppJSConstraints(t *testing.T) {
	b := mustRead(t, "app.js")
	for _, banned := range []string{"innerHTML", "localStorage", "sessionStorage", "eval(", "document.cookie"} {
		if strings.Contains(b, banned) {
			t.Fatalf("app.js contains %q; it must not", banned)
		}
	}
}

func TestAdminAppJSUsesTextContent(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "textContent") {
		t.Fatal("app.js contains no textContent; server data is being injected as HTML")
	}
}

// index.html points at the embedded assets and loads no third-party script.
func TestAdminIndexPointsToAssets(t *testing.T) {
	b := mustRead(t, "index.html")
	for _, want := range []string{`href="/assets/admin/app.css"`, `src="/assets/admin/app.js"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("index.html does not contain %q", want)
		}
	}
	if strings.Contains(b, "<script src=\"http") {
		t.Fatal("index.html loads a script from outside the service")
	}
}

// The dashboard polls stats on a 30-second timer and stops when the tab is
// hidden: a hidden dashboard is not being read, and the poll is a query.
func TestAdminPollsStatsWithVisibilityCheck(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "30000") {
		t.Fatal("the dashboard does not poll on a 30-second timer")
	}
	if !strings.Contains(b, "visibilityState") {
		t.Fatal("the poll does not stop when the tab is hidden")
	}
}

// The 30s poll belongs to the dashboard alone. Every view tears down the page
// through shell()/clear(), so a tick that fires while some other view is on
// screen wipes that view and throws the operator back to the stats page — the
// envelope detail did exactly this a few seconds after "open". Two things keep
// that from happening: the timer callback checks it is still on the dashboard,
// and shell() disarms the timer on entry to any view.
func TestAdminPollStaysOnDashboard(t *testing.T) {
	b := mustRead(t, "app.js")
	// The callback is gated on the current view, not just tab visibility.
	if !regexp.MustCompile(`if \(view === "/" &&`).MatchString(b) {
		t.Fatal(`the poll does not check it is still on the dashboard before rebuilding the page`)
	}
	// shell() runs for every view and must disarm the timer, so a tick cannot
	// be left armed while the operator is on the detail page or a form.
	shell := regexp.MustCompile(`(?s)function shell\(title, path\) \{.*?\n\}`).FindString(b)
	if shell == "" {
		t.Fatal("cannot find shell() to check it disarms the poll")
	}
	if !strings.Contains(shell, "clearInterval(pollTimer)") {
		t.Fatal("shell() does not clear pollTimer, so a non-dashboard view can be wiped by a stray tick")
	}
}

// Every fetch carries same-origin credentials and the token in a header only.
func TestAdminFetchesUseSameOrigin(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, `"same-origin"`) {
		t.Fatal(`app.js fetches without credentials:"same-origin"`)
	}
	if !strings.Contains(b, "Bearer ") {
		t.Fatal("app.js does not send the access token as a bearer header")
	}
	if !strings.Contains(b, "20000") {
		t.Fatal("app.js has no 20-second timeout constant")
	}
}

// The machine client key appears once, in a <pre>, labelled as a one-time
// secret. A UI that re-renders the key from the list would leak it.
func TestAdminKeyShownOnce(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "This is the only time it is shown") {
		t.Fatal("the client key is not labelled as shown once")
	}
	if !strings.Contains(b, `el("pre"`) {
		t.Fatal("the client key is not rendered in a <pre>")
	}
}

// The actions the detail page must offer. Each is a call the operator makes
// from the envelope, not from a search box.
//
// There is no /remind here on purpose. It is the same call as /send now, and
// two buttons that mail the same people with the same links is how operators
// ended up guessing which one worked after a restart.
func TestAdminDetailActionsExist(t *testing.T) {
	b := mustRead(t, "app.js")
	for _, want := range []string{"/send", "/reissue", "/sign", "/cancel", "/audit.zip", "/document"} {
		if !strings.Contains(b, want) {
			t.Fatalf("app.js has no action for %s", want)
		}
	}
	if !strings.Contains(b, "/admin/settings") {
		t.Fatal("app.js has no settings page")
	}
	if !strings.Contains(b, "/admin/events") {
		t.Fatal("app.js does not show the audit log")
	}
}

// app.js body of one function, for asserting what a function does rather than
// what some other function with the same words in it does. The match stops at
// the first column-zero brace, which is the end of the body because every
// nested block in this file is indented.
func fnBody(t *testing.T, b, name string) string {
	t.Helper()
	fn := regexp.MustCompile(`(?s)function ` + name + `\(.*?\n\}`).FindString(b)
	if fn == "" {
		t.Fatalf("cannot find %s() in app.js", name)
	}
	return fn
}

// The three read links on the envelope page (/document, /report, /audit.zip)
// answer some seconds after the click, because the archive is assembled and the
// report re-verifies the signatures on demand. They did present an answer, but
// they presented it by splicing a fresh "Open/Save" row into the top of the
// page and removing nothing — so a click looked like it had done nothing, and
// had in fact added another row. Three clicks left three rows; clicking all
// morning left the page full of them, each pointing at a stale copy of the same
// file. The rules that keep it to one:
//
//   - the answer goes into a <dialog> opened with showModal(), so it lands in
//     front of the operator instead of above or below whatever they scrolled to;
//   - the open dialog is closed and removed before the next one is built, so
//     any number of clicks leaves exactly one thing on screen;
//   - the blob URL is revoked when the dialog goes, so replacing a dialog does
//     not keep every PDF and archive fetched this session in memory;
//   - the control reports that it is fetching, which is what a slow link needed
//     in the first place: a click that changes nothing looks like a link that
//     does nothing.
func TestAdminResultOpensOneDialog(t *testing.T) {
	b := mustRead(t, "app.js")

	dlg := fnBody(t, b, "showResultDialog")
	for _, want := range []string{`el("dialog"`, "showModal(", "closeResultDialog()", "resultDialog = dl"} {
		if !strings.Contains(dlg, want) {
			t.Fatalf("showResultDialog() does not contain %s", want)
		}
	}
	// The assignment is the registration: without it there is no open dialog
	// for the next click to find, closeResultDialog() closes nothing, and the
	// boxes stack two deep — which is the same bug with a nicer backdrop. It
	// was caught by clicking one link twice, not by reading the code.
	if strings.Index(dlg, "resultDialog = dl") > strings.Index(dlg, "showModal(") {
		t.Fatal("showResultDialog() opens the dialog before registering it, so its close listener cannot recognise it")
	}
	// Replaced, not stacked: the teardown has to run before the new dialog
	// exists, not after — a dialog opened on top of the last one is a wall of
	// dialogs, which is the bug in a slightly nicer costume.
	if strings.Index(dlg, "closeResultDialog()") > strings.Index(dlg, `el("dialog"`) {
		t.Fatal("showResultDialog() builds its dialog before closing the open one, so dialogs stack up")
	}

	drop := fnBody(t, b, "dropResultDialog")
	for _, want := range []string{"revokeObjectURL", ".remove()"} {
		if !strings.Contains(drop, want) {
			t.Fatalf("dropResultDialog() does not contain %s", want)
		}
	}

	// The answer must not also be spliced into the page: the dialog is the
	// single place it goes.
	if strings.Contains(b, "insertBefore(row") {
		t.Fatal(`app.js still splices a result row into the page, which is where the pile of buttons came from`)
	}

	link := fnBody(t, b, "apiLink")
	if !strings.Contains(link, "Fetching") {
		t.Fatal("a read link gives no sign it is fetching, so a slow answer reads as a dead link")
	}

	// Navigating away takes the dialog with it: it is modal, and a dialog over
	// a page that has been replaced describes an envelope the operator has left.
	if !strings.Contains(fnBody(t, b, "clear"), "closeResultDialog()") {
		t.Fatal("clear() leaves the result dialog open across a route change")
	}
}

// A cancel needs a reason, and the page says so instead of sending an empty
// body that the server would refuse.
func TestAdminCancelRequiresReason(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "reason") {
		t.Fatal("the cancel action does not collect a reason")
	}
}

func TestAdminCSSNoExternals(t *testing.T) {
	b := mustRead(t, "app.css")
	if strings.Contains(b, "@import") {
		t.Fatal("app.css contains an @import")
	}
	if regexp.MustCompile(`url\(["']?https?://`).MatchString(b) {
		t.Fatal("app.css references an external url()")
	}
}
