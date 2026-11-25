package spa

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/web"
)

// Every rule in docs/steps/08-spa.md that can be checked without a browser is
// asserted here. Acceptance 5 (manual browser walkthrough) is verified by the
// reviewer.

// The three files must exist in the embedded FS.
func TestEmbeddedFilesExist(t *testing.T) {
	fsys := web.SPA("spa")
	if fsys == nil {
		t.Fatal("web.SPA(\"spa\") returned nil; the files are not embedded")
	}
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		if _, err := fs.ReadFile(fsys, name); err != nil {
			t.Fatalf("embedded file %q: %v", name, err)
		}
	}
}

// Acceptance 2: script and link tags in index.html point to /assets/spa/.
func TestIndexPointsToAssets(t *testing.T) {
	b := mustRead(t, "index.html")
	for _, want := range []string{`href="/assets/spa/app.css"`, `src="/assets/spa/app.js"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("index.html does not contain %q", want)
		}
	}
}

// Acceptance 2: no external URL in any of the three files.
func TestNoExternalURLs(t *testing.T) {
	re := regexp.MustCompile(`https?://`)
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		b := mustRead(t, name)
		if re.MatchString(b) {
			t.Fatalf("%s contains an external http(s) URL", name)
		}
	}
}

// Acceptance 3 and 4: app.js contains no innerHTML, no localStorage, no eval.
func TestAppJSConstraints(t *testing.T) {
	b := mustRead(t, "app.js")
	for _, banned := range []string{"innerHTML", "localStorage", "eval", "sessionStorage"} {
		if strings.Contains(b, banned) {
			t.Fatalf("app.js contains %q; it must not", banned)
		}
	}
}

// Every DOM write uses textContent, never innerHTML. Assert that at least one
// assignment to textContent appears, proving the helper is actually used.
func TestAppJSUsesTextContent(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "textContent") {
		t.Fatal("app.js contains no textContent; server data is being injected as HTML")
	}
}

// The CSP must include every directive the spec names. Checked against the
// exported constant so the test and the server middleware cannot drift.
func TestCPSSignerDirectives(t *testing.T) {
	for _, d := range []string{
		"default-src 'self'", "script-src 'self'", "style-src 'self'",
		"frame-src 'self'", "connect-src 'self'",
		"img-src 'self' data:", "base-uri 'self'", "form-action 'self'",
	} {
		if !strings.Contains(web.CSPSigner, d) {
			t.Fatalf("CSPSigner missing %q", d)
		}
	}
}

// app.js must read the token from the path, not from storage.
func TestAppJSReadsTokenFromPath(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "location.pathname") {
		t.Fatal("app.js does not read the token from location.pathname")
	}
}

// app.js must use credentials:"same-origin" on its fetches.
func TestAppJSUsesSameOriginCredentials(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, `"same-origin"`) {
		t.Fatal(`app.js fetches without credentials:"same-origin"`)
	}
}

// app.js must have a 20-second timeout.
func TestAppJSTimeout(t *testing.T) {
	b := mustRead(t, "app.js")
	if !strings.Contains(b, "20000") {
		t.Fatal("app.js has no 20-second timeout constant")
	}
}

// app.js must handle all the status codes the spec lists.
func TestAppJSHandlesStatusCodes(t *testing.T) {
	b := mustRead(t, "app.js")
	for _, code := range []string{"401", "403", "409", "410", "429"} {
		if !strings.Contains(b, code) {
			t.Fatalf("app.js does not handle status %s", code)
		}
	}
}

// app.css has no external @import and no url() to an external resource.
// TestStampFitsMatchesServerRule runs the browser's stampFits under node and
// compares it with signpdf.StampText, case by case. The two must agree: the
// warning is shown from the JS copy and the decision is made by the Go copy, so
// a drift means a party is told the wrong thing about their own signature.
// Skipped where node is not installed, same as the pdftotext tests.
func TestStampFitsMatchesServerRule(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(mustRead(t, "app.js"))
	// The rule is two pieces: the character table and the function that reads
	// it. Both are extracted, so app.js may keep the table at top level where it
	// belongs -- but only if it stays a top-level const next to the function.
	m := regexp.MustCompile(`(?s)const STAMP_CP1252_EXTRA = new Set\(\[.*?\]\);`).FindString(src)
	if m == "" {
		t.Fatal("app.js has no const STAMP_CP1252_EXTRA = new Set([...]);")
	}
	fn := regexp.MustCompile(`(?s)function stampFits\(s\) \{.*?\n\}`).FindString(src)
	if fn == "" {
		t.Fatal("app.js has no function stampFits(s)")
	}
	m = m + "\n" + fn

	cases := []string{
		"Hai Kieu", "O'Brien & Co.", "  spaced  ", "a b", "~", " ",
		"Kiều", "André", "Đặng Văn Toàn", "Сигнатура", "合同", "😀",
		"a\nb", "a\tb", "\x01x", "©", "\u00a0nbsp", // U+00A0 is a WinAnsi byte
		"\x7f", // DEL: not printable, rejected on both sides
		// Cases that only agree if the cp1252 0x80-0x9F table is in sync:
		// curly quotes, the oe ligature, and a Vietnamese letter that has no
		// cp1252 code point at all.
		"\u201cAgree\u201d", "\u0152uvre \u0153il", "\u01a1n",
	}

	// The cases go over as JSON, not one per line: two of them contain a
	// newline and a tab, which is exactly what is being tested. The answer comes
	// back as one digit per case, in order.
	dir := t.TempDir()
	casesJSON, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	js := filepath.Join(dir, "run.js")
	body := m + "\n" +
		"const cases = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));\n" +
		"for (const c of cases) process.stdout.write((stampFits(c) ? 1 : 0) + '\\n');\n"
	if err := os.WriteFile(js, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(in, casesJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, js, in).Output()
	if err != nil {
		t.Fatalf("node: %v %s", err, out)
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(got) != len(cases) {
		t.Fatalf("node answered %d lines for %d cases", len(got), len(cases))
	}
	for i, c := range cases {
		want := signpdf.StampText(c) != ""
		if (got[i] == "1") != want {
			t.Errorf("case %q: js stampFits=%s, go StampText fits=%v (rules have drifted)",
				c, got[i], want)
		}
	}
}

func TestCSSNoExternals(t *testing.T) {
	b := mustRead(t, "app.css")
	if strings.Contains(b, "@import") {
		t.Fatal("app.css contains an @import")
	}
	if regexp.MustCompile(`url\(["']?https?://`).MatchString(b) {
		t.Fatal("app.css references an external url()")
	}
}

func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(web.SPA("spa"), name)
	if err != nil {
		t.Fatalf("read embedded %q: %v", name, err)
	}
	return string(b)
}
