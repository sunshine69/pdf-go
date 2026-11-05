package spa

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

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
