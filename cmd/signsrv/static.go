package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/sunshine69/pdf-go/web"
)

// srvStatic serves the embedded app for a site prefix. The prefix maps to
// the embedded directory: /s/ and /assets/spa/ serve web/spa, /admin/ and
// /assets/admin/ serve web/admin.
//
// A request for a file (a path whose last segment has an extension) serves
// that file. Any other request under a site prefix serves index.html, so the
// SPA can own its own routes. Paths are read through io/fs, which rejects
// ".." outright, so there is no traversal to guard against.
func srvStatic(w http.ResponseWriter, r *http.Request, prefix string) {
	dir, asset := siteFor(prefix)
	fsys := web.SPA(dir)
	if fsys == nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: apiProblem{
			Code: "not_found", Message: "this app is not built yet",
			Hint: "the app is embedded at build time from web/" + dir,
		}})
		return
	}

	name := staticName(r.URL.Path, prefix, asset)
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		if name != "index.html" {
			writeJSON(w, http.StatusNotFound, apiError{Error: apiProblem{
				Code: "not_found", Message: "no such file",
			}})
			return
		}
		writeJSON(w, http.StatusNotFound, apiError{Error: apiProblem{
			Code: "not_found", Message: "this app is not built yet",
			Hint: "web/" + dir + "/index.html is missing from the binary",
		}})
		return
	}

	// The assets are compiled into the binary, so a file's content changes only
	// when a new version is deployed. The ETag is a hash of those bytes: a phone
	// that cached an old app.js revalidates after a deploy and gets the new one
	// instead of running the previous build for the rest of its max-age.
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// An asset's own URL is unversioned, so a browser is allowed to reuse it,
	// but only after asking: must-revalidate plus the content ETag means a
	// refresh never runs a stale build, and an unchanged file costs a 304.
	// index.html carries the versioned references, and is never cached.
	switch {
	case strings.HasSuffix(name, ".html"):
		b = versionedHTML(fsys, asset, b)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	}
	// The HTML was rewritten above, so its ETag is the hash of what is sent.
	sum = sha256.Sum256(b)
	etag = `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// versionedHTML rewrites the asset references in an index.html so they carry a
// version taken from the asset bytes: /assets/spa/app.js becomes
// /assets/spa/app.js?v=<sha256 of that file>. A phone that cached the previous
// build cannot reuse it, because the URL it asks for no longer exists in its
// cache, so a deploy is visible on the next page load without a hard refresh.
//
// The rewrite happens at serve time, so the embedded files stay clean and the
// asset routes stay unversioned.
func versionedHTML(fsys fs.FS, asset string, html []byte) []byte {
	out := html
	for name, ref := range assetRefs(html) {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		v := hex.EncodeToString(sum[:8])
		out = bytes.ReplaceAll(out, []byte(`"`+ref+`"`), []byte(`"`+ref+"?v="+v+`"`))
	}
	return out
}

// assetRefs finds every asset reference in the HTML, keyed by the embedded
// file name it points at: "/assets/spa/app.js" maps to "app.js".
func assetRefs(html []byte) map[string]string {
	refs := map[string]string{}
	for _, ref := range assetRefRe.FindAllString(string(html), -1) {
		name := ref[strings.LastIndex(ref, "/")+1:]
		refs[name] = ref
	}
	return refs
}

var assetRefRe = regexp.MustCompile(`/assets/[a-z]+/[A-Za-z0-9_.\-]+\.(?:js|css)`)

// staticName maps a URL to the embedded file to serve.
func staticName(path, prefix, asset string) string {
	if sub, ok := strings.CutPrefix(path, asset+"/"); ok {
		return sub // /assets/spa/app.js -> app.js
	}
	sub, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return "index.html"
	}
	if sub == "" {
		return "index.html" // /admin/
	}
	if !strings.Contains(sub, ".") {
		return "index.html" // /s/<token>, /admin/envelopes: SPA routes
	}
	return sub
}

// siteFor maps a URL prefix to (embedded directory, asset prefix).
func siteFor(prefix string) (dir, asset string) {
	switch prefix {
	case "/admin/":
		return "admin", "/assets/admin"
	}
	return "spa", "/assets/spa"
}
