package main

import (
	"io/fs"
	"net/http"
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

	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

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
