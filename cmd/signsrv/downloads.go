package main

// The verification tool a recipient is sent. The guide tells a non-technical
// reader to download one file and type one command, so the file has to come
// from somewhere that is not a developer's terminal. Serving it from the same
// host the document came from means the instruction is a single link, and the
// link can be checked against the address bar.
//
// Names are allowlisted, not patterned. The directory is operator-provided and
// the query string is caller-provided, so the set of things this handler will
// open is fixed in code; anything else is refused without touching the disk.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// downloadFiles are the artefacts published under /dl/. The name is both the
// URL segment and the filename on disk.
var downloadFiles = map[string]bool{
	"signsrv-linux-amd64":       true,
	"signsrv-windows-amd64.exe": true,
	"signsrv-checksums.txt":     true,
}

// handleDownload serves one of the allowlisted files from DownloadsDir.
func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.cfg.DownloadsDir == "" {
		writeProblem(w, http.StatusServiceUnavailable, "downloads_unavailable",
			"this instance does not offer downloads",
			"ask whoever sent you the document for the tool, or set downloads_dir in the config")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/dl/")
	if !downloadFiles[name] {
		writeProblem(w, http.StatusNotFound, "no_such_download",
			"unknown download", "the only published files are "+downloadList())
		return
	}
	full := filepath.Join(s.cfg.DownloadsDir, name)
	// The allowlist already blocks traversal; this makes the intent visible
	// rather than relying on Join swallowing "..".
	if filepath.Base(full) != name || !strings.HasPrefix(full, s.cfg.DownloadsDir) {
		writeProblem(w, http.StatusBadRequest, "bad_download", "malformed download request", "")
		return
	}
	http.ServeFile(w, r, full)
}

// handleDownloadManifest lists what is available and its digest, so a person
// who prefers to check before running has one request to make.
func (s *server) handleDownloadManifest(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.cfg.DownloadsDir == "" {
		writeProblem(w, http.StatusServiceUnavailable, "downloads_unavailable",
			"this instance does not offer downloads", "")
		return
	}
	type entry struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256,omitempty"`
		Size   int64  `json:"size,omitempty"`
		URL    string `json:"url"`
		Err    string `json:"error,omitempty"`
	}
	out := make([]entry, 0, len(downloadFiles))
	for _, name := range downloadNames() {
		e := entry{Name: name, URL: "/dl/" + name}
		b, err := os.ReadFile(filepath.Join(s.cfg.DownloadsDir, name))
		if err != nil {
			e.Err = "not published yet"
			out = append(out, e)
			continue
		}
		sum := sha256.Sum256(b)
		e.SHA256 = hex.EncodeToString(sum[:])
		e.Size = int64(len(b))
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

func downloadNames() []string {
	return []string{"signsrv-linux-amd64", "signsrv-windows-amd64.exe", "signsrv-checksums.txt"}
}

func downloadList() string {
	names := downloadNames()
	for i := range names {
		names[i] = "/dl/" + names[i]
	}
	return strings.Join(names, ", ")
}
