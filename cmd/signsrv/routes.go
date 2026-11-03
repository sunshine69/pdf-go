package main

import (
	"log/slog"
	"net/http"
)

// routes wires every endpoint. Step 01 delivers /healthz and the static
// shells; the API endpoints of steps 05 to 10 are registered here as they
// are implemented.
func (s *server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Static faces. The apps are built in steps 08 and 09; the handlers
	// below serve whatever is embedded, so the routes never move again.
	s.mux.HandleFunc("GET /s/{token}", s.handleSignerShell)
	s.mux.HandleFunc("GET /assets/spa/{name}", func(w http.ResponseWriter, r *http.Request) {
		srvStatic(w, r, "/s/")
	})
	s.mux.HandleFunc("GET /admin/", s.handleAdminShell)
	s.mux.HandleFunc("GET /admin/{name}", func(w http.ResponseWriter, r *http.Request) {
		srvStatic(w, r, "/admin/")
	})
	s.mux.HandleFunc("GET /assets/admin/{name}", func(w http.ResponseWriter, r *http.Request) {
		srvStatic(w, r, "/admin/")
	})

	s.mux.HandleFunc("/", s.handleUnknown)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version,
		"request": requestID(r.Context()),
	})
}

// handleSignerShell serves the signing app. The token is not read here: the
// app reads it from the path and the API validates it. Nothing about the
// token is logged, and nothing about the envelope is revealed before claim.
func (s *server) handleSignerShell(w http.ResponseWriter, r *http.Request) {
	s.log.Info("signer shell", "request", requestID(r.Context()),
		"token", "[token:hidden]")
	srvStatic(w, r, "/s/")
}

func (s *server) handleAdminShell(w http.ResponseWriter, r *http.Request) {
	srvStatic(w, r, "/admin/")
}

func (s *server) handleUnknown(w http.ResponseWriter, r *http.Request) {
	s.logJSON(slog.LevelWarn, "route not found", "path", r.URL.Path,
		"request", requestID(r.Context()))
	writeJSON(w, http.StatusNotFound, apiError{
		Error: apiProblem{Code: "not_found", Message: "no such endpoint"},
	})
}

type apiError struct {
	Error apiProblem `json:"error"`
}

type apiProblem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}
