package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Chore endpoints. The verbs of `signsrv` that are not document work — is the
// database alive, what is the schema, run the sweep, verify the audit chain,
// write today's audit file, check the configuration, test the mail path — are
// also routes here, under the admin scope, answering the same JSON shape as
// every other endpoint.
//
// The reason is deployment shape: when the service runs on a server and the CLI
// runs on a desk, `signsrv dbstatus -config …` on the desk is meaningless — the
// database, the audit directory and the config file are on the server. One
// endpoint per chore means the desk can operate the server, and there is one
// way to do each thing rather than a local verb and a remote one.
//
// Each chore has a local verb as well, and both paths call the same function,
// so a runbook step works whichever side of the network you are on.
//
//	GET  /api/v1/admin/dbstatus
//	GET  /api/v1/admin/schema
//	POST /api/v1/admin/sweep
//	POST /api/v1/admin/audit/verify
//	POST /api/v1/admin/audit/write      {"day":"2026-11-07"}
//	GET  /api/v1/admin/configcheck
//	POST /api/v1/admin/mail-test        {"to":"someone@example.com"}
const (
	scopeAdminChores = "admin:read"
	maxChoreBody     = 1 << 14
)

// The two log levels the chore handlers use, named so the calls read as
// sentences. logJSON wants a slog.Level; these are that, spelled for the
// operator's question ("did this succeed?").
const (
	slogInfo  = slog.LevelInfo
	slogError = slog.LevelError
)

// handleDBStatus answers "is the store reachable, and how big is it".
//
// Every number is a count of rows, not a size estimate, because the operator's
// question is "is the pipeline moving": envelopes by status, parties waiting,
// mail queued. A single query per number keeps this cheap enough to poll.
func (s *server) handleDBStatus(w http.ResponseWriter, r *http.Request) {
	db := s.store.DB()
	if err := db.PingContext(r.Context()); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "db_unreachable",
			"the service cannot reach its database", err.Error())
		return
	}
	count := func(query string) (int64, error) {
		var n int64
		err := db.QueryRowContext(r.Context(), query).Scan(&n)
		return n, err
	}
	// one row per status, so an operator sees "12 delivered, 3 signed" and not
	// just a total.
	type statusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	var statuses []statusCount
	rows, err := db.QueryContext(r.Context(),
		"select status, count(*) from envelopes group by status order by status")
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the status counts failed", "")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sc statusCount
		if err := rows.Scan(&sc.Status, &sc.Count); err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "the status counts failed", "")
			return
		}
		statuses = append(statuses, sc)
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the status counts failed", "")
		return
	}

	envelopes, _ := count("select count(*) from envelopes")
	parties, _ := count("select count(*) from parties")
	pending, _ := count("select count(*) from parties where status in ('invited','claimed')")
	mailQueued, _ := count("select count(*) from mail_queue where sent_at is null")
	events, _ := count("select count(*) from events")
	clients, _ := count("select count(*) from clients where revoked_at is null")
	users, _ := count("select count(*) from users where revoked_at is null")
	// Revoked rows are counted separately and never dropped. A count of live
	// rows alone cannot tell an operator whether the revoked account they are
	// chasing is in the table at all.
	usersRevoked, _ := count("select count(*) from users where revoked_at is not null")

	if statuses == nil {
		// An empty list, not null. The answer is read by a desk and by a script
		// that walks the list, and both have to start with a nil check for no
		// reason.
		statuses = []statusCount{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"checked_at":      s.clockNow().UTC().Format(time.RFC3339),
		"db_path":         s.cfg.DBFile(),
		"db_mode":         fileModeOf(s.cfg.DBFile()),
		"schema":          schemaVersionOf(r, s),
		"envelopes":       envelopes,
		"by_status":       statuses,
		"parties":         parties,
		"parties_pending": pending,
		"mail_queued":     mailQueued,
		"events":          events,
		"clients_active":  clients,
		"users_active":    users,
		"users_revoked":   usersRevoked,
	})
}

// schemaVersionOf reads the stored schema version, best effort: a status page
// must not fail because a counter failed.
func schemaVersionOf(r *http.Request, s *server) int {
	v, err := signstore.SchemaVersion(r.Context(), s.store.DB())
	if err != nil {
		return -1
	}
	return v
}

// handleSchemaStatus reports the stored version against the version this binary
// wants, and the migrations it would apply. This is the "should I run migrate?"
// question, answerable from a desk.
func (s *server) handleSchemaStatus(w http.ResponseWriter, r *http.Request) {
	cur, err := signstore.SchemaVersion(r.Context(), s.store.DB())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the schema version could not be read", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        cur,
		"binary_version": signstore.CurrentVersion,
		"migration_open": cur < signstore.CurrentVersion,
		"pending":        signstore.PendingMigrations(cur),
	})
}

// handleSweep runs the expiry sweep and reports what it moved. The verb exists
// as a route because the sweep is the thing you run by hand when the worker was
// stopped for an hour, and by then you are usually not standing at the server.
func (s *server) handleSweep(w http.ResponseWriter, r *http.Request) {
	report, err := signstore.Sweep(r.Context(), s.store.DB())
	if err != nil {
		s.logJSON(slogError, "sweep", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the sweep failed", "")
		return
	}
	s.logJSON(slogInfo, "sweep", "report", report, "actor", actor(r),
		"request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, report)
}

// handleAuditVerify walks the audit files and checks the hash chain against the
// events table. A broken chain is reported as a 200 with ok:false, not as a 500:
// the request succeeded, and "the chain is broken" is a fact about the data, not
// a failure of the endpoint.
func (s *server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	n, err := signstore.AuditVerify(s.store.DB(), s.cfg.AuditDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"dir":    s.cfg.AuditDir,
			"reason": err.Error(),
			"hint":   "a broken chain means a file was edited, truncated, or reordered; treat it as tampering",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"dir":            s.cfg.AuditDir,
		"lines_verified": n,
	})
}

// handleAuditWrite writes one day's audit file. The day is optional and defaults
// to today, UTC; the shape of the value is the file name, so it is checked.
func (s *server) handleAuditWrite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Day string `json:"day"`
	}
	if !decodeJSON(w, r, &body, maxChoreBody) {
		return
	}
	day := strings.TrimSpace(body.Day)
	if day == "" {
		day = s.clock().UTC().Format(signstore.AuditDay)
	}
	if _, err := time.Parse(signstore.AuditDay, day); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_day", "day must be YYYY-MM-DD", "")
		return
	}
	n, err := signstore.AuditWrite(r.Context(), s.store.DB(), s.cfg.AuditDir, day)
	if err != nil {
		s.logJSON(slogError, "audit write", "error", err, "day", day, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the audit file could not be written", "")
		return
	}
	s.logJSON(slogInfo, "audit write", "day", day, "lines", n, "actor", actor(r),
		"request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{
		"day":   day,
		"lines": n,
		"path":  filepath.Join(s.cfg.AuditDir, day+".jsonl"),
		"note":  "the file is appended, not rewritten: re-running for a day already written adds nothing",
	})
}

// handleConfigCheck answers `signsrv checkconfig` over HTTP: the problems list,
// the warnings, and the redacted settings. No secret is in the answer — a
// secret's digest is, which is how you tell two deployments apart without
// reading either.
func (s *server) handleConfigCheck(w http.ResponseWriter, r *http.Request) {
	redacted := strings.Split(s.cfg.Redacted(), "\n")
	settings := make(map[string]string, len(redacted))
	for _, line := range redacted {
		if k, v, ok := strings.Cut(line, "="); ok {
			settings[k] = v
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		// A service that is running has passed its own check, so ok reflects
		// the problems list, which is the same list that would have stopped a
		// boot. It is here so a monitoring probe can compare two boxes.
		"ok":          len(s.cfg.Problems()) == 0,
		"problems":    s.cfg.Problems(),
		"warnings":    s.cfg.Warnings(),
		"settings":    settings,
		"audit_dir":   s.cfg.AuditDir,
		"storage_dir": s.cfg.StorageDir,
		"public_url":  s.cfg.PublicURL,
	})
}

// handleMailTest sends one test message through the configured transport.
//
// The address is required and validated, and the endpoint is inside the admin
// scope and the admin rate bucket: an operator checking a relay should not be
// able to send a thousand messages, and a leaked admin token must not turn the
// service into a spam relay.
func (s *server) handleMailTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		To string `json:"to"`
	}
	if !decodeJSON(w, r, &body, maxChoreBody) {
		return
	}
	to := strings.TrimSpace(body.To)
	if to == "" {
		writeProblem(w, http.StatusBadRequest, "missing_address", `the body needs {"to":"address@example.com"}`, "")
		return
	}
	result, err := runMailTest(s.cfg, to)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "mail_failed", err.Error(),
			"check smtp_host and smtp_port, or set dev=true to write the message to the outbox")
		return
	}
	s.logJSON(slogInfo, "mail test", "to", to, "actor", actor(r), "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, result)
}

// handleUsersList is the read side of the account table: who may sign API
// requests, and with which scopes.
//
// The secret is never in the answer. A list that carried the secrets would make
// one admin read a total compromise of every API caller, and there is no
// endpoint that needs them — verification reads the row itself.
func (s *server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.logJSON(slogError, "user list", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the accounts could not be read", "")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		out = append(out, map[string]any{
			"id":           u.ID,
			"username":     u.Username,
			"scopes":       signstore.ScopeList(u.Scopes),
			"role":         u.Role,
			"has_password": u.HasPassword,
			"has_secret":   u.HasSecret,
			"created_at":   u.CreatedAt,
			"last_login":   u.LastLogin,
			"revoked_at":   u.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "count": len(out)})
}

// handleUserRevoke closes an account over HTTP: both doors at once. The secret
// stays in the row (so the audit trail of what it signed stays verifiable), and
// every token naming it is refused from now on.
func (s *server) handleUserRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeProblem(w, http.StatusBadRequest, "invalid_user", "the user id must be a number", "")
		return
	}
	u, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "user_not_found", "there is no account with that id", "")
		return
	}
	if err := s.store.RevokeUser(r.Context(), id); err != nil {
		s.logJSON(slogError, "user revoke", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the account could not be revoked", "")
		return
	}
	if err := s.store.AddEvent(r.Context(), "", actor(r), "user_revoke",
		jsonPayload(map[string]any{"user_id": id, "username": u.Username})); err != nil {
		s.logJSON(slogError, "user revoke event", "error", err, "request", requestID(r.Context()))
	}
	s.logJSON(slogInfo, "user revoke", "user", id, "username", u.Username, "actor", actor(r),
		"request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id,
		"username":   u.Username,
		"revoked":    true,
		"rotated_at": time.Now().UTC().Format(time.RFC3339),
		"note":       "every token for this account is refused now; the web login is closed too",
	})
}

// jsonPayload is the small wrapper the event table wants. signflow has one; the
// admin package uses this so the chore handlers do not import the signing flow
// for a string.
func jsonPayload(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// fileModeOf reports the mode of the database file, as the octal string an
// operator wrote in the runbook. The secret is in this file, so the mode is part
// of the security posture, and "what is the mode?" should be answerable remotely.
func fileModeOf(path string) string {
	if path == "" {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return "0" + strconv.FormatInt(int64(st.Mode().Perm()), 8)
}
