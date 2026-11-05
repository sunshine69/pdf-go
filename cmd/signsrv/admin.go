package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The admin endpoints of step 09. The rules that decide what an admin is
// allowed to do — the state transitions, the token invalidation, the audit
// event, the mail queue — live in internal/signflow/admin.go. This file owns
// the HTTP shape only: the scope guard, the query parameters, the problem
// mapping, and the actor.

// actor returns the subject of the calling admin. The handler is always behind
// RequireAdmin, so the claims are present; "unknown" is a defensive default
// that should never be written to an audit row.
func actor(r *http.Request) string {
	if c := signauth.ClaimsFrom(r.Context()); c != nil {
		return c.Subject
	}
	return "unknown"
}

// ---------------- events ----------------

// handleAdminEvents is the audit log of one envelope, newest first, paged at
// 100 rows. The envelope parameter is required: the log is always read in the
// context of a request, and a global log across envelopes has no meaning for
// an operator investigating one.
// handleAdminEvents is the audit log: newest first, one page at a time,
// filtered by envelope when the operator wants one envelope's story and
// unfiltered when they want everything. An envelope id that matches nothing
// answers an empty log rather than an error: a typo in an id is not a bad
// request, and the empty answer plus the total tells the operator which it
// was. The paging parameters are the part that must be exact.
func (s *server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	envelopeID := r.URL.Query().Get("envelope")
	// A paging parameter that is not a number is a client bug: answering a
	// wrong offset with page one would hide it. limit and offset are both
	// checked, so a typo shows up as 400 naming the parameter.
	limitText := r.URL.Query().Get("limit")
	limit := 100
	if limitText != "" {
		n, err := strconv.Atoi(limitText)
		if err != nil || n < 1 || n > 1000 {
			writeProblem(w, http.StatusBadRequest, "invalid_limit",
				"limit must be a number between 1 and 1000", "e.g. ?limit=100")
			return
		}
		limit = n
	}
	offsetText := r.URL.Query().Get("offset")
	offset := 0
	if offsetText != "" {
		n, err := strconv.Atoi(offsetText)
		if err != nil || n < 0 {
			writeProblem(w, http.StatusBadRequest, "invalid_offset",
				"offset must be a number of zero or more", "e.g. ?offset=100")
			return
		}
		offset = n
	}
	// The paging happens in the query: the audit log is unbounded and an
	// operator reads it newest-first, page by page. Reversing a whole log in
	// memory to serve one page is the kind of shortcut that works until the
	// log is large.
	page, total, err := s.store.ListRecentEvents(r.Context(), envelopeID, limit, offset)
	if err != nil {
		s.logJSON(slog.LevelError, "admin events", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the events read failed", "")
		return
	}

	type row struct {
		ID        int64           `json:"id"`
		Actor     string          `json:"actor"`
		Kind      string          `json:"kind"`
		Payload   json.RawMessage `json:"payload"`
		CreatedAt string          `json:"created_at"`
	}
	rows := make([]row, 0, len(page))
	for _, e := range page {
		rows = append(rows, row{
			ID: e.ID, Actor: e.Actor, Kind: e.Kind,
			Payload: payloadOr(e.Payload), CreatedAt: e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"envelope": envelopeID, "events": rows, "count": len(rows),
		"total": total, "offset": offset, "limit": limit,
	})
}

// payloadOr keeps the payload JSON as JSON. An event whose payload is not
// valid JSON (which should never happen — the writers all use PayloadJSON) is
// wrapped so the API's answer stays parsable.
func payloadOr(s string) json.RawMessage {
	if s == "" {
		return json.RawMessage(`{}`)
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

// ---------------- settings ----------------

// handleSettingsGet answers the settings page. The values are the running
// configuration — what the process would use on the next send — not a dump of
// whichever settings rows happen to exist.
func (s *server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"settings": s.settingsAnswer(r)})
}

// handleSettingsPost accepts the whitelisted keys only. An unknown key is a
// 400 that names the key, and nothing is written — the whole request is
// refused before the first write. A change writes one audit event naming the
// keys that changed, with the actor.
func (s *server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	var body map[string]json.RawMessage
	if !decodeJSON(w, r, &body, 1<<16) {
		return
	}
	changes := map[string]string{}
	for k, raw := range body {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_settings",
				"the value of "+k+" must be a string", "")
			return
		}
		changes[k] = v
	}
	changed, err := s.flowDeps().WriteSettings(r.Context(), changes, actor(r))
	if err != nil {
		var verr *signflow.ErrValidation
		if signflow.AsValidation(err, &verr) {
			writeProblem(w, http.StatusBadRequest, "invalid_settings", err.Error(),
				"only tsa_url, link_ttl, mail_from, smtp_host may be set here")
			return
		}
		s.logJSON(slog.LevelError, "settings write", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the settings write failed", "")
		return
	}
	s.logJSON(slog.LevelInfo, "settings write", "actor", actor(r),
		"keys", strings.Join(keysSorted(changed), ","), "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"changed": changed})
}

// keysSorted lists the settings a write actually changed, for the log line.
func keysSorted(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// handleSettingsPatch is the settings page's write. It shares the whitelist and
// the validation with the POST handler, but it answers 422 with the offending
// field named, because a page that edits four fields needs to know which one
// it got wrong.
func (s *server) handleSettingsPatch(w http.ResponseWriter, r *http.Request) {
	changes, ok := settingsBody(w, r)
	if !ok {
		return
	}
	if len(changes) == 0 {
		writeProblem(w, http.StatusUnprocessableEntity, "invalid_settings",
			"no settings were given", "send at least one of tsa_url, link_ttl, mail_from, smtp_host")
		return
	}
	changed, err := s.settingsWithValidation(w, r, changes)
	if err != nil {
		return // the problem is already written
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": s.settingsAnswer(r), "changed": changed,
	})
}

// settingsBody decodes a flat object of string values. A value that is not a
// string is a 400 naming the key: a settings document is text, and a number or
// an object there is a client bug, not something to coerce.
func settingsBody(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	var body map[string]json.RawMessage
	if !decodeJSON(w, r, &body, 1<<16) {
		return nil, false
	}
	changes := map[string]string{}
	for k, raw := range body {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_settings",
				"the value of "+k+" must be a string", "")
			return nil, false
		}
		changes[k] = v
	}
	return changes, true
}

// settingsWithValidation applies the changes and maps a whitelist or format
// failure to a 422 that names the field.
func (s *server) settingsWithValidation(w http.ResponseWriter, r *http.Request,
	changes map[string]string) (map[string]string, error) {
	changed, err := s.flowDeps().WriteSettings(r.Context(), changes, actor(r))
	if err != nil {
		var verr *signflow.ErrValidation
		if signflow.AsValidation(err, &verr) {
			writeProblem(w, http.StatusUnprocessableEntity, "invalid_settings",
				verr.Error(), verr.Hint)
			return nil, err
		}
		s.logJSON(slog.LevelError, "settings write", "error", err,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the settings write failed", "")
		return nil, err
	}
	s.logJSON(slog.LevelInfo, "settings write", "actor", actor(r),
		"keys", strings.Join(keysSorted(changed), ","), "request", requestID(r.Context()))
	return changed, nil
}

// settingsAnswer is the settings document the page reads back after a write, so
// the page never has to guess what the stored values became. A key nobody has
// set is answered with the value the process is actually using — the settings
// page must show the running configuration, not a list of rows that happen to
// exist. Otherwise a patch of one key would appear to blank the other three.
func (s *server) settingsAnswer(r *http.Request) map[string]string {
	settings := map[string]string{
		"tsa_url":   s.cfg.TSAURL,
		"link_ttl":  s.cfg.LinkTTL.String(),
		"mail_from": s.cfg.MailFrom,
		"smtp_host": s.cfg.SMTPHost,
	}
	stored, err := s.flowDeps().Settings(r.Context())
	if err != nil {
		return settings
	}
	for k, v := range stored {
		if v != "" {
			settings[k] = v
		}
	}
	return settings
}

// handleClientsList is the operator's list of machine clients. The key hash is
// not in it: the key exists only in the one response that created the client.
func (s *server) handleClientsList(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.logJSON(slog.LevelError, "clients list", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the clients read failed", "")
		return
	}
	out := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if c.RevokedAt != "" {
			continue
		}
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scopes": scopesOf(c.Scopes),
			"created_at": c.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func scopesOf(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------- envelope actions ----------------

// handleEnvelopeSend, handleEnvelopeRemind, handleEnvelopeCancel and
// handleEnvelopeReissue sit on the envelope id and share one rule: the state
// machine decides what is allowed, and the handler only maps the error to a
// status. Cancel is the one that requires a body.

func (s *server) handleEnvelopeRemind(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deps := s.flowDeps()
	n, err := deps.Remind(r.Context(), id, actor(r))
	if err != nil {
		s.actionProblem(w, r, err, "remind", id)
		return
	}
	s.logJSON(slog.LevelInfo, "envelope remind", "envelope", id, "parties", n,
		"actor", actor(r), "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"envelope": id, "reminded": n})
}

func (s *server) handleEnvelopeCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &body, 1<<16) {
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeProblem(w, http.StatusUnprocessableEntity, "invalid_reason",
			"a cancel requires a reason", `{"reason":"the contract was withdrawn"}`)
		return
	}
	deps := s.flowDeps()
	res, err := deps.Cancel(r.Context(), id, actor(r), strings.TrimSpace(body.Reason))
	if err != nil {
		s.actionProblem(w, r, err, "cancel", id)
		return
	}
	s.logJSON(slog.LevelInfo, "envelope cancel", "envelope", id,
		"actor", actor(r), "notified", len(res.Notified), "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"envelope": id, "status": "cancelled",
		"notified": res.Notified})
}

func (s *server) handleEnvelopeReissue(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deps := s.flowDeps()
	res, err := deps.Reissue(r.Context(), id, actor(r))
	if err != nil {
		s.actionProblem(w, r, err, "reissue", id)
		return
	}
	s.logJSON(slog.LevelInfo, "envelope reissue", "envelope", id,
		"parties", len(res.Reissued), "actor", actor(r), "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"envelope": id, "reissued": res.Reissued})
}

// handleEnvelopeSign triggers the signing batch. From collecting it requires
// every party to be consented (otherwise 409); from signed it re-enqueues an
// idempotent batch. The trigger enqueues the batch row the worker of step 10
// drains; the batch itself is idempotent, so re-triggering a signed envelope
// is a repair, not a second signing.
func (s *server) handleEnvelopeSign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	env, err := s.store.GetEnvelope(r.Context(), id)
	if err != nil {
		s.actionProblem(w, r, err, "sign", id)
		return
	}
	switch env.Status {
	case signstore.StatusCollecting:
		total, consented, declined, err := s.store.CountPartiesByStatus(r.Context(), id)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "the parties read failed", "")
			return
		}
		if declined > 0 {
			writeProblem(w, http.StatusConflict, "envelope_failed",
				"a party declined: the request is closed", "")
			return
		}
		if consented < total {
			writeProblem(w, http.StatusConflict, "party_not_consented",
				"sign requires every party to have consented",
				"consented "+strconv.Itoa(consented)+" of "+strconv.Itoa(total))
			return
		}
	case signstore.StatusSigned:
		// Re-trigger: the batch is idempotent, so this is the operator's repair
		// for a batch that died mid-run.
	default:
		writeProblem(w, http.StatusConflict, "state_conflict",
			"sign is allowed from collecting or signed", "status is "+string(env.Status))
		return
	}
	if err := s.store.EnqueueBatch(r.Context(), id, formatStamp(s.clockNow())); err != nil {
		s.logJSON(slog.LevelError, "batch enqueue", "error", err, "envelope", id,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the batch could not be queued", "")
		return
	}
	// The batch is run here, in the request. The queue row is written first so
	// that a crash between the claim and the signing leaves a row the worker
	// can pick up: the operator's "sign now" is an explicit action and the
	// answer should say what the document became. A batch row another process
	// has already claimed is a no-op here and the worker finishes it.
	deps := s.flowDeps()
	deps.Log = s.log
	out, err := deps.RunBatchFor(r.Context(), id, batchLease)
	if err != nil {
		s.logJSON(slog.LevelError, "batch run", "error", err, "envelope", id,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusConflict, "batch_failed",
			"the signing batch could not produce a valid document", err.Error())
		return
	}
	env, err = s.store.GetEnvelope(r.Context(), id)
	if err != nil {
		s.logJSON(slog.LevelError, "batch status read", "error", err, "envelope", id)
		writeProblem(w, http.StatusInternalServerError, "internal", "the envelope read failed", "")
		return
	}
	valid := out != nil && out.Report != nil && out.Report.Valid
	s.logJSON(slog.LevelInfo, "batch run", "envelope", id, "actor", actor(r),
		"signed", signedOf(out), "status", env.Status, "valid", valid,
		"request", requestID(r.Context()))
	answer := map[string]any{
		"envelope": map[string]any{"id": id, "status": env.Status,
			"current_sha": env.CurrentSHA},
		"status": env.Status, "signed": signedOf(out),
		"verified": valid, "batch": out != nil,
		"final_sha": out.Final,
	}
	if out.Report != nil {
		answer["report"] = reportPayload(out.Report)
	}
	writeJSON(w, http.StatusOK, answer)
}

// handleEnvelopeReport answers whether the document the envelope holds right
// now is intact. It reads the stored bytes and runs them through the same
// verifier the batch ran, so a report taken after the fact proves the same
// thing the batch claimed at signing time — and, if the file was changed
// since, it says so.
func (s *server) handleEnvelopeReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	env, err := s.store.GetEnvelope(r.Context(), id)
	if err == signstore.ErrNotFound {
		writeProblem(w, http.StatusNotFound, "not_found", "no envelope with this id", "")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the envelope read failed", "")
		return
	}
	if env.CurrentSHA == "" {
		// Nothing has been signed yet: the report exists, and its answer is
		// that the document is unsigned.
		writeJSON(w, http.StatusOK, map[string]any{
			"envelope": id, "status": env.Status, "sha256": "",
			"report": reportPayload(nil),
		})
		return
	}
	data, err := s.store.GetPDF(env.CurrentSHA)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found",
			"the document this envelope points at is not in the store", "")
		return
	}
	report, err := signService(s.cfg, s.log).Verify(r.Context(), data)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal",
			"the document could not be verified", err.Error())
		return
	}
	// The document-level report is not the whole answer an operator needs: a
	// document can verify perfectly and still be waiting for signatures. The
	// party signatures present, and the number of parties the envelope names,
	// say which of the two it is.
	revs, err := s.store.ListRevisions(r.Context(), id)
	if err != nil {
		s.logJSON(slog.LevelError, "report revisions", "error", err, "envelope", id)
		writeProblem(w, http.StatusInternalServerError, "internal", "the revision chain read failed", "")
		return
	}
	present := 0
	for _, rev := range revs {
		if rev.Kind == signflow.KindSign || strings.HasPrefix(rev.Kind, signstore.KindSignedPref) {
			present++
		}
	}

	parties, _, _, err := s.store.CountPartiesByStatus(r.Context(), id)
	if err != nil {
		s.logJSON(slog.LevelError, "report parties", "error", err, "envelope", id)
		writeProblem(w, http.StatusInternalServerError, "internal", "the parties read failed", "")
		return
	}
	s.logJSON(slog.LevelInfo, "report read", "envelope", id, "actor", actor(r),
		"valid", report.Valid, "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{
		"envelope": id, "status": env.Status, "sha256": env.CurrentSHA,
		"report":         reportPayload(report),
		"signed_parties": present, "required_parties": parties,
		"complete": present >= parties,
	})
}

// reportPayload is the verification report in API shape: valid, the signers
// with the certificate facts, and the reasons a document is not valid.
func reportPayload(r *signpdf.Report) map[string]any {
	if r == nil {
		return map[string]any{"valid": false, "signers": []any{},
			"errors": []string{"the document was not signed"}}
	}
	signers := make([]map[string]any, 0, len(r.Signers))
	for _, s := range r.Signers {
		signers = append(signers, map[string]any{
			"name": s.Name, "email": s.Email, "reason": s.Reason,
			"time": s.Time.UTC().Format(time.RFC3339), "serial": s.Serial,
			"valid": s.Valid, "trusted": s.Trusted, "revoked": s.Revoked,
			"timestamped": s.Timestamp,
		})
	}
	errors := r.Errors
	if errors == nil {
		errors = []string{}
	}
	return map[string]any{"valid": r.Valid, "signers": signers,
		"errors": errors, "pages": r.Pages, "producer": r.Producer}
}

func signedOf(out *signflow.BatchOutcome) int {
	if out == nil {
		return 0
	}
	return out.Signed
}

// handleEnvelopeAuditZip streams audit.zip. Generated on demand, never written
// to disk: the handler takes the bytes from the flow and writes them straight
// out with the envelope id as the download name.
func (s *server) handleEnvelopeAuditZip(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetEnvelope(r.Context(), id); err != nil {
		s.actionProblem(w, r, err, "audit zip", id)
		return
	}
	data, err := s.flowDeps().AuditZip(r.Context(), id)
	if err != nil {
		s.logJSON(slog.LevelError, "audit zip", "error", err, "envelope", id,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the archive could not be built", "")
		return
	}
	s.logJSON(slog.LevelInfo, "audit zip", "envelope", id, "bytes", len(data),
		"actor", actor(r), "request", requestID(r.Context()))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`-audit.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// actionProblem maps the flow's errors to statuses. Not-found is a 404, a
// state conflict is a 409 (cancel on delivered, remind on draft), a missing
// reason is a 400, a validation error is a 400 naming the field. Everything
// else is an internal error, logged with the envelope and the request id.
func (s *server) actionProblem(w http.ResponseWriter, r *http.Request, err error, what, envelopeID string) {
	var v *signflow.ErrValidation
	switch {
	case err == nil:
		return
	case errors.Is(err, signstore.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not_found", "no such envelope", "")
	case signflow.IsConflict(err):
		writeProblem(w, http.StatusConflict, "state_conflict",
			what+" is not allowed from the envelope's current state", err.Error())
	case errors.Is(err, signflow.ErrNoReason):
		writeProblem(w, http.StatusUnprocessableEntity, "invalid_reason",
			"a cancel requires a reason", `{"reason":"..."}`)
	case signflow.AsValidation(err, &v):
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error(), "")
	default:
		s.logJSON(slog.LevelError, "envelope "+what, "error", err, "envelope", envelopeID,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal",
			"the "+what+" failed", "")
	}
}

// ---------------- machine clients ----------------

// handleClientCreate mints a machine client. The key is random, shown once in
// the response, and stored only as its sha256 — the store never sees the key,
// and no later endpoint can print it again.
func (s *server) handleClientCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if !decodeJSON(w, r, &body, 1<<16) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_name", "the client needs a name", "")
		return
	}
	scopes, err := clientScopes(body.Scopes)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_scope", err.Error(),
			"allowed: envelope:read, envelope:write")
		return
	}
	key := randomKey()
	hash := sha256.Sum256([]byte(key))
	id, err := s.store.AddClient(r.Context(), name, hex.EncodeToString(hash[:]), strings.Join(scopes, ","))
	if err != nil {
		s.logJSON(slog.LevelError, "client create", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the client could not be created", "")
		return
	}
	if err := s.store.AddEvent(r.Context(), "", actor(r), "client_create",
		signflow.PayloadJSON(map[string]any{"client_id": id, "name": name, "scopes": scopes})); err != nil {
		s.logJSON(slog.LevelError, "client create event", "error", err, "request", requestID(r.Context()))
	}
	s.logJSON(slog.LevelInfo, "client create", "client", id, "name", name,
		"actor", actor(r), "request", requestID(r.Context()))
	writeJSON(w, http.StatusCreated, map[string]any{
		"client": map[string]any{"id": id, "name": name, "scopes": scopes},
		"key":    key,
		"note":   "this key is shown once and cannot be shown again; store it now",
	})
}

func (s *server) handleClientRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		writeProblem(w, http.StatusBadRequest, "invalid_client", "the client id must be a number", "")
		return
	}
	c, err := s.store.GetClientByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, signstore.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "no such client", "")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal", "the client read failed", "")
		return
	}
	if err := s.store.RevokeClient(r.Context(), n); err != nil {
		// An already-revoked client is not a thing the operator can revoke again.
		// Answering 200 would let a UI believe a second click did something;
		// answering 500 (which is what the zero-row update would produce) would
		// blame the server for a client's repeated click.
		if c.RevokedAt != "" {
			writeProblem(w, http.StatusNotFound, "not_found", "no active client with that id", "")
			return
		}
		s.logJSON(slog.LevelError, "client revoke", "error", err, "client", id,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the client could not be revoked", "")
		return
	}
	// A revoked client's live tokens must die now, not at their expiry. The
	// store records the revocation time as the client's auth epoch, so every
	// token minted before this call is refused by the middleware's epoch check.
	if err := s.store.AddEvent(r.Context(), "", actor(r), "client_revoke",
		signflow.PayloadJSON(map[string]any{"client_id": n, "name": c.Name})); err != nil {
		s.logJSON(slog.LevelError, "client revoke event", "error", err, "request", requestID(r.Context()))
	}
	s.logJSON(slog.LevelInfo, "client revoke", "client", id, "actor", actor(r),
		"request", requestID(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// clientScopes validates the scope list of a machine client. A machine client
// gets envelope scopes only: it can never hold admin:read, which is why
// acceptance item 1 (a client token on /admin/stats) answers 403 even for a
// client that was created a minute ago.
func clientScopes(in []string) ([]string, error) {
	allowed := map[string]bool{signauth.ScopeEnvelopeRead: true, signauth.ScopeEnvelopeWrite: true}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !allowed[s] {
			return nil, errBadScope(s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errNoScope()
	}
	return out, nil
}

// ---------------- login for the SPA ----------------

// handleLogoutForAdmin ends the admin's session. It is the same logout as the
// machine logout (the session belongs to whoever holds the token) and it is a
// mutation, so it writes the audit event with the actor.
func (s *server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	claims := signauth.ClaimsFrom(r.Context())
	if claims == nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "no session", "")
		return
	}
	if err := s.sessions.Logout(r.Context(), claims.Subject, claims.JTI); err != nil {
		s.logJSON(slog.LevelError, "admin logout", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the logout failed", "")
		return
	}
	if err := s.store.AddEvent(r.Context(), "", claims.Subject, "logout",
		signflow.PayloadJSON(map[string]any{"jti": claims.JTI})); err != nil {
		s.logJSON(slog.LevelError, "admin logout event", "error", err, "request", requestID(r.Context()))
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------- small helpers ----------------

func errBadScope(s string) error {
	return &scopeError{msg: "the scope " + s + " cannot be granted to a client"}
}
func errNoScope() error { return &scopeError{msg: "at least one scope is required"} }

type scopeError struct{ msg string }

func (e *scopeError) Error() string { return e.msg }
