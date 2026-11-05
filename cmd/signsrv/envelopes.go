package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/schema"
	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The envelope endpoints. Create is the only endpoint that writes PDF bytes,
// so it is the one place in the server where the signing service is reached.
// Everything else reads.
//
// The signing service is built once at startup and shared: the CA key is read
// only when signing, and pdfsign opens a fresh document per call, so the
// service is safe for concurrent requests. A server without a keystore runs
// read-only: the create endpoint answers 503, and a read-only deployment (a
// web node in front of the signer) is a supported shape.

// signService builds the signing service from the config. It is called at
// startup, so a keystore that cannot be opened is reported at startup, not on
// the first create.
func signService(cfg *Config, log *slog.Logger) *signpdf.Service {
	fontData, fontName := selftestFont(cfg)
	s, err := signpdf.NewService(signpdf.Config{
		KeystoreDir: cfg.Keystore,
		Passphrase:  cfg.KeystorePassphrase(),
		TSAURL:      cfg.TSAURL,
		FontData:    fontData,
		FontName:    fontName,
		Clock:       time.Now,
	})
	if err != nil {
		log.Error("signing service unavailable", "error", err,
			"keystore", cfg.Keystore, "create", "endpoint will answer 503")
		return nil
	}
	return s
}

// flowDeps builds the dependencies of one create call. The actor and the link
// base travel with the request, not with the service: they are per-call
// facts, and the signing service is shared.
func (s *server) flowDeps() *signflow.Deps {
	return &signflow.Deps{
		Store:     s.store,
		Signer:    s.signer,
		Flow:      signflow.NewFlow(s.store),
		CertifyAs: "signsrv",
		Clock:     time.Now,
		Mail:      s.mail,
	}
}

// ---------------- create ----------------

// maxUpload is the create body limit. 20 MB of PDF plus the JSON fields, with
// room for the multipart framing.
const maxUpload = 22 << 20

// createBody is the decoded multipart form. The spec field is one JSON
// document holding the fill spec, the widget, the subject, and the message;
// parties is a JSON array. The fill JSON is the CLI fill format, so it decodes
// into schema.FillSpec directly — no second invented schema.
type createBody struct {
	Title     string          `json:"title"`
	ExpiresIn string          `json:"expires_in"`
	Fill      schema.FillSpec `json:"fill"`
	Widget    signflow.Widget `json:"widget"`
	Subject   string          `json:"subject"`
	Message   string          `json:"message"`
	Parties   []signflow.Party
}

// handleCreateEnvelopes answers POST /api/v1/envelopes. The body is
// multipart/form-data: template (file), spec (JSON), parties (JSON), title,
// expires_in, send.
func (s *server) handleCreateEnvelopes(w http.ResponseWriter, r *http.Request) {
	claims := signauth.ClaimsFrom(r.Context())
	actor := "unknown"
	if claims != nil {
		actor = claims.Subject
	}

	if s.store == nil {
		writeProblem(w, http.StatusServiceUnavailable, "no_store",
			"the service has no database", "run signsrv migrate")
		return
	}
	if s.signer == nil {
		writeProblem(w, http.StatusServiceUnavailable, "no_keystore",
			"the service cannot sign", "check keystore_dir and the keystore passphrase")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		writeProblem(w, http.StatusBadRequest, "body", "the form could not be read",
			"multipart/form-data with fields template, spec, parties, title")
		return
	}
	defer r.MultipartForm.RemoveAll()

	file, _, err := r.FormFile("template")
	if err != nil {
		writeField(w, "template", "required", "upload the PDF as the template field")
		return
	}
	defer file.Close()
	template, err := io.ReadAll(io.LimitReader(file, maxUpload))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "body", "the template could not be read", "")
		return
	}

	body, ok := s.decodeCreate(w, r)
	if !ok {
		return
	}

	req := signflow.CreateRequest{
		Template:  template,
		Title:     body.Title,
		Parties:   body.Parties,
		Widget:    body.Widget,
		Subject:   body.Subject,
		Message:   body.Message,
		Actor:     actor,
		LinkBase:  s.cfg.PublicURL,
		ExpiresIn: linkTTL(s.cfg, body.ExpiresIn),
	}
	req.Fill = body.Fill

	created, err := s.flowDeps().Create(r.Context(), req)
	if err != nil {
		s.answerCreateFailure(w, r, actor, err)
		return
	}

	s.logJSON(slog.LevelInfo, "envelope created", "envelope", created.Envelope.ID,
		"actor", actor, "parties", len(created.Links), "request", requestID(r.Context()))

	out := map[string]any{
		"envelope": envelopeViewOf(created.Envelope),
		"fill":     created.Fill,
		"links":    created.Links,
		"request":  requestID(r.Context()),
	}
	writeJSON(w, http.StatusCreated, out)
}

// decodeCreate reads the JSON fields of the form. Every field is decoded
// against its own struct, so a bad parties array names the field.
func (s *server) decodeCreate(w http.ResponseWriter, r *http.Request) (createBody, bool) {
	var out createBody

	title := r.FormValue("title")
	if title == "" {
		writeField(w, "title", "required", "a short name for the document, up to 200 characters")
		return out, false
	}
	out.Title = title

	spec := r.FormValue("spec")
	if spec == "" {
		writeField(w, "spec", "required", `{"fill":{"values":{...}},"widget":{...}}`)
		return out, false
	}
	// One JSON document, decoded once: the fill is the CLI fill JSON, the
	// widget and the mail text sit next to it.
	var doc struct {
		Fill    schema.FillSpec `json:"fill"`
		Widget  signflow.Widget `json:"widget"`
		Subject string          `json:"subject"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal([]byte(spec), &doc); err != nil {
		writeField(w, "spec", "not JSON: "+err.Error(),
			`{"fill":{"values":{"field":"text"}}}`)
		return out, false
	}
	if len(doc.Fill.Values) == 0 && len(doc.Fill.Logos) == 0 && len(doc.Fill.Paints) == 0 {
		writeField(w, "spec.fill", "empty",
			"fill needs at least one value, logo, or paint")
		return out, false
	}
	out.Fill = doc.Fill
	out.Widget = doc.Widget
	out.Subject = doc.Subject
	out.Message = doc.Message

	parties := r.FormValue("parties")
	if parties == "" {
		writeField(w, "parties", "required",
			`[{"email":"a@x","name":"Ann","order":1,"reason":"I agree"}]`)
		return out, false
	}
	if err := json.Unmarshal([]byte(parties), &out.Parties); err != nil {
		writeField(w, "parties", "not a JSON array: "+err.Error(),
			`[{"email":"a@x","name":"Ann","order":1}]`)
		return out, false
	}

	out.ExpiresIn = r.FormValue("expires_in")
	return out, true
}

// answerCreateFailure maps a create error to an HTTP answer. A validation
// failure names the field; a conflict means the document was not in the state
// the request expected; anything else is a server fault, reported without
// leaking the internal message to the client.
func (s *server) answerCreateFailure(w http.ResponseWriter, r *http.Request, actor string, err error) {
	var v *signflow.ErrValidation
	if signflow.AsValidation(err, &v) {
		writeProblem(w, http.StatusBadRequest, "invalid_"+v.Field, v.Error(), v.Hint)
		return
	}
	if signflow.IsConflict(err) {
		writeProblem(w, http.StatusConflict, "state_conflict", err.Error(),
			"the envelope changed under the request")
		return
	}
	s.logJSON(slog.LevelError, "create failed", "actor", actor, "error", err,
		"request", requestID(r.Context()))
	writeProblem(w, http.StatusInternalServerError, "internal", "the create failed", "")
}

// ---------------- get / list ----------------

// envelopeViewOf renders an envelope row for the API. The ids of the stored
// PDFs are exposed as document_sha: a client that will download the document
// needs the hash to check what it got.
func envelopeViewOf(e *signstore.Envelope) envelopeView {
	return envelopeView{
		ID:        e.ID,
		Title:     e.Title,
		Status:    string(e.Status),
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
		ExpiresAt: e.ExpiresAt,
	}
}

// handleGetEnvelope answers GET /api/v1/envelopes/{id}: the envelope, its
// parties in signing order, the revision chain, and the audit trail.
func (s *server) handleGetEnvelope(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "the envelope id is required",
			"a 32 character hex id, from the create response")
		return
	}

	env, err := s.store.GetEnvelope(r.Context(), id)
	if err == signstore.ErrNotFound {
		writeProblem(w, http.StatusNotFound, "not_found", "no envelope with this id", "")
		return
	}
	if err != nil {
		s.logJSON(slog.LevelError, "get envelope", "envelope", id, "error", err,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the read failed", "")
		return
	}

	parties, err := s.store.ListParties(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the parties read failed", "")
		return
	}
	revisions, err := s.store.ListRevisions(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the revisions read failed", "")
		return
	}
	events, err := s.store.ListEvents(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the events read failed", "")
		return
	}
	consents, err := s.store.ListConsents(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the consents read failed", "")
		return
	}

	byParty := make(map[string]signstore.Consent, len(consents))
	for _, c := range consents {
		byParty[c.PartyID] = c
	}
	views := make([]partyView, 0, len(parties))
	consented := 0
	for _, p := range parties {
		v := partyView{
			Order: p.OrderIdx, Email: p.Email, Name: p.Name,
			Status: string(p.Status), ConsentAt: p.ConsentAt,
			LinkExpiresAt: p.TokenExpires,
		}
		if c, ok := byParty[p.ID]; ok {
			v.SignatureText = c.SignatureText
		}
		if p.Status == signstore.PartyConsented {
			consented++
		}
		views = append(views, v)
	}

	revs := make([]revisionView, 0, len(revisions))
	for _, rev := range revisions {
		revs = append(revs, revisionView{
			ID: rev.ID, Kind: rev.Kind, SHA256: rev.SHA256,
			PrevID: rev.PrevID, Size: rev.Size, CreatedAt: rev.CreatedAt,
			PartyID: rev.PartyID, CertSerial: rev.CertSerial,
		})
	}
	evs := make([]eventView, 0, len(events))
	for _, e := range events {
		evs = append(evs, eventView{
			Kind: e.Kind, Actor: e.Actor, CreatedAt: e.CreatedAt, Payload: e.Payload,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           env.ID,
		"title":        env.Title,
		"status":       string(env.Status),
		"expires_at":   env.ExpiresAt,
		"serial":       env.Serial,
		"document_sha": env.CurrentSHA,
		"parties":      views,
		"consented":    consented,
		"total":        len(views),
		"revisions":    revs,
		"events":       evs,
		"request":      requestID(r.Context()),
	})
}

// handleGetDocument streams the current PDF of an envelope. The body is the
// stored bytes, so the hash of what is sent is exactly envelopes.current_sha;
// the header X-Content-Sha256 lets a client check that without re-hashing the
// envelope state.
func (s *server) handleGetDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	env, err := s.store.GetEnvelope(r.Context(), id)
	if err == signstore.ErrNotFound {
		writeProblem(w, http.StatusNotFound, "not_found", "no envelope with this id", "")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the read failed", "")
		return
	}
	// The kind comes from the revision row, so the filename says what the
	// bytes are: "certified" while the document is collecting signatures,
	// "signed" once every party has signed. A filename that matches the
	// content is what makes a download identifiable in a filing system.
	kind := "document"
	if rev, err := s.store.GetRevisionOfEnvelope(r.Context(), env.ID, env.CurrentSHA); err == nil {
		kind = rev.Kind
	}
	s.streamPDF(w, r, env.Title, kind, env.CurrentSHA)
}

// handleGetRevision streams one revision of an envelope. The revision must
// belong to the envelope in the path: a revision id from another envelope is
// a 404, not a leak of someone else's document.
func (s *server) handleGetRevision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rev, err := s.store.GetRevision(r.Context(), r.PathValue("rid"))
	if err == signstore.ErrNotFound {
		writeProblem(w, http.StatusNotFound, "not_found", "no revision with this id", "")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the read failed", "")
		return
	}
	if rev.EnvelopeID != id {
		writeProblem(w, http.StatusNotFound, "not_found",
			"the revision does not belong to this envelope", "")
		return
	}
	s.streamPDF(w, r, envTitleOf(r.Context(), s, id), rev.Kind, rev.SHA256)
}

func envTitleOf(ctx context.Context, s *server, id string) string {
	env, err := s.store.GetEnvelope(ctx, id)
	if err != nil {
		return "envelope"
	}
	return env.Title
}

// streamPDF writes a stored PDF as an attachment. A PDF that the store does
// not have is a 410: the row is in the database, the file is not, and that is
// a state the operator needs to see rather than a generic 500.
func (s *server) streamPDF(w http.ResponseWriter, r *http.Request, title, kind, sha string) {
	if sha == "" {
		writeProblem(w, http.StatusNotFound, "no_document",
			"the envelope has no document in this state", "")
		return
	}
	data, err := s.store.GetPDF(sha)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeProblem(w, http.StatusGone, "missing_file",
				"the stored file is missing from the storage directory",
				"check storage_dir, and restore it from backup")
			return
		}
		s.logJSON(slog.LevelError, "document read", "sha", sha, "error", err,
			"request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the document read failed", "")
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("Content-Disposition", `attachment; filename="`+DownloadName(title, kind)+`"`)
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Sha256", sha)
	if _, err := w.Write(data); err != nil {
		s.logJSON(slog.LevelWarn, "document write", "sha", sha, "error", err,
			"request", requestID(r.Context()))
	}
	s.logJSON(slog.LevelInfo, "document sent", "sha", sha, "bytes", len(data),
		"request", requestID(r.Context()))
}

// DownloadName is the filename of an attachment: a slug of the title plus the
// revision kind. A filename that carries the title is what makes a downloaded
// file recognisable in a filing system.
func DownloadName(title, kind string) string {
	slug := slugify(title)
	if kind == "" {
		kind = "document"
	}
	return slug + "-" + slugify(kind) + ".pdf"
}

func slugify(s string) string {
	out := make([]rune, 0, len(s))
	prev := '-'
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
			prev = r
		case r == '-' || r == '_':
			if prev != '-' {
				out = append(out, '-')
				prev = '-'
			}
		default:
			if prev != '-' {
				out = append(out, '-')
				prev = '-'
			}
		}
	}
	if len(out) == 0 {
		return "envelope"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}

// ---------------- small helpers ----------------

// writeField is the 400 answer for one form field. The code names the field,
// so a client can map the failure to the input it sent.
func writeField(w http.ResponseWriter, field, msg, hint string) {
	writeProblem(w, http.StatusBadRequest, "invalid_"+field, msg, hint)
}

// linkTTL parses expires_in. The accepted forms are a Go duration ("48h",
// "24h30m") or a number of hours, so a shell command and a JSON form agree.
func linkTTL(cfg *Config, raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg.LinkTTL
	}
	if n, err := strconv.Atoi(raw); n > 0 && err == nil {
		return time.Duration(n) * time.Hour
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return cfg.LinkTTL
	}
	return d
}

// The views of the API answers. They are separate structs so the JSON order
// is stable and the internal model does not travel to the client.
type partyView struct {
	Order         int    `json:"order"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	ConsentAt     string `json:"consent_at,omitempty"`
	SignatureText string `json:"signature_text,omitempty"`
	LinkExpiresAt string `json:"link_expires_at"`
}

type revisionView struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	SHA256     string `json:"sha256"`
	PrevID     string `json:"prev_id,omitempty"`
	Size       int64  `json:"size"`
	CreatedAt  string `json:"created_at"`
	PartyID    string `json:"party_id,omitempty"`
	CertSerial string `json:"cert_serial,omitempty"`
}

type eventView struct {
	Kind      string `json:"kind"`
	Actor     string `json:"actor"`
	CreatedAt string `json:"created_at"`
	Payload   string `json:"payload,omitempty"`
}

var _ = fmt.Sprintf

// ---------------- send ----------------

// handleSendEnvelope answers POST /api/v1/envelopes/{id}/send. Send is a state
// transition (Ready -> Sent): it stamps each party token, enqueues the
// invitations, and moves the envelope to Sent. The tokens are returned so the
// operator can read them once, at the moment the links are created. A send on
// an envelope that is not ready is 409; a send that finds the envelope
// missing is 404.
func (s *server) handleSendEnvelope(w http.ResponseWriter, r *http.Request) {
	claims := signauth.ClaimsFrom(r.Context())
	actor := "unknown"
	if claims != nil {
		actor = claims.Subject
	}

	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "the envelope id is required",
			"a 32 character hex id, from the create response")
		return
	}
	if s.store == nil {
		writeProblem(w, http.StatusServiceUnavailable, "store_unavailable",
			"this node has no store", "start with a storage directory")
		return
	}

	links, err := s.flowDeps().Send(r.Context(), id, actor, time.Now())
	if err != nil {
		var v *signflow.ErrValidation
		if signflow.AsValidation(err, &v) {
			writeProblem(w, http.StatusBadRequest, "invalid_"+v.Field, v.Error(), v.Hint)
			return
		}
		if err == signstore.ErrNotFound {
			writeProblem(w, http.StatusNotFound, "not_found", "no envelope with this id", "")
			return
		}
		if signflow.IsConflict(err) {
			writeProblem(w, http.StatusConflict, "state_conflict", err.Error(),
				"only a ready envelope can be sent")
			return
		}
		s.logJSON(slog.LevelError, "send failed", "envelope", id, "actor", actor,
			"error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the send failed", "")
		return
	}

	env, err := s.store.GetEnvelope(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal", "the send failed", "")
		return
	}

	s.logJSON(slog.LevelInfo, "envelope sent", "envelope", id, "actor", actor,
		"parties", len(links), "request", requestID(r.Context()))

	writeJSON(w, http.StatusOK, map[string]any{
		"envelope": envelopeViewOf(env),
		"links":    links,
		"request":  requestID(r.Context()),
	})
}
