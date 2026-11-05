package main

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The first protected endpoints. They exist in step 03 because the acceptance
// test for the middleware needs a route to be allowed on and a route to be
// refused: the middleware is the deliverable, the payloads are step 05.

// envelopeView is one row of the list. The full detail, the parties and the
// consents, is step 05.
type envelopeView struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	ExpiresAt string `json:"expires_at"`
}

// handleListEnvelopes answers GET /api/v1/envelopes?status=&q=. The scope is
// envelope:read, so a machine client with only that scope can list, and an
// admin can list because an admin carries every scope.
func (s *server) handleListEnvelopes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	if status != "" && !signstore.ValidStatus(status) {
		writeProblem(w, http.StatusBadRequest, "invalid_status",
			"status is not one of the known values",
			"one of: draft, ready, sent, collecting, signed, completed, delivered, expired, cancelled, failed")
		return
	}
	// The limit is capped here as well, so the answer echoes the page size
	// actually used. A caller that asks for 500 gets 100 and sees 100.
	limit := intQuery(q.Get("limit"), 50)
	if limit > signstore.MaxPageSize {
		limit = signstore.MaxPageSize
	}
	offset := intQuery(q.Get("offset"), 0)

	out, total, err := s.store.ListEnvelopes(r.Context(), status, q.Get("q"), limit, offset)
	if err != nil {
		s.logJSON(slog.LevelError, "list envelopes", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the list failed", "")
		return
	}
	views := make([]envelopeView, 0, len(out))
	for _, e := range out {
		views = append(views, envelopeView{
			ID: e.ID, Title: e.Title, Status: string(e.Status),
			CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, ExpiresAt: e.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"envelopes": views,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
		"request":   requestID(r.Context()),
	})
}

// handleAdminStats is the admin audience probe: it needs admin:read, which a
// machine client does not carry. The numbers are the row counts the operator
// looks at, and the request id is echoed so a support ticket can quote it.
func (s *server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	counts, err := s.store.Counts(r.Context())
	if err != nil {
		s.logJSON(slog.LevelError, "admin stats", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the counts failed", "")
		return
	}
	claims := signauth.ClaimsFrom(r.Context())
	actor := "unknown"
	if claims != nil {
		actor = claims.Subject
	}
	// The dashboard payload proper: counts per status, the overdue list and
	// the collecting list with consent progress. The table counts stay in the
	// answer as well, because they are the numbers dbstatus and the operator's
	// sanity check read.
	flowStats, err := s.flowDeps().Stats(r.Context(), s.clockNow())
	if err != nil {
		s.logJSON(slog.LevelError, "admin stats flow", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the counts failed", "")
		return
	}
	// The queue depth rides along: the dashboard that polls stats is where an
	// operator notices that nothing is draining.
	backlog, err := s.store.QueueBacklog(r.Context())
	if err != nil {
		s.logJSON(slog.LevelError, "admin stats queues", "error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the queue counts failed", "")
		return
	}
	s.logJSON(slog.LevelInfo, "admin stats", "actor", actor, "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{
		"counts":     counts,
		"by_status":  flowStats.Counts,
		"overdue":    flowStats.Overdue,
		"collecting": flowStats.Collecting,
		"queues":     backlog,
		"actor":      actor,
		"request":    requestID(r.Context()),
	})
}

// intQuery reads a paging parameter, falling back to the default when it is
// missing or not a number: a page size is not a place where an error helps.
func intQuery(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}
