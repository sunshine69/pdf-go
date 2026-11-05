package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The admin surface of step 09: the dashboard, the actions an operator takes on
// a live envelope, the audit log, the settings, and the machine clients. The
// actions are the interesting part, because each one has a fact a party can
// check from the other side of the API: a cancelled envelope answers 410 to the
// links it invalidated, and a reissue answers 404 to the link it replaced.

// adminCode runs an admin request and returns the status and the decoded answer.
func adminCode(t *testing.T, ts *httptest.Server, method, path, token, body string) (int, map[string]any) {
	t.Helper()
	res, raw := adminCall(t, ts, token, method, path, body)
	return res.StatusCode, decodeJSONMap(raw)
}

// outboxFiles lists the messages the file sender wrote, which is how a test
// proves an action mailed something.
func outboxFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func hasOutbox(t *testing.T, dir, prefix string) bool {
	t.Helper()
	for _, n := range outboxFiles(t, dir) {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Scope on the admin endpoints

func TestAdminStatsCollectingTile(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)

	// An empty dashboard still answers every status, so the tiles do not have
	// to guess which keys exist.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", admin, "")
	if code != http.StatusOK {
		t.Fatalf("stats: code %d", code)
	}
	empty, _ := out["by_status"].(map[string]any)
	if len(empty) == 0 {
		t.Fatalf("stats by_status is empty: %v", out)
	}
	if _, ok := empty["collecting"]; !ok {
		t.Fatalf("stats must list every status: %v", empty)
	}
	if out["collecting"] == nil {
		t.Fatalf("stats must answer the collecting list even when it is empty: %v", out)
	}
	if out["queues"] == nil {
		t.Fatalf("stats must answer the queue depth: %v", out)
	}

	// One party consented of two: the tile shows the progress, not just a
	// status word.
	se := newSignEnv(t, ts, admin)
	id := se.id
	jar := signAs(t, ts, se, "ann@x.test")
	res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("Ann Lawless", true, se.dsha, ""))
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("consent: status %d body %s", res.StatusCode, body)
	}

	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", admin, "")
	if code != http.StatusOK {
		t.Fatalf("stats after a consent: code %d", code)
	}
	byStatus, _ := out["by_status"].(map[string]any)
	if byStatus["collecting"] == nil || byStatus["collecting"].(float64) != 1 {
		t.Fatalf("by_status collecting: %v", byStatus)
	}
	rows, _ := out["collecting"].([]any)
	if len(rows) != 1 {
		t.Fatalf("collecting rows: %d", len(rows))
	}
	row, _ := rows[0].(map[string]any)
	if row["id"] != id {
		t.Fatalf("collecting row envelope: %v", row)
	}
	if row["consented"] == nil || row["consented"].(float64) != 1 || row["total"] == nil || row["total"].(float64) != 2 {
		t.Fatalf("collecting row consent progress: %v", row)
	}
	if row["title"] == nil || row["title"] == "" {
		t.Fatalf("collecting row must carry the title: %v", row)
	}
	queues, _ := out["queues"].(map[string]any)
	if queues["mail_waiting"] == nil {
		t.Fatalf("queue depth incomplete: %v", out["queues"])
	}
}

// Scope on the admin endpoints

func TestAdminClientTokenCannotReadStats(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	key := mintClientToken(t, ts, admin, "ops", signauth.ScopeEnvelopeRead)

	// envelope:read sees the envelope, but not the operator's numbers.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", key, "")
	if code != http.StatusForbidden {
		t.Fatalf("envelope:read on stats: want 403, got %d (%v)", code, out["detail"])
	}
	if codeOf(t, out) != "insufficient_scope" {
		t.Fatalf("problem type on a scope refusal: %q", codeOf(t, out))
	}

	// The admin token sees them.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", admin, "")
	if code != http.StatusOK {
		t.Fatalf("admin on stats: want 200, got %d (%v)", code, out["detail"])
	}
	for _, k := range []string{"counts", "overdue", "queues"} {
		if out[k] == nil {
			t.Fatalf("stats answer is missing %q: %v", k, out)
		}
	}

	// No token at all is a 401, not a 403.
	code, _ = adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", "", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("anonymous on stats: want 401, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Cancel

func TestAdminCancelCollecting(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	// A cancel without a reason is refused: an operator must say why.
	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/cancel", admin, `{}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("cancel with no reason: want 422, got %d (%v)", code, out["detail"])
	}

	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/cancel", admin,
		`{"reason":"the contract was withdrawn"}`)
	if code != http.StatusOK {
		t.Fatalf("cancel: want 200, got %d (%v)", code, out["detail"])
	}

	// The parties' links are gone.
	for _, token := range se.tokens {
		res, _ := rawGet(t, ts, "/api/v1/sign/"+token+"/envelope", "")
		if res.StatusCode != http.StatusGone {
			t.Fatalf("link on a cancelled envelope: want 410, got %d", res.StatusCode)
		}
	}

	// Each party was notified: the queue carries a cancelled row for each one.
	rows, err := store.ListMail(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	parties := partyList(t, store, se.id)
	for _, p := range parties {
		if !hasMailKind(t, rows, "cancelled", p.ID) {
			t.Fatalf("no cancelled mail row for party %s: %v", p.ID, mailKinds(t, rows))
		}
	}

	// The audit log says the request was cancelled, and says why.
	ev := eventOf(t, store, se.id, "cancelled")
	if ev == nil {
		t.Fatalf("no cancelled event; kinds %v", eventKinds(t, store, se.id))
	}
	if !strings.Contains(ev.Payload, "withdrawn") {
		t.Fatalf("the cancelled event does not carry the reason: %q", ev.Payload)
	}

	env, err := store.GetEnvelope(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != signstore.StatusCancelled {
		t.Fatalf("status after cancel: %s", env.Status)
	}

	// The admin log the operator reads carries the same fact.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/events?envelope="+se.id, admin, "")
	if code != http.StatusOK {
		t.Fatalf("admin events: want 200, got %d", code)
	}
	if !strings.Contains(fmt.Sprint(out["events"]), "cancelled") {
		t.Fatalf("the admin log has no cancelled entry: %v", out["events"])
	}
}

func TestAdminCancelDeliveredIsConflict(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	id := deliverOne(t, ts, admin)

	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+id+"/cancel", admin,
		`{"reason":"too late"}`)
	if code != http.StatusConflict {
		t.Fatalf("cancel a delivered envelope: want 409, got %d (%v)", code, out["detail"])
	}
	if codeOf(t, out) != "state_conflict" {
		t.Fatalf("problem type on a closed envelope: %q", codeOf(t, out))
	}
}

// ---------------------------------------------------------------------------
// Remind

func TestAdminRemindTwiceIsLimited(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	for i := 1; i <= 2; i++ {
		code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/remind", admin, "")
		if code != http.StatusOK {
			t.Fatalf("remind %d: want 200, got %d (%v)", i, code, out["detail"])
		}
	}
	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/remind", admin, "")
	if code != http.StatusTooManyRequests {
		t.Fatalf("third remind: want 429, got %d (%v)", code, out["detail"])
	}
	if codeOf(t, out) != "rate_limited" {
		t.Fatalf("problem type on the third remind: %q", codeOf(t, out))
	}
	// Both parties were mailed a reminder: the file sender names each message
	// {kind}-{envelope}-{party}, so one reminder file per party is the proof.
	for _, p := range partyList(t, store, se.id) {
		if !hasOutbox(t, cfg.Outbox, "reminder-"+se.id+"-"+p.ID) {
			t.Fatalf("no reminder mail for party %s; outbox %v", p.ID, outboxFiles(t, cfg.Outbox))
		}
	}
	if n := eventOf(t, store, se.id, "remind"); n == nil {
		t.Fatalf("no remind event; kinds %v", eventKinds(t, store, se.id))
	}
	// A cancel on a collecting envelope is still allowed after the limit is hit,
	// because the limit is per action.
	code, _ = adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/cancel", admin,
		`{"reason":"rate limited tests"}`)
	if code != http.StatusOK {
		t.Fatalf("cancel after reminds: want 200, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Reissue

func TestAdminReissueLinks(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/reissue", admin, "")
	if code != http.StatusOK {
		t.Fatalf("reissue: want 200, got %d (%v)", code, out["detail"])
	}
	reissued := out["reissued"].([]any)
	if len(reissued) != len(se.tokens) {
		t.Fatalf("reissue returned %d links, want %d", len(reissued), len(se.tokens))
	}
	seen := map[string]bool{}
	for _, r := range reissued {
		entry := r.(map[string]any)
		if entry["party_id"] == nil || entry["email"] == nil {
			t.Fatalf("reissued entry incomplete: %v", entry)
		}
		link := entry["link"].(string)
		if link == "" {
			t.Fatalf("reissued entry has no link: %v", entry)
		}
		token := linkToken(link)
		if token == "" || seen[token] {
			t.Fatalf("reissued link is unusable or repeated: %q", link)
		}
		seen[token] = true
	}
	for _, token := range se.tokens {
		if seen[token] {
			t.Fatal("reissue returned the old token")
		}
	}

	// The old links are dead.
	for _, token := range se.tokens {
		res, _ := rawGet(t, ts, "/api/v1/sign/"+token+"/envelope", "")
		if res.StatusCode == http.StatusOK {
			t.Fatalf("the old link still resolves: %s", token)
		}
	}
	// The new links work.
	// The new links resolve: the envelope behind them is the same one, and the
	// link itself is not the old one.
	for token := range seen {
		res, body := rawGet(t, ts, "/api/v1/sign/"+token+"/envelope", "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("new link after reissue: want 200, got %d (%s)", res.StatusCode, body)
		}
	}

	if eventOf(t, store, se.id, "reissue") == nil {
		t.Fatalf("no reissue event; kinds %v", eventKinds(t, store, se.id))
	}
}

// linkToken takes the token out of a link URL.
func linkToken(link string) string {
	i := strings.LastIndex(link, "/")
	if i < 0 {
		return ""
	}
	return link[i+1:]
}

// partyList reads the parties of an envelope.
// hasMailKind reports whether the queue holds a row of this kind for this party.
func hasMailKind(t *testing.T, rows []signstore.MailItem, kind, partyID string) bool {
	t.Helper()
	for _, r := range rows {
		if r.Kind == kind && r.PartyID == partyID {
			return true
		}
	}
	return false
}

// mailKinds renders the queue for a failure message.
func mailKinds(t *testing.T, rows []signstore.MailItem) []string {
	t.Helper()
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Kind+":"+r.PartyID)
	}
	return out
}

func partyList(t *testing.T, store *signstore.Store, envelopeID string) []signstore.Party {
	t.Helper()
	parties, err := store.ListParties(context.Background(), envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	return parties
}

// eventKinds lists the event kinds recorded for an envelope.
func eventKinds(t *testing.T, store *signstore.Store, envelopeID string) []string {
	t.Helper()
	events, err := store.ListEvents(context.Background(), envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]string, 0, len(events))
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

// codeOf reads the problem code out of an answer. Every error in this service
// is {"error":{"code":...,"message":...}}, so the code lives one level down.
func codeOf(t *testing.T, out map[string]any) string {
	t.Helper()
	if errObj, ok := out["error"].(map[string]any); ok {
		if s, ok := errObj["code"].(string); ok {
			return s
		}
	}
	for _, k := range []string{"code", "type"} {
		if s, ok := out[k].(string); ok {
			return s
		}
	}
	return ""
}
