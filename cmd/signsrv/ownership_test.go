package main

// Envelope ownership, through HTTP.
//
// created_by_subject is what keeps one machine client's documents away from
// another's. The store filter is tested in signstore; this file tests the four
// places the API has to remember it, because each is a separate handler and a
// missing check in any one of them is a leak the others would not show.
//
// The interesting direction is the negative one: client B must get a 404 for a
// real envelope id belonging to client A. A 403 would confirm the id exists to
// anyone willing to guess one, and these ids are the only capability a signing
// link holder has, so "not yours" and "does not exist" have to be the same
// answer.
//
// An admin is checked in the other direction too: the filter must not quietly
// apply to the operator, who is the one person able to see a client's stuck
// envelope.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// clientToken creates a machine client holding both envelope scopes and
// returns a bearer token for it together with the subject that token carries.
// The scopes are not what this file is about — the scope tests cover those —
// so both are granted, to keep these assertions about ownership rather than
// about being turned away before the ownership check ever runs.
func clientToken(t *testing.T, ts *httptest.Server, store *signstore.Store, name string) (string, string) {
	t.Helper()
	key := randomKey()
	id, err := store.AddClient(context.Background(), name, sha256Of([]byte(key)),
		signauth.ScopeEnvelopeRead+","+signauth.ScopeEnvelopeWrite)
	if err != nil {
		t.Fatalf("add client %s: %v", name, err)
	}
	// The subject the token will carry, and therefore the subject every
	// envelope this client creates is stamped with.
	subject := signauth.ClientSubject(id)
	res, err := ts.Client().Post(ts.URL+"/api/v1/auth/token", "application/json",
		strings.NewReader(`{"key":"`+key+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body := decode(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token for %s = %d: %v", name, res.StatusCode, body)
	}
	access, _ := body["access"].(string)
	if access == "" {
		t.Fatalf("no access token for %s: %v", name, body)
	}
	return access, subject
}

// createAs creates one envelope titled title and returns its id.
func createAs(t *testing.T, ts *httptest.Server, token, title string) string {
	t.Helper()
	fields := createFields(t, sample1(t),
		`[{"email":"`+slugify(title)+`@example.test","name":"Ann","order":1}]`)
	fields["title"] = title
	code, out := createRequest(t, ts, token, sample1(t), fields)
	if code != http.StatusCreated {
		t.Fatalf("create %q = %d: %v", title, code, out)
	}
	env, _ := out["envelope"].(map[string]any)
	id, _ := env["id"].(string)
	if id == "" {
		t.Fatalf("create %q returned no envelope id: %v", title, out)
	}
	return id
}

// listTotal asks the list endpoint how many envelopes the caller can see, and
// checks the rows agree with the count it reports.
func listTotal(t *testing.T, ts *httptest.Server, token string) int {
	t.Helper()
	code, out := getJSON(t, ts, "/api/v1/envelopes", token)
	if code != http.StatusOK {
		t.Fatalf("list = %d: %v", code, out)
	}
	total, _ := out["total"].(float64)
	list, _ := out["envelopes"].([]any)
	if len(list) != int(total) {
		t.Fatalf("list returned %d rows but total %v", len(list), out["total"])
	}
	return int(total)
}

// statusOnly is the status of a GET whose body is bytes rather than JSON.
func statusOnly(t *testing.T, ts *httptest.Server, path, token string) int {
	t.Helper()
	res, err := rawGet(t, ts, path, token)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

// TestEnvelopeOwnershipBetweenClients is the whole rule in one pass: what a
// client can see of its own documents, and what it cannot see of another's.
func TestEnvelopeOwnershipBetweenClients(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)

	a, _ := clientToken(t, ts, store, "alpha")
	b, _ := clientToken(t, ts, store, "beta")
	admin := accessOf(t, ts)

	idA := createAs(t, ts, a, "Alpha NDA")
	createAs(t, ts, b, "Beta Lease")

	// The list. Two clients created two envelopes; each sees exactly one.
	if got := listTotal(t, ts, a); got != 1 {
		t.Errorf("client alpha sees %d envelopes, want 1", got)
	}
	if got := listTotal(t, ts, b); got != 1 {
		t.Errorf("client beta sees %d envelopes, want 1", got)
	}
	// The admin sees both. The filter is for clients, not for the operator.
	if got := listTotal(t, ts, admin); got != 2 {
		t.Errorf("admin sees %d envelopes, want 2", got)
	}

	// The status endpoint: one's own is readable, the other's is a 404 rather
	// than a 403, so knowing another client's envelope id reveals nothing.
	if code, _ := getJSON(t, ts, "/api/v1/envelopes/"+idA, a); code != http.StatusOK {
		t.Errorf("alpha reads its own envelope = %d, want 200", code)
	}
	if code, _ := getJSON(t, ts, "/api/v1/envelopes/"+idA, b); code != http.StatusNotFound {
		t.Errorf("beta reads alpha's envelope = %d, want 404", code)
	}
	if code, _ := getJSON(t, ts, "/api/v1/envelopes/"+idA, admin); code != http.StatusOK {
		t.Errorf("admin reads alpha's envelope = %d, want 200", code)
	}

	// The document download and the revision read are separate handlers with
	// separate checks, and both return bytes, so each earns its own assertion.
	if code := statusOnly(t, ts, "/api/v1/envelopes/"+idA+"/document", a); code != http.StatusOK {
		t.Errorf("alpha downloads its own document = %d, want 200", code)
	}
	if code := statusOnly(t, ts, "/api/v1/envelopes/"+idA+"/document", b); code != http.StatusNotFound {
		t.Errorf("beta downloads alpha's document = %d, want 404", code)
	}

	revs, err := store.ListRevisions(context.Background(), idA)
	if err != nil || len(revs) == 0 {
		t.Fatalf("alpha's envelope has no revisions to read: %v %d", err, len(revs))
	}
	rid := revs[0].ID
	if code := statusOnly(t, ts, "/api/v1/envelopes/"+idA+"/revisions/"+rid, a); code != http.StatusOK {
		t.Errorf("alpha reads its own revision = %d, want 200", code)
	}
	// The revision route is scoped by the envelope id in the path, so beta
	// reaching it with its own id cannot find alpha's revision under it.
	if code := statusOnly(t, ts, "/api/v1/envelopes/"+idA+"/revisions/"+rid, b); code != http.StatusNotFound {
		t.Errorf("beta reads alpha's revision = %d, want 404", code)
	}

	// Send is the write in the set. Beta must not mail Alpha's parties, and
	// must not leave a queue row behind while being refused.
	if res, body := adminCall(t, ts, b, http.MethodPost, "/api/v1/envelopes/"+idA+"/send", `{}`); res.StatusCode != http.StatusNotFound {
		t.Errorf("beta sends alpha's envelope = %d, want 404: %s", res.StatusCode, body)
	}
	if n, err := store.CountMail(context.Background(), idA, "", false); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Errorf("a refused send queued %d messages, want 0", n)
	}
	if res, body := adminCall(t, ts, a, http.MethodPost, "/api/v1/envelopes/"+idA+"/send", `{}`); res.StatusCode != http.StatusOK {
		t.Errorf("alpha sends its own envelope = %d, want 200: %s", res.StatusCode, body)
	}
}

// TestEnvelopeOwnershipIsNotInheritedByScope asks the question the scopes do
// not answer: a client that may create envelopes at all still cannot reach
// another client's, though it holds the same capabilities. That is the
// difference between "allowed to use the endpoint" and "allowed to read this
// row", and it is only visible when both clients hold identical scopes, which
// clientToken arranges.
func TestEnvelopeOwnershipIsNotInheritedByScope(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	a, subject := clientToken(t, ts, store, "alpha")
	b, _ := clientToken(t, ts, store, "beta")

	idA := createAs(t, ts, a, "Alpha Only")
	idB := createAs(t, ts, b, "Beta Only")
	code, out := getJSON(t, ts, "/api/v1/envelopes/"+idA, b)
	if code != http.StatusNotFound {
		t.Fatalf("beta read alpha's envelope = %d: %v", code, out)
	}
	// The row is really there. Without this the 404 above could just mean the
	// create failed, and the test would prove nothing.
	got, err := store.GetEnvelope(context.Background(), idA)
	if err != nil {
		t.Fatalf("the envelope beta could not see: %v", err)
	}
	if got.CreatedBySubject != subject {
		t.Errorf("envelope owned by %q, want the creating client's subject %q",
			got.CreatedBySubject, subject)
	}
	// And beta's own envelope is stamped with beta's subject, not alpha's: the
	// stamp comes from the caller, not from whatever created the last row.
	own, err := store.GetEnvelope(context.Background(), idB)
	if err != nil {
		t.Fatalf("beta's own envelope: %v", err)
	}
	if own.CreatedBySubject == got.CreatedBySubject || own.CreatedBySubject == "" {
		t.Errorf("beta's envelope owned by %q, want beta's own subject", own.CreatedBySubject)
	}
}

// TestEnvelopeOwnershipOfActions covers the endpoints that act on an envelope
// rather than read it: remind, cancel, reissue, sign, the report and the audit
// archive. Each sits behind envelope:write, which any machine client that may
// create envelopes also holds, so before these gates any such client could
// cancel any other client's envelope and, on the two GETs, read it.
//
// The three-way comparison is the point. The action's own answer to the owner
// is whatever the state machine says it is — a draft cannot be cancelled, a
// draft has nobody to remind — so the test does not hard-code it. What it does
// require is that a stranger's answer is a 404, that a stranger's answer never
// equals the owner's, and that an unknown envelope answers exactly as a
// stranger's envelope does. Those three together say the refusal comes from
// ownership and not from the action happening to be impossible right now.
func TestEnvelopeOwnershipOfActions(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	a, _ := clientToken(t, ts, store, "alpha")
	b, _ := clientToken(t, ts, store, "beta")
	admin := accessOf(t, ts)

	// A fresh draft: cancel and remind are both refused by the state machine,
	// which is what makes the comparison below meaningful.
	idA := createAs(t, ts, a, "Alpha Actions")

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"remind", http.MethodPost, "/remind", `{}`},
		{"cancel", http.MethodPost, "/cancel", `{"reason":"withdrawn"}`},
		{"reissue", http.MethodPost, "/reissue", ``},
		{"sign", http.MethodPost, "/sign", ``},
		{"report", http.MethodGet, "/report", ``},
		{"audit.zip", http.MethodGet, "/audit.zip", ``},
	}
	for _, c := range cases {
		path := "/api/v1/envelopes/" + idA + c.path
		other := "/api/v1/envelopes/" + strings.Repeat("0", 32) + c.path

		owner, ownerBody := adminCall(t, ts, a, c.method, path, c.body)
		stranger, strangerBody := adminCall(t, ts, b, c.method, path, c.body)
		missing, _ := adminCall(t, ts, b, c.method, other, c.body)

		// The stranger is refused, and refused with the same answer an unknown
		// id gets: the envelope's existence is not confirmed to it.
		if stranger.StatusCode != http.StatusNotFound {
			t.Errorf("%s by a stranger = %d, want 404: %s", c.name, stranger.StatusCode, strangerBody)
		}
		if missing.StatusCode != http.StatusNotFound {
			t.Errorf("%s on an unknown envelope = %d, want 404", c.name, missing.StatusCode)
		}
		// The owner is not refused for want of ownership. If this failed with a
		// 404 the gate would be wrong rather than merely untested, because the
		// state machine has no way to answer "not yours".
		if owner.StatusCode == http.StatusNotFound {
			t.Errorf("%s by the owner = 404, want the action's own answer: %s", c.name, ownerBody)
		}
		// An admin, who is not the owner, is not refused either.
		if as, _ := adminCall(t, ts, admin, c.method, path, c.body); as.StatusCode == http.StatusNotFound {
			t.Errorf("%s by an admin on a client's envelope = 404, want the action's own answer", c.name)
		}
	}
}
