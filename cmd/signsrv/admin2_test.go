package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The second half of step 09: the batch that the operator starts by hand, the
// archive that proves what the batch did, and the report that says whether the
// document is still intact. All three run against the real signing service, so
// the PDFs in the archive are the PDFs the API serves.

// deliverOne runs the whole chain through the endpoints: create, send, both
// parties consent, the operator signs now. It returns the envelope id, whose
// status is delivered and whose verification report is valid.
func deliverOne(t *testing.T, ts *httptest.Server, admin string) string {
	t.Helper()
	se := newSignEnv(t, ts, admin)
	names := []string{"Ann", "Bob"}
	emails := []string{"ann@x.test", "bob@x.test"}
	for i := range se.tokens {
		jar := newJar()
		res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[i]+"/claim",
			`{"email":"`+emails[i]+`"}`)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("claim: status %d body %s", res.StatusCode, body)
		}
		res, body, err = jar.postJSON(ts, "/api/v1/sign/"+se.tokens[i]+"/consent",
			consentBody(names[i]+" Lawless", true, se.dsha, ""))
		if err != nil {
			t.Fatalf("consent: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("consent: status %d body %s", res.StatusCode, body)
		}
	}
	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/sign", admin, "")
	if code != http.StatusOK {
		t.Fatalf("sign: code %d detail %v", code, out["detail"])
	}
	env, _ := out["envelope"].(map[string]any)
	if env["status"] != "delivered" {
		t.Fatalf("status after sign: %v", env["status"])
	}
	return se.id
}

// ---------------------------------------------------------------------------
// Sign now

func TestAdminSignNow(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	// One party has had its say, so the batch refuses to run.
	jar := signAs(t, ts, se, "ann@x.test")
	res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("Ann Lawless", true, se.dsha, ""))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("consent: status %v err %v body %s", res.StatusCode, err, body)
	}
	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/sign", admin, "")
	if code != http.StatusConflict {
		t.Fatalf("sign with a party outstanding: want 409, got %d (%v)", code, out["detail"])
	}
	// The refusal is a refusal: nothing was queued for the envelope.
	if batchCount(t, storeOf(t, ts), se.id) != 0 {
		t.Fatalf("a refused sign queued %d batches, want 0", batchCount(t, storeOf(t, ts), se.id))
	}

	jar2 := newJar()
	res, body, err = jar2.postJSON(ts, "/api/v1/sign/"+se.tokens[1]+"/claim", `{"email":"bob@x.test"}`)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("claim bob: status %v err %v body %s", res.StatusCode, err, body)
	}
	res, body, err = jar2.postJSON(ts, "/api/v1/sign/"+se.tokens[1]+"/consent",
		consentBody("Bob Lawless", true, se.dsha, ""))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("consent bob: status %v err %v body %s", res.StatusCode, err, body)
	}

	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/envelopes/"+se.id+"/sign", admin, "")
	if code != http.StatusOK {
		t.Fatalf("sign now: code %d detail %v", code, out["detail"])
	}
	env, _ := out["envelope"].(map[string]any)
	if env["status"] != "delivered" {
		t.Fatalf("status: %v", env["status"])
	}
	report, _ := out["report"].(map[string]any)
	if report == nil {
		t.Fatalf("the batch answer must carry the verification report: %v", out)
	}
	if report["valid"] != true {
		t.Fatalf("the batch reported an invalid document: %v", report)
	}
	if out["final_sha"] == nil {
		t.Fatal("the batch answer must carry the final document hash")
	}

	// The document on disk carries both signatures and passes verification.
	stored, err := storeOf(t, ts).GetEnvelope(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CurrentSHA == "" {
		t.Fatal("no final hash on the envelope")
	}
	res, err = rawGet(t, ts, "/api/v1/envelopes/"+se.id+"/document", admin)
	if err != nil {
		t.Fatal(err)
	}
	served, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if sha256Of(served) != stored.CurrentSHA {
		t.Fatal("the served document is not the batch's final document")
	}
	report2, err := signService(cfg, logger(cfg)).Verify(context.Background(), served)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report2.Valid {
		t.Fatalf("report invalid: %v", report2.Errors)
	}
	// The document carries the certification signature plus one signature per
	// party: three signature fields, each its own entry in the report.
	if len(report2.Signers) != 3 {
		t.Fatalf("signers in the document (certification + 2 parties): %d", len(report2.Signers))
	}

	// The signed document is the last revision, and the queue is empty.
	revs, err := storeOf(t, ts).ListRevisions(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	if revs[len(revs)-1].SHA256 != stored.CurrentSHA {
		t.Fatalf("the final revision is %s, the envelope says %s",
			revs[len(revs)-1].SHA256, stored.CurrentSHA)
	}
	if n := batchCount(t, storeOf(t, ts), se.id); n != 0 {
		t.Fatalf("the batch queue still holds %d rows for the envelope", n)
	}
	// The signed document is queued for delivery.
	mail, err := storeOf(t, ts).ListMail(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(mail) == 0 {
		t.Fatal("the batch queued no delivery mail")
	}
	// Each party is still consented: the signature lives in the document and
	for _, p := range partyList(t, storeOf(t, ts), se.id) {
		if p.Status != signstore.PartyConsented {
			t.Fatalf("party %s status after the batch: %s", p.ID, p.Status)
		}
	}
}

// ---------------------------------------------------------------------------
// audit.zip

func TestAdminAuditZip(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	id := deliverOne(t, ts, admin)

	res, err := rawGet(t, ts, "/api/v1/envelopes/"+id+"/audit.zip", admin)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("audit.zip: status %d body %s", res.StatusCode, body)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content type: %q", ct)
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, id+"-audit.zip") {
		t.Fatalf("content disposition: %q", cd)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	names := map[string]bool{}
	sums := map[string]string{}
	var manifestRaw []byte
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		names[f.Name] = true
		sum := sha256.Sum256(data)
		sums[f.Name] = hex.EncodeToString(sum[:])
		if f.Name == "manifest.json" {
			manifestRaw = data
		}
	}
	var manifest signflow.AuditManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if !manifest.Verification.Valid {
		t.Fatalf("the manifest's report is invalid: %v", manifest.Verification.Errors)
	}
	// The verification report the archive carries is the batch's own report:
	// the certification plus one signature per party.
	if len(manifest.Verification.Signers) != 3 {
		t.Fatalf("manifest signers (certification + 2 parties): %d",
			len(manifest.Verification.Signers))
	}
	if manifest.Verification.Signers[0].Serial == "" {
		t.Fatal("the manifest report carries no certificate serial")
	}

	for _, want := range []string{"001-template.pdf", "002-filled.pdf", "003-certified.pdf",
		"004-sign-ann.pdf", "005-sign-bob.pdf", "document.pdf",
		"consents.json", "events.json", "manifest.json"} {
		if !names[want] {
			t.Fatalf("audit.zip is missing %s; has %v", want, names)
		}
	}
	// Every hash the manifest publishes matches the file the reader opened.
	for _, entry := range manifest.Files {
		if sums[entry.Name] == "" {
			t.Fatalf("the manifest lists %s, the zip does not contain it", entry.Name)
		}
		if sums[entry.Name] != entry.SHA256 {
			t.Fatalf("%s: the zip holds %s, the manifest says %s", entry.Name, sums[entry.Name], entry.SHA256)
		}
	}
}

// ---------------------------------------------------------------------------
// Report

func TestAdminReport(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	// Before the batch no party has signed, and the answer says so with numbers
	// rather than a status word: the document carries no party signature, and
	// the envelope names two parties.
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/envelopes/"+se.id+"/report", admin, "")
	if code != http.StatusOK {
		t.Fatalf("report before sign: code %d out %v", code, out)
	}
	rep, _ := out["report"].(map[string]any)
	if rep == nil {
		t.Fatalf("report answer: %v", out)
	}

	if out["signed_parties"] == nil || out["signed_parties"].(float64) != 0 {
		t.Fatalf("no party has signed, the report must say so: %v", out)
	}
	if out["required_parties"] == nil || out["required_parties"].(float64) != 2 {
		t.Fatalf("the report must name the parties the envelope asks for: %v", out)
	}
	if out["complete"] != false {
		t.Fatalf("an envelope with no party signatures is not complete: %v", out)
	}
	// The envelope points at the certification: the document is intact, the
	// signatures are what is missing.
	if sha, _ := out["sha256"].(string); sha == "" {
		t.Fatalf("the report must name the document it checked: %v", out)
	}

	id := deliverOne(t, ts, admin)
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/envelopes/"+id+"/report", admin, "")
	if code != http.StatusOK {
		t.Fatalf("report: code %d out %v", code, out)
	}
	rep, _ = out["report"].(map[string]any)
	if rep["valid"] != true {
		t.Fatalf("report after the batch: %v", rep)
	}
	signers, _ := rep["signers"].([]any)
	// One signature field per party, plus the certification the batch laid down
	// before collecting them.
	if len(signers) != 3 {
		t.Fatalf("report signers: %d (%v)", len(signers), signers)
	}
	for _, s := range signers {
		info, _ := s.(map[string]any)
		if info["name"] == nil || info["time"] == nil {
			t.Fatalf("signer entry incomplete: %v", info)
		}
	}
	if rep["pages"] == nil {
		t.Fatalf("the report must state the page count: %v", rep)
	}

}

// ---------------------------------------------------------------------------
// Settings, clients, events, logout

func TestAdminSettingsAndClients(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)

	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/admin/clients", admin,
		`{"name":"reader","scopes":["envelope:read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create client: code %d detail %v", code, out["detail"])
	}
	key, _ := out["key"].(string)
	if key == "" {
		t.Fatalf("no client key in the answer: %v", out)
	}
	client, _ := out["client"].(map[string]any)
	if client == nil || client["id"] == nil {
		t.Fatalf("no client id in the answer: %v", out)
		// The key itself is not a bearer token: only a session minted from it is,
		// so a leaked key file cannot be waved at the API directly.
		code, _ = adminCode(t, ts, http.MethodGet, "/api/v1/admin/settings", key, "")
		if code != http.StatusUnauthorized {
			t.Fatalf("raw client key as a bearer token: want 401, got %d", code)
		}

		t.Fatalf("reader on clients: want 403, got %d", code)
	}

	// A client key mints a session token, and that token is only a reader.
	code, out = post(t, ts, "/api/v1/auth/token", `{"key":"`+key+`"}`, "")
	if code != http.StatusOK {
		t.Fatalf("token: code %d detail %v", code, out["detail"])
	}
	reader, _ := out["access"].(string)
	if reader == "" {
		t.Fatalf("no session token for the client: %v", out)
	}
	code, _ = adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", reader, "")
	if code != http.StatusForbidden {
		t.Fatalf("reader session on stats: want 403, got %d", code)
	}

	// A client cannot be given an admin scope: the API refuses the escalation.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/clients", admin,
		`{"name":"escalator","scopes":["envelope:read","admin:read"]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("escalating client: want 400, got %d (%v)", code, out["detail"])
	}
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/clients", admin, `{"name":"x"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("client with no scopes: want 400, got %d (%v)", code, out["detail"])
	}

	// A name already in use is a conflict the operator can act on, not a 500
	// carrying the driver's constraint text. "reader" was created at the top of
	// this test, so the collision costs no extra row.
	code, out = adminCode(t, ts, http.MethodPost, "/api/v1/admin/clients", admin,
		`{"name":"reader","scopes":["envelope:write"]}`)
	if code != http.StatusConflict {
		t.Fatalf("duplicate client name: want 409, got %d (%v)", code, out)
	}
	if c := codeOf(t, out); c != "name_taken" {
		t.Fatalf("duplicate client name code: want name_taken, got %q", c)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "reader") {
		t.Fatalf("the answer should name the client that is in the way: %v", out["error"])
	}

	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/settings", admin, "")
	if code != http.StatusOK {
		t.Fatalf("settings: code %d", code)
	}
	settings, _ := out["settings"].(map[string]any)
	for _, k := range []string{"tsa_url", "link_ttl", "mail_from", "smtp_host"} {
		if _, ok := settings[k]; !ok {
			t.Fatalf("settings missing %q: %v", k, settings)
		}
	}
	code, out = adminCode(t, ts, http.MethodPatch, "/api/v1/admin/settings", admin,
		`{"link_ttl":"48h","mail_from":"sign@x.test"}`)
	if code != http.StatusOK {
		t.Fatalf("patch settings: code %d detail %v", code, out["detail"])
	}
	settings, _ = out["settings"].(map[string]any)
	if settings["link_ttl"] != "48h" {
		t.Fatalf("link_ttl after the patch: %v", settings["link_ttl"])
	}
	if settings["mail_from"] != "sign@x.test" {
		t.Fatalf("mail_from after the patch: %v", settings["mail_from"])
	}
	if settings["tsa_url"] == "" {
		t.Fatalf("a patch must not drop the settings it did not touch: %v", settings)
	}
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/settings", admin, "")
	if code != http.StatusOK {
		t.Fatalf("settings after the patch: code %d", code)
	}
	if got, _ := out["settings"].(map[string]any)["link_ttl"]; got != "48h" {
		t.Fatalf("the patch did not stick: %v", out["settings"])
	}

	// A bad duration is a validation problem naming the field.
	code, out = adminCode(t, ts, http.MethodPatch, "/api/v1/admin/settings", admin, `{"link_ttl":"tomorrow"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("bad ttl: want 422, got %d (%v)", code, out["detail"])
	}
	if !strings.Contains(fmt.Sprintf("%v", out), "link_ttl") {
		t.Fatalf("the field error must name link_ttl: %v", out)
	}
	code, _ = adminCode(t, ts, http.MethodPatch, "/api/v1/admin/settings", admin, `{}`)
	if code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
		t.Fatalf("empty patch: want 422 or 400, got %d", code)
	}
	code, _ = adminCode(t, ts, http.MethodPatch, "/api/v1/admin/settings", admin, `{"tsa_public_key":"x"}`)
	if code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
		t.Fatalf("unknown setting: want 422 or 400, got %d", code)
	}
	// A settings change is in the audit log.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/events", admin, "")
	if code != http.StatusOK {
		t.Fatalf("events after a settings change: code %d", code)
	}
	if !strings.Contains(fmt.Sprintf("%v", out["events"]), "settings") {
		t.Fatalf("no settings entry in the audit log: %v", out["events"])
	}

	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/clients", admin, "")
	if code != http.StatusOK {
		t.Fatalf("clients list: code %d", code)
	}
	clients, _ := out["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("clients list: %d (%v)", len(clients), clients)
	}
	first, _ := clients[0].(map[string]any)
	if first["key"] != nil {
		t.Fatalf("the client list must not carry the key: %v", first)
	}
	clientID := first["id"]
	code, _ = adminCode(t, ts, http.MethodDelete, "/api/v1/admin/clients/"+strOf(clientID), admin, "")
	if code != http.StatusNoContent {
		t.Fatalf("revoke a client: want 204, got %d", code)
	}
	code, _ = adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", reader, "")
	if code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("revoked client session on stats: want 401 or 403, got %d", code)
	}
	code, _ = post(t, ts, "/api/v1/auth/token", `{"key":"`+key+`"}`, "")
	if code == http.StatusOK {
		t.Fatal("a revoked client key still mints a session")
	}
	code, _ = adminCode(t, ts, http.MethodDelete, "/api/v1/admin/clients/"+strOf(clientID), admin, "")
	if code != http.StatusNotFound {
		t.Fatalf("revoke an unknown client: want 404, got %d", code)
	}
}

func TestAdminEventsAndLogout(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/admin/events?envelope="+se.id, admin, "")
	if code != http.StatusOK {
		t.Fatalf("events for the envelope: code %d", code)
	}
	envEvents, _ := out["events"].([]any)
	if len(envEvents) == 0 {
		t.Fatalf("no events for the envelope: %v", out)
	}
	if out["total"] == nil {
		t.Fatal("the audit log must report a total, for the paging UI")
	}
	seen := map[string]bool{}
	for _, e := range envEvents {
		ev, _ := e.(map[string]any)
		if ev["actor"] == nil || ev["kind"] == nil {
			t.Fatalf("event incomplete: %v", ev)
		}
		if ev["at"] == nil && ev["created_at"] == nil {
			t.Fatalf("event has no timestamp: %v", ev)
		}
		seen[ev["kind"].(string)] = true
	}
	// Whatever the state machine calls its steps, the operator must be able to
	// see that the envelope was created and that it went out.
	if !seen["created"] {
		t.Fatalf("the audit log has no record of the create: %v", seen)
	}
	if !seen["sent"] && !seen["transition"] {
		t.Fatalf("the audit log has no record of the send: %v", seen)
	}

	all, _ := out["events"].([]any)
	if len(all) == 0 {
		t.Fatal("the audit log is empty")
	}
	var last string
	for i, e := range all {
		at, _ := e.(map[string]any)["at"].(string)
		if i > 0 && at > last {
			t.Fatalf("events are not newest first: %s after %s", at, last)
		}
		last = at
	}
	if len(all) > 100 {
		t.Fatalf("a page is 100 events, got %d", len(all))
	}
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/events?offset=1", admin, "")
	if code != http.StatusOK {
		t.Fatalf("offset page: code %d", code)
	}
	if len(out["events"].([]any)) != len(all)-1 {
		t.Fatalf("offset 1 should drop exactly one event: %d vs %d",
			len(out["events"].([]any)), len(all))
	}
	// An envelope id that matches nothing answers an empty log with a zero
	// total: the paging UI reads the same shape whether or not the id is real.
	code, out = adminCode(t, ts, http.MethodGet, "/api/v1/admin/events?envelope=not-an-id", admin, "")
	if code != http.StatusOK {
		t.Fatalf("unknown envelope filter: want 200, got %d", code)
	}
	if out["events"] == nil || len(out["events"].([]any)) != 0 || out["total"] != float64(0) {
		t.Fatalf("an unknown envelope must answer an empty log: %v", out)
	}

	code, _ = adminCode(t, ts, http.MethodPost, "/api/v1/admin/logout", admin, "")
	if code != http.StatusNoContent {
		t.Fatalf("logout: code %d", code)
	}
	code, _ = adminCode(t, ts, http.MethodGet, "/api/v1/admin/stats", admin, "")
	if code == http.StatusOK {
		t.Fatal("the access token still works after logout")
	}
	// A second logout with the same token is a 401: the token died on the
	// first call, so the request never reaches the handler. A 204 here would
	// mean the revocation had not taken effect.
	code, _ = adminCode(t, ts, http.MethodPost, "/api/v1/admin/logout", admin, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("a second logout with a dead token: want 401, got %d", code)
	}
}
