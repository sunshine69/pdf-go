package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// ---------------------------------------------------------------------------
// A cookie-aware client.
//
// The signing endpoints set a session cookie, and every later call on the link
// has to carry it back. The jar here is the party's browser.

type cookieJar struct{ c []http.Cookie }

func newJar() *cookieJar { return &cookieJar{c: []http.Cookie{}} }

func (j *cookieJar) postJSON(ts *httptest.Server, url, body string) (*http.Response, []byte, error) {
	return j.roundTrip(ts, http.MethodPost, url, body, "application/json")
}

func (j *cookieJar) getJSON(ts *httptest.Server, url string) (*http.Response, []byte, error) {
	return j.roundTrip(ts, http.MethodGet, url, "", "")
}

func (j *cookieJar) roundTrip(ts *httptest.Server, method, url, body, ctype string) (*http.Response, []byte, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+url, r)
	if err != nil {
		return nil, nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for i := range j.c {
		req.AddCookie(&j.c[i])
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	for _, ck := range res.Cookies() {
		if ck.Value != "" {
			j.c = append(j.c, *ck)
		}
	}
	return res, b, nil
}

func (j *cookieJar) count() int { return len(j.c) }

// adminCall signs a request with the admin bearer. The admin endpoints need a
// token, and the signing tests have to drive them to set up a request.
func adminCall(t *testing.T, ts *httptest.Server, admin, method, url, body string) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+admin)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, b
}

// ---------------------------------------------------------------------------
// Building a request a party can act on.
//
// Every test here needs a live envelope with two parties and a link token for
// each. Send is where the tokens appear, so a test that needs a token has to
// run it: the create response has none.

type signEnv struct {
	id     string
	dsha   string // the base revision digest, as the envelope reports it
	tokens []string
}

// newSignEnv creates an envelope with Ann and Bob and sends it. Create has
// already certified the document, so send is the step that stamps the party
// tokens, enqueues the invitations, and returns the links in signing order.
func newSignEnv(t *testing.T, ts *httptest.Server, admin string) *signEnv {
	t.Helper()
	template := sample1(t)
	se := &signEnv{}

	code, out := createRequest(t, ts, admin, template, createFields(t, template,
		`[{"email":"ann@x.test","name":"Ann","order":1},{"email":"bob@x.test","name":"Bob","order":2}]`))
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	env, _ := out["envelope"].(map[string]any)
	if env == nil {
		t.Fatalf("create returned no envelope: %v", out)
	}
	se.id, _ = env["id"].(string)

	// A signer is shown the certified revision, and a consent is bound to its
	// digest. The chain is template, filled, certified.
	envrow, err := storeOf(t, ts).GetEnvelope(context.Background(), se.id)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	se.dsha = envrow.CurrentSHA
	revs, err := storeOf(t, ts).ListRevisions(context.Background(), se.id)
	if err != nil || len(revs) != 3 {
		t.Fatalf("the envelope does not have three revisions: %v %d", err, len(revs))
	}

	res, body := adminCall(t, ts, admin, http.MethodPost, "/api/v1/envelopes/"+se.id+"/send", `{}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("send: %d %s", res.StatusCode, body)
	}
	var sent struct {
		Links []struct {
			Order int    `json:"order"`
			Token string `json:"token"`
		} `json:"links"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("send body: %v (%s)", err, body)
	}
	se.tokens = make([]string, len(sent.Links))
	for _, l := range sent.Links {
		if l.Order < 1 || l.Order > len(se.tokens) {
			t.Fatalf("link order %d is out of range", l.Order)
		}
		se.tokens[l.Order-1] = l.Token
	}
	if len(se.tokens) != 2 {
		t.Fatalf("send returned %d links, want 2", len(se.tokens))
	}
	return se
}

// storeOf reaches the store the test server is built on. envelopeServer
// registers it, so a helper can read the database without rebuilding anything.
func storeOf(t *testing.T, ts *httptest.Server) *signstore.Store {
	t.Helper()
	s, ok := stores[ts]
	if !ok {
		t.Fatal("no store registered for this test server")
	}
	return s
}

// stores remembers which store each test server was built on.
var stores = map[*httptest.Server]*signstore.Store{}

// signAs claims a session for the party the first token belongs to.
func signAs(t *testing.T, ts *httptest.Server, se *signEnv, email string) *cookieJar {
	t.Helper()
	jar := newJar()
	res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"`+email+`"}`)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("claim: status %d body %s", res.StatusCode, body)
	}
	return jar
}

// consentBody is the JSON a signing page posts.
func consentBody(text string, consent bool, dsha, image string) string {
	b := `{"signature_text":"` + text + `","consent":` + fmt.Sprint(consent) +
		`,"document_sha":"` + dsha + `"`
	if image != "" {
		b += `,"image":"` + image + `"`
	}
	return b + "}"
}

// jsonOf decodes an answer.
func jsonOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("answer is not JSON: %s", body)
	}
	return out
}

// ---------------------------------------------------------------------------
// Claim

func TestClaimWithCorrectEmail(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	res, body, err := newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"ann@x.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("claim: status %d body %s", res.StatusCode, body)
	}
	out := jsonOf(t, body)
	if out["ok"] != true {
		t.Fatalf("claim is not ok: %s", body)
	}
	if out["name"] != "Ann" {
		t.Fatalf("claim name = %v, want Ann", out["name"])
	}
	if _, ok := out["expires_at"].(string); !ok {
		t.Fatalf("claim has no expires_at: %s", body)
	}
	for k := range out {
		if k == "email" {
			t.Fatalf("the claim echoes the address: %s", body)
		}
	}
	// The session cookie, as step 03 specifies it: HttpOnly, SameSite=Strict,
	// the signing path, and a lifetime bound to the link. Secure is off because
	// this server runs in dev, where a Secure cookie would never be sent.
	var set bool
	for _, ck := range res.Cookies() {
		if ck.MaxAge <= 0 {
			t.Fatalf("the session cookie has no Max-Age: %+v", ck)
		}
		if ck.Path != "/api/v1/sign/" {
			t.Fatalf("the session cookie path is %q", ck.Path)
		}
		if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
			t.Fatalf("the session cookie flags: %+v", ck)
		}
		set = true
	}
	if !set {
		t.Fatalf("no session cookie: %v", res.Header.Values("Set-Cookie"))
	}
	// The party is claimed, and the trail carries the claim with the IP.
	p, err := store.GetPartyByTokenHash(context.Background(), signflow.HashLink(se.tokens[0]))
	if err != nil {
		t.Fatalf("party: %v", err)
	}
	if p.Status != signstore.PartyClaimed {
		t.Fatalf("party status = %s, want claimed", p.Status)
	}
	if ev := eventOf(t, store, se.id, "claimed"); ev == nil {
		t.Fatalf("no claim event")
	} else if !strings.Contains(ev.Payload, `"ip"`) {
		t.Fatalf("the claim event does not carry the IP: %s", ev.Payload)
	}
}

// A party that types its address in capitals, or with spaces around it, is the
// same party.
func TestClaimIsCaseAndSpaceInsensitive(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	res, body, _ := newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"  ANN@X.TEST  "}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("claim: status %d body %s", res.StatusCode, body)
	}
}

func TestClaimWithWrongEmail(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := newJar()
	res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"eve@x.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", res.StatusCode, body)
	}
	// The refusal names no address: neither the probed one nor the invited one.
	low := strings.ToLower(string(body))
	if strings.Contains(low, "eve@x.test") || strings.Contains(low, "ann@x.test") {
		t.Fatalf("the refusal leaks an address: %s", body)
	}
	if jar.count() != 0 {
		t.Fatalf("a refused claim set a cookie")
	}
	// The refusal is logged against the party the token belongs to, with the
	// IP: a token used from an unexpected address leaves a trace.
	ev := eventOf(t, store, se.id, "claim_failed")
	if ev == nil {
		t.Fatalf("no claim_failed event")
	}
	if !strings.Contains(ev.Payload, `"ip"`) {
		t.Fatalf("the refusal does not record the IP: %s", ev.Payload)
	}
	if strings.Contains(ev.Payload, "eve@x.test") {
		t.Fatalf("the audit row stores the probed address: %s", ev.Payload)
	}
	p := partyByToken(t, store, se.tokens[0])
	if ev.Actor != "party:"+p.ID {
		t.Fatalf("the refusal is logged against %q, want the party the token belongs to",
			ev.Actor)
	}
}

// An unknown token has no party to log against. The answer is 404, and the
// trail does not grow.
func TestClaimUnknownTokenLeavesNoTrace(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	before := eventCount(t, store, se.id)
	res, body, err := newJar().postJSON(ts, "/api/v1/sign/nosuchtoken/claim",
		`{"email":"a@b.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", res.StatusCode, body)
	}
	if got := eventCount(t, store, se.id); got != before {
		t.Fatalf("an unknown token grew the trail: %d -> %d", before, got)
	}
}

// A session belongs to one envelope. A cookie minted on link A cannot be used
// on link B, even when both are issued to the same address.
func TestClaimSessionIsEnvelopeScoped(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	seA := newSignEnv(t, ts, admin)
	seB := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, seA, "ann@x.test")
	res, body, err := jar.getJSON(ts, "/api/v1/sign/"+seB.tokens[0]+"/envelope")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cross-envelope: status %d body %s", res.StatusCode, body)
	}
	if jsonOf(t, body)["my"] != nil {
		t.Fatalf("a session from another link opened a slot here: %s", body)
	}
	if _, ok := jsonOf(t, body)["parties"]; ok {
		t.Fatalf("a session from another link opened the party list: %s", body)
	}
}

// A party that has signed is done. Its session is dead, and its claim is
// refused: the claim cannot be re-run to get a fresh cookie.
func TestClaimAfterConsentIsRefused(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, se.dsha, ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("consent: %d %s", res.StatusCode, body)
	}
	res, body, _ = newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"ann@x.test"}`)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("re-claim after consent: status %d body %s", res.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// Envelope view

// Before the claim the view is the title and the expiry, and nothing else. A
// link is a bearer credential, and the party list belongs to the people named
// on it.
func TestEnvelopeViewBeforeClaim(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	res, body, err := newJar().getJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/envelope")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	out := jsonOf(t, body)
	if out["title"] != "NDA for review" {
		t.Fatalf("title = %v", out["title"])
	}
	if _, ok := out["expires_at"].(string); !ok {
		t.Fatalf("no expires_at: %s", body)
	}
	for _, k := range []string{"parties", "my", "document_sha", "status", "serial"} {
		if _, ok := out[k]; ok {
			t.Fatalf("the pre-claim view leaks %q: %s", k, body)
		}
	}
	if strings.Contains(string(body), "@") {
		t.Fatalf("the pre-claim view contains an address: %s", body)
	}
}

// After the claim the party sees the request: the title, the document digest,
// its own slot, and the other parties by name.
func TestEnvelopeViewAfterClaim(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, err := jar.getJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/envelope")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	out := jsonOf(t, body)
	if out["document_sha"] != se.dsha {
		t.Fatalf("document_sha = %v, want %s", out["document_sha"], se.dsha)
	}
	if out["status"] != string(signstore.StatusSent) {
		t.Fatalf("status = %v, want sent", out["status"])
	}
	my, ok := out["my"].(map[string]any)
	if !ok {
		t.Fatalf("no my slot: %s", body)
	}
	if my["name"] != "Ann" || my["order"] != 1.0 {
		t.Fatalf("my slot: %v", my)
	}
	parties, ok := out["parties"].([]any)
	if !ok || len(parties) != 2 {
		t.Fatalf("parties: %s", body)
	}
	if !strings.Contains(string(body), "Bob") {
		t.Fatalf("the other party is not named: %s", body)
	}
	// Party emails are never exposed to other parties.
	if strings.Contains(string(body), "@") {
		t.Fatalf("the view exposes addresses: %s", body)
	}
}

// The party's own view after signing says so.
func TestEnvelopeViewAfterConsent(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, se.dsha, ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("consent: %d %s", res.StatusCode, body)
	}
	// The consent destroyed the session that proved this party's address, so the
	// view is the one a party without a session gets: the title and the deadline,
	// and nothing about the parties. What the consent did is on the party row.
	res, body, _ = jar.getJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/envelope")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("view: %d %s", res.StatusCode, body)
	}
	if jsonOf(t, body)["my"] != nil {
		t.Fatalf("a dead session still shows a slot: %s", body)
	}
	if _, ok := jsonOf(t, body)["parties"]; ok {
		t.Fatalf("a dead session still shows the party list: %s", body)
	}
}

// ---------------------------------------------------------------------------
// Document

// A signer is shown the certified revision, and the digest the view reports is
// the digest of the bytes sent. This pair is what makes a consent provable:
// the consent is about the exact bytes the party reviewed.
func TestSignerDocumentIsTheCertifiedRevision(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, err := jar.getJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/document")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("document: status %d body %s", res.StatusCode, body)
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Fatalf("the signer's document is not a PDF")
	}
	if sha256Of(body) != se.dsha {
		t.Fatalf("the signer was shown a different document: %s, envelope says %s",
			sha256Of(body), se.dsha)
	}
	if got := res.Header.Get("Content-Disposition"); !strings.HasPrefix(got, "inline") {
		t.Fatalf("Content-Disposition = %q, want inline", got)
	}
	if !strings.Contains(res.Header.Get("Content-Disposition"), "nda") {
		t.Fatalf("the filename is not the request's title: %q",
			res.Header.Get("Content-Disposition"))
	}
	if res.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("Content-Type = %q", res.Header.Get("Content-Type"))
	}
	if !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", res.Header.Get("Cache-Control"))
	}
	// The base revision is the uploaded document, and it is the one the
	// envelope is showing.
	rev, err := store.GetRevisionOfEnvelope(context.Background(), se.id, se.dsha)
	if err != nil {
		t.Fatalf("the envelope does not have the digest it shows: %v", err)
	}
	if rev.Kind != "certified" {
		t.Fatalf("the signer is shown the %q revision, want certified", rev.Kind)
	}
}

// The document is the party's, not the bearer token's.
func TestSignerDocumentNeedsSession(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	res, body, err := newJar().getJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/document")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d body %s, want 401", res.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// Consent

func TestConsentHappyPath(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	ctx := context.Background()
	before := len(mustRevisions(t, store, se.id))
	jar := signAs(t, ts, se, "ann@x.test")
	res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, se.dsha, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("consent: status %d body %s", res.StatusCode, body)
	}
	out := jsonOf(t, body)
	if out["ok"] != true || out["all_consented"] != false {
		t.Fatalf("consent answer: %s", body)
	}
	if out["status"] != string(signstore.StatusCollecting) {
		t.Fatalf("status = %v, want collecting", out["status"])
	}
	// The consent row: text, time, IP, user agent, and the document it is about.
	p := partyByToken(t, store, se.tokens[0])
	c, err := store.GetConsentByParty(ctx, p.ID)
	if err != nil {
		t.Fatalf("the consent row is missing: %v", err)
	}
	if c.SignatureText != "I read it" {
		t.Fatalf("consent text = %q", c.SignatureText)
	}
	if c.DocumentSHA != se.dsha {
		t.Fatalf("consent is bound to %q, want the certified sha %s", c.DocumentSHA, se.dsha)
	}
	if c.ConsentAt == "" || c.IP == "" || c.UserAgent == "" {
		t.Fatalf("the consent row is missing the when and the who: %+v", c)
	}
	if p.Status != signstore.PartyConsented {
		t.Fatalf("party status = %s, want consented", p.Status)
	}
	// The session is dead: the cookie that proved it opens nothing but the
	// pre-claim view.
	res, body, _ = jar.getJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/envelope")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the session survived the consent: %d %s", res.StatusCode, body)
	}
	if jsonOf(t, body)["my"] != nil {
		t.Fatalf("a dead session still shows a slot: %s", body)
	}
	// No PDF was written. Consent is data.
	if got := len(mustRevisions(t, store, se.id)); got != before {
		t.Fatalf("consent added a revision: %d -> %d", before, got)
	}
	if eventOf(t, store, se.id, "consent") == nil {
		t.Fatalf("no consent event on the trail")
	}
}

// Consent is bound to the bytes: a consent about a digest the envelope is not
// holding is a consent about a document the service is not holding.
func TestConsentIsBoundToTheCertifiedDigest(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, strings.Repeat("a", 64), ""))
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("stale digest: status %d body %s", res.StatusCode, body)
	}
	if len(mustRevisions(t, store, se.id)) != 3 {
		t.Fatalf("a refused consent changed the chain")
	}
}

// One consent per party.
func TestConsentTwiceIsRefused(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, se.dsha, ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first consent: %d %s", res.StatusCode, body)
	}
	// The session is gone, so the second attempt arrives without a cookie. The
	// party is closed either way.
	res, body, _ = jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it again", true, se.dsha, ""))
	if res.StatusCode == http.StatusOK {
		t.Fatalf("a second consent was accepted: %s", body)
	}
	if len(mustRevisions(t, store, se.id)) != 3 {
		t.Fatalf("the second consent changed the chain")
	}
}

// The checkbox has to be checked, and the words have to be the party's own.
func TestConsentValidatesTheDeclaration(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	cases := []struct{ body, why string }{
		{consentBody("I read it", false, se.dsha, ""), "consent false"},
		{consentBody("", true, se.dsha, ""), "empty signature text"},
		{consentBody("   ", true, se.dsha, ""), "blank signature text"},
		{consentBody("a\nb", true, se.dsha, ""), "newline in the text"},
		{consentBody("a\tb", true, se.dsha, ""), "tab in the text"},
		{consentBody(strings.Repeat("x", 121), true, se.dsha, ""), "121 characters"},
	}
	for _, c := range cases {
		jar := signAs(t, ts, se, "ann@x.test")
		res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent", c.body)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status %d body %s, want 400", c.why, res.StatusCode, body)
		}
	}
	// A refusal leaves nothing behind: no consent row, and the party is still
	// where it was.
	if n := consentCount(t, store, se.id); n != 0 {
		t.Fatalf("a refused consent wrote %d consent rows", n)
	}
	if p := partyByToken(t, store, se.tokens[0]); p.Status != signstore.PartyClaimed {
		t.Fatalf("a refused consent moved the party to %s", p.Status)
	}

	// 120 characters is the limit, and it is inclusive.
	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody(strings.Repeat("x", 120), true, se.dsha, ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("120 characters refused: %d %s", res.StatusCode, body)
	}
}

// consentCount counts the consent rows on an envelope.
func consentCount(t *testing.T, store *signstore.Store, envelopeID string) int {
	t.Helper()
	var n int
	if err := store.DB().QueryRow(`select count(*) from consents where envelope_id = ?`,
		envelopeID).Scan(&n); err != nil {
		t.Fatalf("consent count: %v", err)
	}
	return n
}

// A signature image is a picture, so it is checked as one.
func TestConsentSignatureImageRules(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	big := make([]byte, 60*1024)
	for i := range big {
		big[i] = 'A'
	}
	cases := []struct{ image, why string }{
		{base64.StdEncoding.EncodeToString(big), "over the size ceiling"},
		{"not base64 at all!!", "malformed base64"},
		{base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 a pdf is not a picture")), "not an image"},
	}
	for _, c := range cases {
		jar := signAs(t, ts, se, "ann@x.test")
		res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
			consentBody("I read it", true, se.dsha, c.image))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("image %s: status %d body %s, want 400", c.why, res.StatusCode, body)
		}
	}
	// A real image is stored, and its digest is on the consent row.
	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, se.dsha, pngBase64(t, 40, 20)))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("png consent: %d %s", res.StatusCode, body)
	}
	c, err := store.GetConsentByParty(context.Background(), partyByToken(t, store, se.tokens[0]).ID)
	if err != nil || c.ImageSHA == "" {
		t.Fatalf("the signature image is not recorded: %+v %v", c, err)
	}
}

// Declining is a decision, not an error: 200, and the request is over.
func TestDeclineRefusesTheEnvelope(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, err := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/decline",
		`{"reason":"not comfortable"}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("decline: status %d body %s", res.StatusCode, body)
	}
	env, err := store.GetEnvelope(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != signstore.StatusFailed {
		t.Fatalf("envelope = %s, want failed", env.Status)
	}
	ev := eventOf(t, store, se.id, "declined")
	if ev == nil {
		t.Fatalf("no decline event for the admin")
	}
	if !strings.Contains(ev.Payload, "not comfortable") {
		t.Fatalf("the decline event does not carry the reason: %s", ev.Payload)
	}
	// Every other link on the request is closed.
	res, body, _ = newJar().getJSON(ts, "/api/v1/sign/"+se.tokens[1]+"/envelope")
	if res.StatusCode != http.StatusGone {
		t.Fatalf("declined request: status %d body %s, want 410", res.StatusCode, body)
	}
	res, body, _ = newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"ann@x.test"}`)
	if res.StatusCode != http.StatusGone {
		t.Fatalf("claim on a declined request: status %d body %s, want 410",
			res.StatusCode, body)
	}
	// The other party's link resolves, so the closed request can answer honestly.
	res, body, _ = newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[1]+"/claim",
		`{"email":"bob@x.test"}`)
	if res.StatusCode != http.StatusGone {
		t.Fatalf("claim on the other party's link: status %d body %s, want 410",
			res.StatusCode, body)
	}
}

func TestDeclineTwiceIsRefused(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/decline", `{"reason":"no"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("decline: %d %s", res.StatusCode, body)
	}
	res, body, _ = jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/decline", `{"reason":"no"}`)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("a second decline was accepted: %s", body)
	}
	if len(mustRevisions(t, store, se.id)) != 3 {
		t.Fatalf("a declined request grew the chain")
	}
}

// An expired link is gone, and so is consent on it. The expiry is set in the
// database, so this runs against the same rule the sweep uses.
func TestConsentOnExpiredLinkIsGone(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	if _, err := store.DB().Exec(`update envelopes set expires_at = '2020-01-01T00:00:00Z'
		where id = ?`, se.id); err != nil {
		t.Fatal(err)
	}
	res, body, _ := newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/claim",
		`{"email":"ann@x.test"}`)
	if res.StatusCode != http.StatusGone {
		t.Fatalf("claim on an expired link: %d %s, want 410", res.StatusCode, body)
	}
	res, body, _ = newJar().postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("I read it", true, se.dsha, ""))
	if res.StatusCode != http.StatusGone {
		t.Fatalf("consent on an expired link: %d %s, want 410", res.StatusCode, body)
	}
	if len(mustRevisions(t, store, se.id)) != 3 {
		t.Fatalf("a consent on an expired link changed the chain")
	}
}

// The last consent queues the batch. Exactly one batch, and it is queued, not
// run: no signing happens inside an HTTP request.
func TestLastConsentEnqueuesOneBatch(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)
	se := newSignEnv(t, ts, admin)

	before := batchCount(t, store, se.id)
	jar := signAs(t, ts, se, "ann@x.test")
	res, body, _ := jar.postJSON(ts, "/api/v1/sign/"+se.tokens[0]+"/consent",
		consentBody("Ann read it", true, se.dsha, ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("consent A: %d %s", res.StatusCode, body)
	}
	if jsonOf(t, body)["all_consented"] == true {
		t.Fatalf("the first consent claims all parties are done")
	}
	if got := batchCount(t, store, se.id); got != before {
		t.Fatalf("the first consent queued a batch: %d -> %d", before, got)
	}

	jarB := newJar()
	res, body, err := jarB.postJSON(ts, "/api/v1/sign/"+se.tokens[1]+"/claim",
		`{"email":"bob@x.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("claim B: %d %s", res.StatusCode, body)
	}
	res, body, _ = jarB.postJSON(ts, "/api/v1/sign/"+se.tokens[1]+"/consent",
		consentBody("Bob read it", true, se.dsha, ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("consent B: %d %s", res.StatusCode, body)
	}
	if jsonOf(t, body)["all_consented"] != true {
		t.Fatalf("the last consent does not say all_consented: %s", body)
	}
	got := batchCount(t, store, se.id)
	if got != before+1 {
		t.Fatalf("batches: %d -> %d, want exactly one new", before, got)
	}
}

func batchCount(t *testing.T, store *signstore.Store, envelopeID string) int {
	t.Helper()
	var n int
	if err := store.DB().QueryRow(`select count(*) from batch_queue where envelope_id = ?`,
		envelopeID).Scan(&n); err != nil {
		t.Fatalf("batch count: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// shape

// The consent body is the party's words, the checkbox, the picture, and the
// digest it was shown. Nothing in it is a power: a party cannot name its
// signer, choose a key, supply a certificate, pick a TSA, place a rectangle,
// or claim to be somebody else.
func TestConsentInputCarriesNoPower(t *testing.T) {
	typ := reflect.TypeOf(signflow.ConsentInput{})
	allowed := map[string]bool{
		"SignatureText": true, "Consent": true, "Image": true,
		"DocumentSHA": true, "IP": true, "UserAgent": true,
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !allowed[f.Name] {
			t.Fatalf("ConsentInput has field %q, which is not the party's to set", f.Name)
		}
	}
	for _, banned := range []string{"Name", "Email", "Order", "Certificate", "Key",
		"TSA", "Rect", "Actor", "Fields"} {
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Name == banned {
				t.Fatalf("ConsentInput carries %q", banned)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// helpers

// eventOf returns the last event of a kind on the envelope, or nil.
func eventOf(t *testing.T, store *signstore.Store, envelopeID, kind string) *signstore.Event {
	t.Helper()
	events, err := store.ListEvents(context.Background(), envelopeID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var found *signstore.Event
	for i, e := range events {
		if e.Kind == kind {
			found = &events[i]
		}
	}
	return found
}

// eventCount is the length of an envelope's audit trail.
func eventCount(t *testing.T, store *signstore.Store, envelopeID string) int {
	t.Helper()
	var n int
	if err := store.DB().QueryRow(`select count(*) from events where envelope_id = ?`,
		envelopeID).Scan(&n); err != nil {
		t.Fatalf("event count: %v", err)
	}
	return n
}

func partyByToken(t *testing.T, store *signstore.Store, token string) *signstore.Party {
	t.Helper()
	p, err := store.GetPartyByTokenHash(context.Background(), signflow.HashLink(token))
	if err != nil {
		t.Fatalf("party for the token: %v", err)
	}
	return p
}

// pngBase64 is a real PNG, base64'd, for the signature image field.
func pngBase64(t *testing.T, w, h int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 20, G: 30, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
