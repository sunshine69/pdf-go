package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The signing token is the party's credential: a bearer of a link can sign.
// A path is not a log field, it is a channel to whoever reads the log, and the
// service writes it in three places. This test is the rule, stated as a check.

const probeToken = "txglfdh6ins3fp7mb5jicqdkfkx222pytzopnslbuh436mbjki4q"

// TestUnroutedSigningVerbDoesNotLogTheToken is the regression for the one place
// the service logged a raw request path. A verb that is not routed on a signing
// path lands in the catch-all, which used to log r.URL.Path in full: a probe of
// DELETE /api/v1/sign/<live token>/consent wrote a live signing link into the
// log, where the log shipper, journalctl, and any support bundle carry it.
func TestUnroutedSigningVerbDoesNotLogTheToken(t *testing.T) {
	var buf bytes.Buffer
	cfg := testConfig(t)
	cfg.LogPath = "" // the capture buffer is the log
	s := newServer(cfg, slog.New(slog.NewJSONHandler(&buf, nil)), nil)
	ts := httptest.NewServer(s.withDefaults(s.mux))
	defer ts.Close()

	for _, verb := range []string{http.MethodDelete, http.MethodPut,
		http.MethodPatch, http.MethodHead, http.MethodOptions} {
		req, err := http.NewRequest(verb, ts.URL+"/api/v1/sign/"+probeToken+"/consent", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		res.Body.Close()
	}
	log := buf.String()

	if strings.Contains(log, probeToken) {
		t.Fatalf("the log carries the signing token in the clear:\n%s", log)
	}
	if !strings.Contains(log, "/api/v1/sign/[token]/consent") {
		t.Fatalf("the refusal is not in the log, so the audit trail lost the probe:\n%s", log)
	}
}

// TestRedactPathShapes pins the redaction itself. Every route family that
// carries a credential in the path has to be covered, and a path that is not
// one of them must survive intact, because the log is how an operator finds a
// request.
func TestRedactPathShapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/v1/sign/" + probeToken + "/consent", "/api/v1/sign/[token]/consent"},
		{"/api/v1/sign/" + probeToken + "/document", "/api/v1/sign/[token]/document"},
		{"/api/v1/sign/" + probeToken, "/api/v1/sign/[token]"},
		{"/s/" + probeToken, "/s/[token]"},
		{"/api/v1/envelopes/ae916bfe3d6d001462ce6c8108deb3ac",
			"/api/v1/envelopes/ae916bfe3d6d001462ce6c8108deb3ac"}, // not a credential
		{"/healthz", "/healthz"},
		{"", "/"},
	}
	for _, c := range cases {
		if got := redactPath(c.in); got != c.want {
			t.Errorf("redactPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAccessLogNeverCarriesASecret is the same rule across the whole signing
// family, driven by the real routes: the access line, the cookie line, and the
// authorization line. A link token, a session secret, and a bearer token are
// three different credentials and none of them belongs in a log record.
func TestAccessLogNeverCarriesASecret(t *testing.T) {
	var buf bytes.Buffer
	cfg := testConfig(t)
	cfg.LogPath = ""
	s := newServer(cfg, slog.New(slog.NewJSONHandler(&buf, nil)), nil)
	ts := httptest.NewServer(s.withDefaults(s.mux))
	defer ts.Close()

	const session = "9f2c1a7de4b03c8e5a6d1f0b7c2e9a4d8b3f6c1a0e5d2b7f4c9a1e6d3b8f05c2"
	const bearer = "eyJhbGciOiBFZDQ0S0F9ImtpZCI6ImprMV9kby0xMjM0In0"
	for _, path := range []string{
		"/api/v1/sign/" + probeToken + "/envelope",
		"/api/v1/sign/" + probeToken + "/document",
		"/s/" + probeToken,
	} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: "signsrv_session", Value: session})
		req.Header.Set("Authorization", "Bearer "+bearer)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		res.Body.Close()
	}
	log := buf.String()
	for _, secret := range []string{probeToken, session, bearer} {
		if strings.Contains(log, secret) {
			t.Fatalf("a credential is in the log records:\n%s", log)
		}
	}
	// The cookie names survive so an operator can see a cookie was presented;
	// the values do not.
	if !strings.Contains(log, "signsrv_session") {
		t.Fatalf("the cookie name is gone, so the audit trail lost the claim:\n%s", log)
	}
}

// TestLogRecordsAreValidJSON is cheap and pays for itself: a log line built by
// string concatenation breaks every shipper, and redactPath is now on the path
// of every unrouted request.
func TestLogRecordsAreValidJSON(t *testing.T) {
	var buf bytes.Buffer
	cfg := testConfig(t)
	cfg.LogPath = ""
	s := newServer(cfg, slog.New(slog.NewJSONHandler(&buf, nil)), nil)
	ts := httptest.NewServer(s.withDefaults(s.mux))
	defer ts.Close()
	for _, path := range []string{"/nope", "/api/v1/sign/x/consent", "/s/abc", "/healthz"} {
		res, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		res.Body.Close()
	}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	n := 0
	for {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("record %d is not JSON: %v\n%s", n+1, err, buf.String())
		}
		if _, ok := rec["msg"]; !ok {
			t.Fatalf("record %d has no msg: %v", n+1, rec)
		}
		n++
	}
	if n == 0 {
		t.Fatalf("nothing was logged:\n%s", buf.String())
	}
}
