package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/sunshine69/pdf-go/internal/schema"
	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signfill"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The envelope endpoints, tested through HTTP: the create request, the state
// the response reports, and the download headers. These are the tests the
// acceptance list names, run against the real signing service with a local
// TSA (tests must not use the network).

// envelopeServer builds a server with a store, a keystore, and a local TSA.
func envelopeServer(t *testing.T, cfg *Config) (*httptest.Server, *signstore.Store) {
	t.Helper()
	cfg.TSAURL = testTSA(t)
	ctx := context.Background()
	db, err := signstore.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signstore.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := signstore.NewStore(db, cfg.StorageDir)
	t.Cleanup(func() { store.Close() })

	hash, err := signauth.HashPassword("test-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddAdmin(ctx, "admin@example.test", hash, "admin"); err != nil {
		t.Fatal(err)
	}

	s := newServer(cfg, logger(cfg), store)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	if s.signer == nil {
		t.Fatal("the signing service was not built; the keystore is not usable")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)
	stores[ts] = store
	return ts, store
}

// testTSA is a timestamp authority in the process. The certificate is self
// signed, and the signer accepts it because signpdf trusts the TSA it is
// pointed at.
func testTSA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signsrv test TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/tsr", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ts := timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now().UTC(),
			Accuracy:          time.Second,
			SerialNumber:      big.NewInt(7),
			Policy:            asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 1},
			Nonce:             req.Nonce,
			Certificates:      []*x509.Certificate{cert},
			AddTSACertificate: true,
		}
		resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/tsr"
}

// sample1 is the template every create test uses.
func sample1(t *testing.T) []byte {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "sample1.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("testdata/sample1.pdf missing: %v", err)
	}
	return b
}

// createRequest sends the multipart body and returns the decoded answer with
// its status. The spec is built to fill one text field, so the fill path is
// exercised, not just the plumbing.
func createRequest(t *testing.T, ts *httptest.Server, token string, template []byte, fields map[string]string) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("template", "template.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(template); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", ts.URL+"/api/v1/envelopes", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := decode(t, res)
	return res.StatusCode, out
}

func decode(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("answer is not JSON: %s", string(body))
	}
	return out
}

// createFields is the standard create form: title, parties, and a fill spec
// that writes the first text field of the template. The field name comes from
// the extract, so the test fills a field that exists.
func createFields(t *testing.T, template []byte, parties string) map[string]string {
	t.Helper()
	name := firstTextField(t, template)
	return map[string]string{
		"title":      "NDA for review",
		"expires_in": "48h",
		"parties":    parties,
		"spec":       `{"fill":{"values":{"` + name + `":"filed"}},"widget":{"page":1,"y":60},"subject":"Sign","message":"Please sign"}`,
	}
}

// firstTextField names the first fillable text field of a template.
func firstTextField(t *testing.T, template []byte) string {
	t.Helper()
	s, err := signfill.Extract(template)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range s.Fields {
		if f.Type == schema.TypeText {
			return f.Name
		}
	}
	t.Fatal("the template has no text field")
	return ""
}

// accessOf logs in and returns the access token. The create endpoint needs
// envelope:write, which an admin carries.
func accessOf(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	res, err := ts.Client().Post(ts.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"email":"admin@example.test","password":"test-admin-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body := decode(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %v", res.StatusCode, body)
	}
	access, _ := body["access"].(string)
	if access == "" {
		t.Fatal("login returned no access token")
	}
	return access
}

// 1. Create -> 201, status ready, 3 revisions, plaintext links in the response
// only.
func TestCreateViaAPI(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	created, out := createRequest(t, ts, access, sample1(t),
		createFields(t, sample1(t), `[{"email":"ann@example.test","name":"Ann","order":1},{"email":"bo@example.test","name":"Bo","order":2}]`))
	if created != http.StatusCreated {
		t.Fatalf("POST /api/v1/envelopes = %d, want 201: %v", created, out)
	}

	env, _ := out["envelope"].(map[string]any)
	if env == nil {
		t.Fatalf("no envelope in the answer: %v", out)
	}
	if env["status"] != "ready" {
		t.Fatalf("status = %v, want ready", env["status"])
	}
	id, _ := env["id"].(string)
	if len(id) != 32 {
		t.Fatalf("envelope id %q is not 32 hex characters", id)
	}

	links, _ := out["links"].([]any)
	if len(links) != 2 {
		t.Fatalf("links = %d, want 2", len(links))
	}
	for i, l := range links {
		m, _ := l.(map[string]any)
		token, _ := m["token"].(string)
		if len(token) < 32 {
			t.Fatalf("link %d token is too short", i)
		}
		url, _ := m["url"].(string)
		if !strings.HasPrefix(url, cfg.PublicURL+"/s/") || !strings.HasSuffix(url, token) {
			t.Fatalf("link %d url %q does not end with its token", i, url)
		}
	}

	// The stored rows: three revisions (template, filled, certified), the
	// parties with hashed tokens, and the certification serial on the envelope.
	ctx := context.Background()
	row, err := store.GetEnvelope(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != signstore.StatusReady {
		t.Fatalf("stored status %q, want ready", row.Status)
	}
	if row.Serial == "" {
		t.Fatal("the certification serial was not stored")
	}
	revisions, err := store.ListRevisions(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 3 {
		t.Fatalf("revisions = %d, want 3", len(revisions))
	}
	kinds := []string{revisions[0].Kind, revisions[1].Kind, revisions[2].Kind}
	if kinds[0] != signstore.KindTemplate || kinds[1] != signstore.KindFilled || kinds[2] != signstore.KindCertified {
		t.Fatalf("revision kinds %v, want template, filled, certified", kinds)
	}
	if revisions[0].PrevID != "" || revisions[1].PrevID != revisions[0].ID || revisions[2].PrevID != revisions[1].ID {
		t.Fatalf("the revision chain is not linked: %v", kinds)
	}

	parties, err := store.ListParties(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(parties) != 2 {
		t.Fatalf("parties = %d, want 2", len(parties))
	}
	for i, p := range parties {
		l, _ := links[i].(map[string]any)
		token, _ := l["token"].(string)
		if p.TokenHash == token {
			t.Fatalf("party %d stores the plaintext token", i)
		}
		if p.TokenHash != signauth.HashToken(token) {
			t.Fatalf("party %d token hash does not match its link", i)
		}
	}

	// The answer must not echo the stored hashes, and the plaintext tokens
	// must appear only in the links.
	encoded, _ := json.Marshal(out)
	for _, p := range parties {
		if bytes.Contains(encoded, []byte(p.TokenHash)) {
			t.Fatalf("the token hash of party %s is in the answer", p.Email)
		}
	}

	// A second create from the same template: the template bytes are stored
	// once, and both envelopes have their own revision rows.
	second, out2 := createRequest(t, ts, access, sample1(t),
		createFields(t, sample1(t), `[{"email":"cy@example.test","name":"Cy","order":1}]`))
	if second != http.StatusCreated {
		t.Fatalf("second create = %d: %v", second, out2)
	}
	env2, _ := out2["envelope"].(map[string]any)
	id2, _ := env2["id"].(string)
	row2, err := store.GetEnvelope(ctx, id2)
	if err != nil {
		t.Fatal(err)
	}
	if row2.TemplateSHA != row.TemplateSHA {
		t.Fatal("the same template produced two different template hashes")
	}
	if row2.CurrentSHA == row.CurrentSHA {
		t.Fatal("two envelopes share their certified bytes; the certification time differs")
	}
	if n := len(mustRevisions(t, store, id2)); n != 3 {
		t.Fatalf("second envelope revisions = %d, want 3", n)
	}
}

func mustRevisions(t *testing.T, store *signstore.Store, id string) []signstore.Revision {
	t.Helper()
	revs, err := store.ListRevisions(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return revs
}

// 2. A fill spec naming an unknown field is a 400 that names the field, and
// leaves no rows behind.
func TestCreateUnknownFieldLeavesNoRows(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	before := countRows(t, store, "envelopes")
	fields := map[string]string{
		"title":   "Unknown field",
		"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":    `{"fill":{"values":{"not_a_field":"x"}}}`,
	}
	code, out := createRequest(t, ts, access, sample1(t), fields)
	if code != http.StatusBadRequest {
		t.Fatalf("create with an unknown field = %d, want 400: %v", code, out)
	}
	problem := problemOf(t, out)
	if !strings.Contains(problem["code"].(string), "fill") {
		t.Fatalf("code %q does not name the fill spec", problem["code"])
	}
	if !strings.Contains(problem["message"].(string), "not_a_field") {
		t.Fatalf("the answer does not name the field: %q", problem["message"])
	}

	if n := countRows(t, store, "envelopes"); n != before {
		t.Fatalf("envelope rows after a failed create: %d, want %d", n, before)
	}
	if n := countRows(t, store, "parties"); n != 0 {
		t.Fatalf("party rows after a failed create: %d, want 0", n)
	}
	if n := countRows(t, store, "revisions"); n != 0 {
		t.Fatalf("revision rows after a failed create: %d, want 0", n)
	}
}

// 3. Duplicate party email and a gap in the orders are 400s.
func TestCreateRejectsDuplicateAndGappedParties(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)
	before := countRows(t, store, "envelopes")

	dup := createFields(t, sample1(t),
		`[{"email":"ann@example.test","name":"Ann","order":1},{"email":"ANN@example.test","name":"Ann","order":2}]`)
	code, out := createRequest(t, ts, access, sample1(t), dup)
	if code != http.StatusBadRequest {
		t.Fatalf("duplicate email = %d, want 400: %v", code, out)
	}
	if !strings.Contains(problemOf(t, out)["code"].(string), "email") {
		t.Fatalf("the duplicate answer does not name the email field: %v", out)
	}

	gap := createFields(t, sample1(t),
		`[{"email":"ann@example.test","name":"Ann","order":1},{"email":"bo@example.test","name":"Bo","order":3}]`)
	code, out = createRequest(t, ts, access, sample1(t), gap)
	if code != http.StatusBadRequest {
		t.Fatalf("gapped order = %d, want 400: %v", code, out)
	}
	if !strings.Contains(problemOf(t, out)["code"].(string), "order") {
		t.Fatalf("the gap answer does not name the order field: %v", out)
	}

	// A template that is not a PDF is refused before any parsing.
	code, out = createRequest(t, ts, access, []byte("not a pdf"), map[string]string{
		"title":   "Not a PDF",
		"parties": `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":    `{"fill":{"values":{"d1":"x"}}}`,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("non-PDF template = %d, want 400: %v", code, out)
	}

	// Missing template, missing spec, missing title.
	code, out = createRequest(t, ts, access, sample1(t),
		map[string]string{"title": "No spec", "parties": `[{"email":"ann@example.test","order":1}]`})
	if code != http.StatusBadRequest {
		t.Fatalf("missing spec = %d, want 400: %v", code, out)
	}

	if n := countRows(t, store, "envelopes"); n != before {
		t.Fatalf("envelope rows after the failures: %d, want %d", n, before)
	}
}

// 4. GET /api/v1/envelopes/{id}: the envelope, the parties, the revision
// chain, the audit trail. The document download hashes to current_sha.
func TestGetEnvelopeAndDocument(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	created, out := createRequest(t, ts, access, sample1(t), createFields(t, sample1(t),
		`[{"email":"ann@example.test","name":"Ann","order":1},{"email":"bo@example.test","name":"Bo","order":2}]`))
	if created != http.StatusCreated {
		t.Fatalf("create = %d: %v", created, out)
	}
	env, _ := out["envelope"].(map[string]any)
	id, _ := env["id"].(string)

	code, full := getJSON(t, ts, "/api/v1/envelopes/"+id, access)
	if code != http.StatusOK {
		t.Fatalf("GET envelope = %d: %v", code, full)
	}
	if full["document_sha"] == nil || full["document_sha"] == "" {
		t.Fatalf("no document_sha in the answer: %v", full)
	}
	if full["total"] != float64(2) {
		t.Fatalf("total = %v, want 2", full["total"])
	}
	if full["consented"] != float64(0) {
		t.Fatalf("consented = %v, want 0", full["consented"])
	}
	parties, _ := full["parties"].([]any)
	if len(parties) != 2 {
		t.Fatalf("parties = %d, want 2", len(parties))
	}
	first, _ := parties[0].(map[string]any)
	if first["order"] != float64(1) || first["email"] != "ann@example.test" {
		t.Fatalf("party 1 is %v", first)
	}
	if first["link_expires_at"] == nil {
		t.Fatalf("the party answer has no link_expires_at: %v", first)
	}
	revisions, _ := full["revisions"].([]any)
	if len(revisions) != 3 {
		t.Fatalf("revisions = %d, want 3", len(revisions))
	}
	events, _ := full["events"].([]any)
	if len(events) < 2 {
		t.Fatalf("events = %d, want the create and the ready events", len(events))
	}
	// The trail is the create event plus the transition to ready. The
	// transition event names the target state in its payload, so the audit
	// trail says what happened, not only that something happened.
	firstEvent, _ := events[0].(map[string]any)
	if firstEvent["kind"] != "created" {
		t.Fatalf("the first event is %v, want created", firstEvent)
	}
	if firstEvent["actor"] != "admin:1" {
		t.Fatalf("the create event actor is %v, want the admin who created it", firstEvent["actor"])
	}
	last, _ := events[len(events)-1].(map[string]any)
	payload, _ := last["payload"].(string)
	if !strings.Contains(payload, "ready") {
		t.Fatalf("the last event is %v, want a transition to ready", last)
	}

	// The document: the bytes hash to current_sha.
	res, err := rawGet(t, ts, "/api/v1/envelopes/"+id+"/document", access)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("download = %d", res.StatusCode)
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Fatal("the download is not a PDF")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != full["document_sha"] {
		t.Fatalf("the download hashes to %x, want %v", sum, full["document_sha"])
	}
	if res.Header.Get("X-Content-Sha256") != full["document_sha"] {
		t.Fatalf("X-Content-Sha256 is %q, want the document sha", res.Header.Get("X-Content-Sha256"))
	}
	if res.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("Content-Type is %q", res.Header.Get("Content-Type"))
	}
	disposition := res.Header.Get("Content-Disposition")
	if !strings.HasPrefix(disposition, `attachment; filename="nda-for-review`) ||
		!strings.HasSuffix(disposition, "-certified.pdf\"") {
		t.Fatalf("Content-Disposition is %q, want a slug of the title plus the kind", disposition)
	}
	if res.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("Cache-Control is %q", res.Header.Get("Cache-Control"))
	}

	// One revision: the template bytes are the original upload.
	templateSHA := mustRevisions(t, store, id)[0].SHA256
	rid := mustRevisions(t, store, id)[0].ID
	res2, err := rawGet(t, ts, "/api/v1/envelopes/"+id+"/revisions/"+rid, access)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	tbody, err := io.ReadAll(res2.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("revision download = %d", res2.StatusCode)
	}
	tsum := sha256.Sum256(tbody)
	if hex.EncodeToString(tsum[:]) != templateSHA {
		t.Fatalf("the template revision hashes to %x, want %s", tsum, templateSHA)
	}
	if !bytes.Equal(tbody, sample1(t)) {
		t.Fatal("the template revision is not the uploaded bytes")
	}

	// A revision id from another envelope is a 404, not a document leak.
	other, out2 := createRequest(t, ts, access, sample1(t), createFields(t, sample1(t),
		`[{"email":"cy@example.test","name":"Cy","order":1}]`))
	if other != http.StatusCreated {
		t.Fatalf("second create = %d: %v", other, out2)
	}
	env2, _ := out2["envelope"].(map[string]any)
	id2, _ := env2["id"].(string)
	rid2 := mustRevisions(t, store, id2)[0].ID
	res3, err := rawGet(t, ts, "/api/v1/envelopes/"+id+"/revisions/"+rid2, access)
	if err != nil {
		t.Fatal(err)
	}
	res3.Body.Close()
	if res3.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-envelope revision = %d, want 404", res3.StatusCode)
	}

	// An unknown envelope is 404.
	code, out = getJSON(t, ts, "/api/v1/envelopes/"+strings.Repeat("0", 32), access)
	if code != http.StatusNotFound {
		t.Fatalf("unknown envelope = %d, want 404", code)
	}
}

// 5. The scope check: a client without envelope:write cannot create, and a
// caller without a token cannot read.
func TestEnvelopeScopes(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)

	// No token: 401.
	code, _ := getJSON(t, ts, "/api/v1/envelopes", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("list without a token = %d, want 401", code)
	}

	// A machine client with envelope:read only.
	ctx := context.Background()
	key := randomKey()
	if _, err := store.AddClient(ctx, "reader", sha256Of([]byte(key)),
		signauth.ScopeEnvelopeRead); err != nil {
		t.Fatal(err)
	}
	res, err := ts.Client().Post(ts.URL+"/api/v1/auth/token", "application/json",
		strings.NewReader(`{"key":"`+key+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body := decode(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("client token = %d: %v", res.StatusCode, body)
	}
	access, _ := body["access"].(string)

	if code, _ := getJSON(t, ts, "/api/v1/envelopes", access); code != http.StatusOK {
		t.Fatalf("list with envelope:read = %d, want 200", code)
	}
	code, out := createRequest(t, ts, access, sample1(t), createFields(t, sample1(t),
		`[{"email":"ann@example.test","name":"Ann","order":1}]`))
	if code != http.StatusForbidden {
		t.Fatalf("create with envelope:read only = %d, want 403: %v", code, out)
	}
	if n := countRows(t, store, "envelopes"); n != 0 {
		t.Fatalf("a forbidden create stored %d envelopes", n)
	}
}

// 6. List filters and paging, through the API.
func TestListThroughAPI(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	for i, title := range []string{"Alpha lease", "Beta report", "Alpha report"} {
		fields := createFields(t, sample1(t), `[{"email":"ann`+itoa(i)+`@example.test","name":"Ann","order":1}]`)
		fields["title"] = title
		if code, out := createRequest(t, ts, access, sample1(t), fields); code != http.StatusCreated {
			t.Fatalf("seed %d = %d: %v", i, code, out)
		}
	}

	code, out := getJSON(t, ts, "/api/v1/envelopes?status=ready&q=Alpha", access)
	if code != http.StatusOK {
		t.Fatalf("list = %d: %v", code, out)
	}
	if out["total"] != float64(2) {
		t.Fatalf("title filter matched %v, want 2", out["total"])
	}

	code, out = getJSON(t, ts, "/api/v1/envelopes?status=nonsense&q=", access)
	if code != http.StatusBadRequest {
		t.Fatalf("bad status filter = %d, want 400", code)
	}

	code, out = getJSON(t, ts, "/api/v1/envelopes?limit=1", access)
	if code != http.StatusOK {
		t.Fatalf("paged list = %d: %v", code, out)
	}
	list, _ := out["envelopes"].([]any)
	if len(list) != 1 {
		t.Fatalf("limit 1 returned %d rows", len(list))
	}
	if out["limit"] != float64(1) {
		t.Fatalf("limit is echoed as %v, want 1", out["limit"])
	}

	// The page size cap: a request for 500 gets the capped page, and the
	// answer echoes the cap rather than the number asked for.
	code, out = getJSON(t, ts, "/api/v1/envelopes?limit=500", access)
	list, _ = out["envelopes"].([]any)
	if code != http.StatusOK || len(list) > maxPageSize {
		t.Fatalf("limit 500 returned %d rows, want at most %d", len(list), maxPageSize)
	}
	if out["limit"] != float64(maxPageSize) {
		t.Fatalf("limit is echoed as %v, want the capped %d", out["limit"], maxPageSize)
	}
}

// maxPageSize is the page ceiling the store enforces.
const maxPageSize = signstore.MaxPageSize

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// rawGet sends a GET with a bearer token and hands back the response, so a
// test can read the download headers as well as the body.
func rawGet(t *testing.T, ts *httptest.Server, path, token string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return ts.Client().Do(req)
}

func problemOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	p, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("the answer has no error object: %v", out)
	}
	return p
}

func countRows(t *testing.T, store *signstore.Store, table string) int {
	t.Helper()
	var n int
	if err := store.DB().QueryRow("select count(*) from " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The download filename keeps a title with punctuation inside a safe slug: a
// title that tries to carry a quote cannot break the header.
func TestDownloadNameIsSlugified(t *testing.T) {
	if got := DownloadName(`NDA "for" review / final`, "certified"); got != "nda-for-review-final-certified.pdf" {
		t.Fatalf("filename = %q", got)
	}
	if got := DownloadName("   ", "template"); got != "envelope-template.pdf" {
		t.Fatalf("empty title filename = %q", got)
	}
	long := strings.Repeat("a", 80)
	got := DownloadName(long, "signed")
	if !strings.HasSuffix(got, "-signed.pdf") {
		t.Fatalf("long title filename = %q", got)
	}
	if len(got) > 60+len("-signed.pdf") {
		t.Fatalf("the filename is not capped: %d characters", len(got))
	}
}
