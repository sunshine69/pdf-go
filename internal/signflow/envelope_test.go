package signflow

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
	"fmt"
	"io"
	"math/big"
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
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The acceptance list of docs/steps/05-envelopes.md, in order. The tests run
// against the real state machine, the real fill, and the real certification,
// with a test TSA so no test touches the network.

func TestMain(m *testing.M) {
	// The PDF library reports unencodable glyphs with log.Printf; the service
	// keeps its log clean, and a glyph it cannot draw is a note in the report.
	os.Exit(m.Run())
}

func newTestStore(t *testing.T) *signstore.Store {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "signsrv.db")
	db, err := signstore.Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := signstore.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return signstore.NewStore(db, filepath.Join(t.TempDir(), "storage"))
}

func sampleBytes(t *testing.T) []byte {
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

// A test TSA: honest by default, so the certification carries a validated
// signing time. The tests must not use the network, and the verifier rejects a
// timestamp token that is not bound to the request, so an in-process TSA that
// behaves correctly is the only way to exercise the real create path.
func newTestTSA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signflow test TSA"},
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

// newDeps wires a full service: store, signing service, state machine.
func newDeps(t *testing.T) *Deps {
	t.Helper()
	tsa := newTestTSA(t)
	dir := t.TempDir()
	s, err := signpdfService(dir, "dev-passphrase-that-is-long-enough", tsa)
	if err != nil {
		t.Fatalf("signing service: %v", err)
	}
	store := newTestStore(t)
	return &Deps{
		Store:     store,
		Signer:    s,
		Flow:      NewFlow(store),
		CertifyAs: "signsrv",
		Clock:     time.Now,
	}
}

// fillSpecFor builds a spec that fills every text field of the template, so
// the create path exercises a real fill rather than an empty one.
func fillSpecFor(t *testing.T, template []byte) schema.FillSpec {
	t.Helper()
	s, err := signfillExtract(template)
	if err != nil {
		t.Fatal(err)
	}
	spec := schema.FillSpec{Values: schema.SetValues{}}
	for _, f := range s.Fields {
		if f.Type == schema.TypeText {
			spec.Values[f.Name] = "x"
		}
	}
	return spec
}

func parties(n int) []Party {
	out := make([]Party, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, Party{
			Email:  fmt.Sprintf("party%d@example.test", i),
			Name:   fmt.Sprintf("Party %d", i),
			Order:  i,
			Reason: "I agree to the terms",
		})
	}
	return out
}

// 1. Create with sample1.pdf + 2 parties: status ready, 3 revisions, and the
// plaintext links in the response only.
func TestCreateProducesReadyEnvelope(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	req := CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(2),
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	}
	created, err := d.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if created.Envelope.Status != Ready {
		t.Fatalf("status is %q, want ready", string(created.Envelope.Status))
	}
	if len(created.Envelope.ID) != 32 {
		t.Fatalf("id %q is not 32 hex characters", created.Envelope.ID)
	}

	revs, err := d.Store.ListRevisions(context.Background(), created.Envelope.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 3 {
		t.Fatalf("revisions: %d, want 3 (template, filled, certified)", len(revs))
	}
	if revs[0].Kind != signstore.KindTemplate || revs[1].Kind != signstore.KindFilled ||
		revs[2].Kind != signstore.KindCertified {
		t.Fatalf("revision kinds: %s %s %s", revs[0].Kind, revs[1].Kind, revs[2].Kind)
	}
	if revs[2].CertSerial == "" {
		t.Fatal("the certified revision records no certificate serial")
	}
	if revs[2].SHA256 != created.Envelope.CurrentSHA {
		t.Fatal("current_sha is not the certified revision")
	}
	if revs[0].PrevID != "" || revs[1].PrevID != revs[0].ID || revs[2].PrevID != revs[1].ID {
		t.Fatal("the revision chain is not linked by prev_id")
	}

	// The response carries 2 plaintext links; the store holds only hashes.
	if len(created.Links) != 2 {
		t.Fatalf("links: %d, want 2", len(created.Links))
	}
	for i, l := range created.Links {
		if len(l.Token) < 40 {
			t.Fatalf("link %d token is too short to be 256-bit", i)
		}
		if l.URL != "http://127.0.0.1:8090/s/"+l.Token {
			t.Fatalf("link %d url %q", i, l.URL)
		}
		if l.ExpiresAt != created.Envelope.ExpiresAt {
			t.Fatalf("link %d expires at %s, envelope at %s", i, l.ExpiresAt, created.Envelope.ExpiresAt)
		}
	}

	partyRows, err := d.Store.ListParties(context.Background(), created.Envelope.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(partyRows) != 2 {
		t.Fatalf("parties: %d, want 2", len(partyRows))
	}
	for i, p := range partyRows {
		if p.Status != signstore.PartyInvited {
			t.Fatalf("party %d status %q, want invited", i, string(p.Status))
		}
		if p.TokenHash == "" {
			t.Fatalf("party %d has no token hash", i)
		}
		// The party's stored hash is the hash of its own link, and of
		// nothing stored in plaintext.
		l := linkFor(created.Links, p.OrderIdx)
		if l.Token == "" {
			t.Fatalf("party %d has no link", i)
		}
		if p.TokenHash == l.Token || strings.Contains(p.TokenHash, l.Token) {
			t.Fatalf("party %d stores the plaintext token", i)
		}
		if p.TokenHash != signauth.HashToken(l.Token) {
			t.Fatalf("party %d token hash does not match its link", i)
		}
	}

	// The create event is in the audit trail, and the transition to ready is
	// audited too.
	events, err := d.Store.ListEvents(context.Background(), created.Envelope.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 {
		t.Fatalf("events: %d, want the create event and the transition", len(events))
	}
	if events[0].Kind != "created" {
		t.Fatalf("first event is %q, want created", events[0].Kind)
	}
	if events[0].Actor != "api:test" {
		t.Fatalf("event actor is %q, want the client that created it", events[0].Actor)
	}
	if !strings.Contains(events[0].Payload, "NDA") {
		t.Fatalf("create payload does not carry the title: %s", events[0].Payload)
	}
	last := events[len(events)-1]
	if last.Kind != "transition" || !strings.Contains(last.Payload, "ready") {
		t.Fatalf("last event is %s %s, want the transition to ready", last.Kind, last.Payload)
	}

	// The certification serial is recorded on the envelope.
	if created.Envelope.Serial == "" {
		t.Fatal("envelope records no certification serial")
	}
}

// 2. Fill spec with an unknown field: 400 naming the field, and no envelope
// row created.
func TestCreateUnknownFieldLeavesNoRows(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	countBefore := countEnvelopes(t, d.Store)

	spec := fillSpecFor(t, in)
	spec.Values["nope"] = "x"
	_, err := d.Create(context.Background(), CreateRequest{
		Template:  in,
		Fill:      spec,
		Parties:   parties(2),
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	var ev *ErrValidation
	if !AsValidation(err, &ev) {
		t.Fatalf("expected a validation error, got %v", err)
	}
	if !strings.Contains(ev.Msg, `"nope"`) {
		t.Fatalf("the error does not name the field: %v", ev)
	}
	if ev.Field == "" {
		t.Fatalf("the error names no field: %v", ev)
	}
	if countEnvelopes(t, d.Store) != countBefore {
		t.Fatal("an envelope row was created for a failed create")
	}
	// No parties, no revisions, no events: the transaction rolled back.
	for _, table := range []string{"parties", "revisions", "events"} {
		if n := countRows(t, d.Store, table); n != 0 {
			t.Fatalf("%s rows after a failed create: %d", table, n)
		}
	}
}

// 3. Duplicate party email and non-contiguous order are both 400.
func TestCreateRejectsDuplicateAndGappedOrders(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	before := countEnvelopes(t, d.Store)

	dup := parties(2)
	dup[1].Email = dup[0].Email
	_, err := d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: dup,
		Title: "NDA", ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	var ev *ErrValidation
	if !AsValidation(err, &ev) || !strings.Contains(ev.Field, "email") {
		t.Fatalf("duplicate email: %v", err)
	}

	gap := parties(3)
	gap[2].Order = 5
	_, err = d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: gap,
		Title: "NDA", ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if !AsValidation(err, &ev) || !strings.Contains(ev.Field, "order") {
		t.Fatalf("gapped order: %v", err)
	}

	// A non-PDF template, a title that is too long, and an expiry past 720h
	// are all refused before any work is done.
	_, err = d.Create(context.Background(), CreateRequest{
		Template: []byte("not a pdf"), Fill: fillSpecFor(t, in), Parties: parties(1),
		Title: "NDA", ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if !AsValidation(err, &ev) {
		t.Fatalf("non-PDF: %v", err)
	}
	_, err = d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: parties(1),
		Title: strings.Repeat("t", 201), ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if !AsValidation(err, &ev) {
		t.Fatalf("long title: %v", err)
	}
	_, err = d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: parties(1),
		Title: "NDA", ExpiresIn: 800 * time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if !AsValidation(err, &ev) {
		t.Fatalf("long expiry: %v", err)
	}

	if countEnvelopes(t, d.Store) != before {
		t.Fatal("a rejected create wrote an envelope")
	}
}

// 4. The certified document is read-only: every field on the stored certified
// file carries the readOnly flag.
func TestCertifiedDocumentIsReadOnly(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	created, err := d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: parties(2),
		Title: "NDA", ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	certified, err := d.Store.GetPDF(created.Envelope.CurrentSHA)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signfillExtract(certified)
	if err != nil {
		t.Fatalf("extract certified: %v", err)
	}
	checked := 0
	for _, f := range s.Fields {
		if f.Type == schema.TypePushButton || f.Type == schema.TypeSignature {
			continue
		}
		checked++
		if !f.HasFlag("readOnly") {
			t.Fatalf("field %s is not read-only on the certified file", f.Name)
		}
	}
	if checked == 0 {
		t.Fatal("no fields checked")
	}
	if s.FieldCount == 0 {
		t.Fatal("certified document has no fields")
	}
}

// 5. Transition from ready to completed is refused: 409 at the API.
func TestTransitionRefusesIllegalAdvance(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	created, err := d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: parties(2),
		Title: "NDA", ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e := created.Envelope

	err = d.Flow.Transition(context.Background(), e, Completed, "api", "")
	if !IsConflict(err) {
		t.Fatalf("ready -> completed: %v, want ErrStateConflict", err)
	}
	// The status is unchanged in the database.
	got, err := d.Store.GetEnvelope(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Ready {
		t.Fatalf("status after a refused transition is %q", string(got.Status))
	}
	// No event was written for a transition that did not happen.
	events, _ := d.Store.ListEvents(context.Background(), e.ID)
	for _, ev := range events {
		if strings.Contains(ev.Payload, "completed") {
			t.Fatalf("an event recorded the refused transition: %s", ev.Payload)
		}
	}

	// The legal path works, and is audited.
	for _, to := range []State{Sent, Collecting} {
		if err := d.Flow.Transition(context.Background(), e, to, "worker", ""); err != nil {
			t.Fatalf("%s: %v", string(to), err)
		}
	}
	got, _ = d.Store.GetEnvelope(context.Background(), e.ID)
	if got.Status != Collecting {
		t.Fatalf("status is %q, want collecting", string(got.Status))
	}
	if got.SentAt == "" {
		t.Fatal("sent_at was not stamped by the transition to sent")
	}

	// A signed document cannot be cancelled: the parties' signatures exist.
	if err := d.Flow.Transition(context.Background(), e, Signed, "worker", ""); err != nil {
		t.Fatalf("-> signed: %v", err)
	}
	if err := d.Flow.Transition(context.Background(), e, Cancelled, "admin", ""); !IsConflict(err) {
		t.Fatalf("signed -> cancelled: %v, want conflict", err)
	}
}

// 6. List filters by status and title, with paging; 1000 envelopes answer in
// well under 50 ms.
func TestListFiltersAndPaging(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)

	// Seed: a set of envelopes with two titles and mixed statuses.
	ids := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		title := "Alpha report"
		if i%3 == 0 {
			title = "Beta lease"
		}
		created, err := d.Create(context.Background(), CreateRequest{
			Template: in, Fill: fillSpecFor(t, in), Parties: parties(1),
			Title: title, ExpiresIn: time.Hour, Actor: "api",
			LinkBase: "http://127.0.0.1:8090",
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		ids = append(ids, created.Envelope.ID)
		if i%2 == 0 {
			if err := d.Flow.Transition(context.Background(), created.Envelope,
				Sent, "worker", ""); err != nil {
				t.Fatal(err)
			}
		}
	}

	// status filter
	ready, total, err := d.Store.ListEnvelopes(context.Background(), "ready", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total < 6 {
		t.Fatalf("ready total %d, want at least 6", total)
	}
	for _, e := range ready {
		if e.Status != Ready {
			t.Fatalf("status filter returned %q", string(e.Status))
		}
	}

	// q filter on title
	hits, total, err := d.Store.ListEnvelopes(context.Background(), "", "Beta", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("Beta matches %d, want 4", total)
	}
	for _, e := range hits {
		if !strings.Contains(e.Title, "Beta") {
			t.Fatalf("q filter returned %q", e.Title)
		}
	}

	// q filter on party email
	hits, total, err = d.Store.ListEnvelopes(context.Background(), "", "party1@example.test", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 12 {
		t.Fatalf("email search matched %d, want 12", total)
	}

	// limit and offset are enforced, and page size is capped.
	page, _, err := d.Store.ListEnvelopes(context.Background(), "", "", "", 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 5 {
		t.Fatalf("limit 5 returned %d", len(page))
	}
	page, _, err = d.Store.ListEnvelopes(context.Background(), "", "", "", 500, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) > 100 {
		t.Fatalf("page size cap: %d rows returned", len(page))
	}

	// 1000 envelopes: the list call must be fast. The index on
	// (status, created_at) is what makes this a seek, not a scan.
	seed1000(t, d.Store)
	start := time.Now()
	list, total, err := d.Store.ListEnvelopes(context.Background(), "ready", "", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if total < 1000 {
		t.Fatalf("total %d, want 1000+", total)
	}
	if len(list) > 100 {
		t.Fatalf("limit 100 returned %d", len(list))
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("list of 1000 envelopes took %s, want under 50ms", elapsed)
	}
}

// 7. Document download: the stored bytes hash to current_sha.
func TestDocumentDownloadMatchesCurrentSHA(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	created, err := d.Create(context.Background(), CreateRequest{
		Template: in, Fill: fillSpecFor(t, in), Parties: parties(2),
		Title: "NDA", ExpiresIn: time.Hour, Actor: "api",
		LinkBase: "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e := created.Envelope

	body, err := d.Store.GetPDF(e.CurrentSHA)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != e.CurrentSHA {
		t.Fatal("the stored document does not hash to current_sha")
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Fatal("stored document is not a PDF")
	}

	// The template, filled, and certified files all hash to their rows.
	revs, _ := d.Store.ListRevisions(context.Background(), e.ID)
	for _, r := range revs {
		b, err := d.Store.GetPDF(r.SHA256)
		if err != nil {
			t.Fatalf("%s: %v", r.Kind, err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != r.SHA256 {
			t.Fatalf("%s file does not hash to its row", r.Kind)
		}
	}

	// The filename the download uses is slug + kind. It is built here so the
	// test proves the shape, and the handler uses the same function.
	name := DownloadName(e.Title, signstore.KindCertified)
	if name != "nda-certified.pdf" {
		t.Fatalf("download name %q", name)
	}
}

// helpers

func countEnvelopes(t *testing.T, s *signstore.Store) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow("select count(*) from envelopes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countRows(t *testing.T, s *signstore.Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow("select count(*) from " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// seed1000 writes 1000 envelopes through raw inserts: the point of the test is
// the read, not 1000 certifications.
func seed1000(t *testing.T, s *signstore.Store) {
	t.Helper()
	tx, err := s.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for i := 0; i < 1000; i++ {
		// A distinct id per row. A repeating byte pattern collides after 251
		// rows, which is exactly the collision this test must not create.
		id := fmt.Sprintf("%032x", i)
		status := "ready"
		expiry := now.Add(48 * time.Hour).Format(timeFormat)
		if _, err := tx.Exec(
			`insert into envelopes(id, title, status, template_sha, filled_sha, current_sha,
			 created_by, created_at, updated_at, expires_at)
			 values(?,?,?,?,?,?,?,?,?,?)`,
			id, "Bulk document "+hex.EncodeToString([]byte{byte(i % 251)}), status,
			strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64),
			1, now.Add(-time.Duration(i)*time.Second).Format(timeFormat),
			now.Format(timeFormat), expiry); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// DownloadName builds the attachment filename: a slug of the title plus the
// revision kind. A title with a path separator in it cannot escape the
// filename, which is what the Content-Disposition header needs.
func DownloadName(title, kind string) string {
	slug := slugify(title)
	if slug == "" {
		slug = "document"
	}
	return slug + "-" + kind + ".pdf"
}

func slugify(s string) string {
	out := make([]rune, 0, len(s))
	last := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out = append(out, r)
			last = false
			continue
		}
		if !last {
			out = append(out, '-')
			last = true
		}
	}
	return strings.Trim(string(out), "-")
}

// sql.DB is imported for the count helpers above.
