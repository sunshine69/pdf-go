package signstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	path := t.TempDir() + "/signsrv.db"
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(db, t.TempDir()+"/storage")
}

func env(t *testing.T, s *Store, id string) *Envelope {
	t.Helper()
	e := &Envelope{ID: id, Title: "NDA", Status: StatusReady, CreatedBy: 1,
		ExpiresAt: formatTime(time.Now().UTC().Add(24 * time.Hour))}
	if err := s.CreateEnvelope(context.Background(), e); err != nil {
		t.Fatalf("create envelope: %v", err)
	}
	return e
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	applied, err := Migrate(ctx, s.DB())
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if applied != 0 {
		t.Fatalf("re-running migrate applied %d migrations, want 0", applied)
	}
	v, err := SchemaVersion(ctx, s.DB())
	if err != nil || v != CurrentVersion {
		t.Fatalf("schema version = %d, %v; want %d", v, err, CurrentVersion)
	}

	// Fresh database: migrate applies every migration once.
	path := t.TempDir() + "/fresh.db"
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	applied, err = Migrate(ctx, db)
	if err != nil || applied != CurrentVersion {
		t.Fatalf("first migrate applied %d, err %v; want %d", applied, err, CurrentVersion)
	}
}

func TestMigrateRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.SetSetting(ctx, "schema_version", "99"); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, s.DB()); err == nil ||
		!strings.Contains(err.Error(), "newer") {
		t.Fatalf("migrate on newer schema: %v, want a 'newer' error", err)
	}
}

func TestCascadeDeleteOfParties(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	e := env(t, s, "0123456789abcdef0123456789abcdef")

	for i, email := range []string{"a@x.test", "b@x.test"} {
		p := &Party{ID: partyID(i), EnvelopeID: e.ID, OrderIdx: i + 1, Email: email,
			Status: PartyInvited, TokenHash: "hash-" + email,
			TokenExpires: formatTime(time.Now().Add(time.Hour))}
		if err := s.CreateParty(ctx, p); err != nil {
			t.Fatalf("create party: %v", err)
		}
	}
	parties, err := s.ListParties(ctx, e.ID)
	if err != nil || len(parties) != 2 {
		t.Fatalf("parties = %d (%v), want 2", len(parties), err)
	}

	if _, err := s.DB().ExecContext(ctx, "delete from envelopes where id = ?1", e.ID); err != nil {
		t.Fatalf("delete envelope: %v", err)
	}
	parties, err = s.ListParties(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(parties) != 0 {
		t.Fatalf("%d parties survived the envelope delete, want cascade", len(parties))
	}
}

func TestDuplicatePartyRejected(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	e := env(t, s, "11223344556677889900112233445566")

	first := &Party{ID: "p1", EnvelopeID: e.ID, OrderIdx: 1, Email: "a@x.test",
		Status: PartyInvited, TokenHash: "tok001", TokenExpires: "2030-01-01T00:00:00Z"}
	if err := s.CreateParty(ctx, first); err != nil {
		t.Fatal(err)
	}
	dup := &Party{ID: "p2", EnvelopeID: e.ID, OrderIdx: 2, Email: "a@x.test",
		Status: PartyInvited, TokenHash: "bb", TokenExpires: "2030-01-01T00:00:00Z"}
	if err := s.CreateParty(ctx, dup); err == nil {
		t.Fatal("duplicate email in the same envelope was accepted")
	}
	dup2 := &Party{ID: "p3", EnvelopeID: e.ID, OrderIdx: 1, Email: "c@x.test",
		Status: PartyInvited, TokenHash: "cc", TokenExpires: "2030-01-01T00:00:00Z"}
	if err := s.CreateParty(ctx, dup2); err == nil {
		t.Fatal("duplicate order_idx in the same envelope was accepted")
	}
	// Same email in a different envelope is fine.
	env(t, s, "22334455667788990011223344556677")
	other := &Party{ID: "p4", EnvelopeID: "22334455667788990011223344556677", OrderIdx: 1,
		Email: "a@x.test", Status: PartyInvited, TokenHash: "dd", TokenExpires: "2030-01-01T00:00:00Z"}
	if err := s.CreateParty(ctx, other); err != nil {
		t.Fatalf("same email in another envelope: %v", err)
	}
}

func TestTokenHashLookup(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	e := env(t, s, "33445566778899001122334455667788")
	p := &Party{ID: "p1", EnvelopeID: e.ID, OrderIdx: 1, Email: "a@x.test",
		Status: PartyInvited, TokenHash: "cafebabe", TokenExpires: "2030-01-01T00:00:00Z"}
	if err := s.CreateParty(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPartyByTokenHash(ctx, "cafebabe")
	if err != nil {
		t.Fatalf("by token hash: %v", err)
	}
	if got.ID != "p1" {
		t.Fatalf("token resolved to %q, want p1", got.ID)
	}
	if _, err := s.GetPartyByTokenHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v, want ErrNotFound", err)
	}
	if _, err := s.GetPartyByTokenHash(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty token: %v, want ErrNotFound", err)
	}
	// Reissuing the link drops the old hash.
	if err := s.SetPartyToken(ctx, "p1", "deadbeef", "2031-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPartyByTokenHash(ctx, "cafebabe"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the superseded token still resolves")
	}
}

func TestPutPDFRejectsNonPDF(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.PutPDF([]byte("not a pdf at all")); err == nil {
		t.Fatal("PutPDF accepted data without a %PDF- header")
	}
	if _, err := s.PutPDF(nil); err == nil {
		t.Fatal("PutPDF accepted empty data")
	}
	data := []byte("%PDF-1.7\n% test\n")
	sha, err := s.PutPDF(data)
	if err != nil {
		t.Fatalf("PutPDF: %v", err)
	}
	if len(sha) != 64 {
		t.Fatalf("sha = %q, want 64 hex characters", sha)
	}
	sha2, err := s.PutPDF(data)
	if err != nil || sha2 != sha {
		t.Fatalf("re-storing the same bytes: %q %v, want %q", sha2, err, sha)
	}
	back, err := s.GetPDF(sha)
	if err != nil || string(back) != string(data) {
		t.Fatalf("GetPDF = %q %v", back, err)
	}
	if _, err := s.GetPDF(strings.Repeat("00", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revision: %v, want ErrNotFound", err)
	}
	if _, err := s.GetPDF("../etc/passwd"); err == nil {
		t.Fatal("GetPDF accepted a path traversal sha")
	}
	if _, err := s.PutPDF([]byte("%PDF-" + strings.Repeat("x", MaxPDFBytes))); err == nil {
		t.Fatal("PutPDF accepted an oversized document")
	}
}

func TestSweepExpiresOldEnvelope(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	past := formatTime(time.Now().UTC().Add(-time.Hour))

	e := &Envelope{ID: "44556677889900112233445566778899", Title: "old", Status: StatusSent,
		CreatedBy: 1, ExpiresAt: past}
	if err := s.CreateEnvelope(ctx, e); err != nil {
		t.Fatal(err)
	}
	p := &Party{ID: "p1", EnvelopeID: e.ID, OrderIdx: 1, Email: "a@x.test",
		Status: PartyInvited, TokenHash: "tok002", TokenExpires: past}
	if err := s.CreateParty(ctx, p); err != nil {
		t.Fatal(err)
	}
	live := &Envelope{ID: "55667788990011223344556677889900", Title: "live", Status: StatusSent,
		CreatedBy: 1, ExpiresAt: formatTime(time.Now().UTC().Add(24 * time.Hour))}
	if err := s.CreateEnvelope(ctx, live); err != nil {
		t.Fatal(err)
	}

	r, err := Sweep(ctx, s.DB())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if r.EnvelopesExpired != 1 || r.PartiesExpired != 1 {
		t.Fatalf("sweep report = %+v, want 1 envelope and 1 party expired", r)
	}
	got, err := s.GetEnvelope(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("status = %q, want expired", got.Status)
	}
	if g, _ := s.GetEnvelope(ctx, live.ID); g.Status != StatusSent {
		t.Fatalf("unexpired envelope became %q", g.Status)
	}
	if p, _ := s.GetParty(ctx, "p1"); p.Status != PartyExpired {
		t.Fatalf("party status = %q, want expired", p.Status)
	}
	// A second sweep changes nothing.
	r2, err := Sweep(ctx, s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if r2.EnvelopesExpired != 0 || r2.PartiesExpired != 0 {
		t.Fatalf("second sweep report = %+v, want zeros", r2)
	}
	events, err := s.ListEvents(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("sweep wrote per-envelope events: %+v", events)
	}
	// A sweep with nothing to do writes no event, so only the first one
	// appears in the trail.
	if n := countRows(t, s, "events"); n != 1 {
		t.Fatalf("events rows = %d, want one (the sweep that changed rows)", n)
	}
}

func TestBatchQueueLeaseAndBackoff(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := "66778899001122334455667788990011"
	env(t, s, id)

	if _, err := s.ClaimBatch(ctx, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim on empty queue: %v, want ErrNotFound", err)
	}
	if err := s.EnqueueBatch(ctx, id, timeNow()); err != nil {
		t.Fatal(err)
	}
	b, err := s.ClaimBatch(ctx, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if b.EnvelopeID != id || b.Attempts != 1 {
		t.Fatalf("claimed %+v", b)
	}
	// The lease blocks a second claim.
	if _, err := s.ClaimBatch(ctx, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second claim: %v, want ErrNotFound while leased", err)
	}
	if err := s.RequeueBatch(ctx, id, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimBatch(ctx, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("claim succeeded before next_at")
	}
	if err := s.RequeueBatch(ctx, id, -time.Second); err != nil {
		t.Fatal(err)
	}
	b, err = s.ClaimBatch(ctx, 20*time.Second)
	if err != nil {
		t.Fatalf("claim after the backoff window: %v", err)
	}
	if b.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", b.Attempts)
	}
	if err := s.CompleteBatch(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimBatch(ctx, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("completed batch is still queued")
	}
	// Exhausting the retries marks the envelope failed on the next sweep.
	// RequeueBatch with a negative delay clears the lease and makes the row
	// due again, so the attempts climb without waiting.
	if err := s.EnqueueBatch(ctx, id, timeNow()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxBatchAttempts; i++ {
		b, err := s.ClaimBatch(ctx, 0)
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if b.Attempts != i+1 {
			t.Fatalf("claim %d reports attempts %d", i, b.Attempts)
		}
		if err := s.RequeueBatch(ctx, id, -time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB().ExecContext(ctx,
		"update envelopes set status = 'collecting' where id = ?", id); err != nil {
		t.Fatal(err)
	}
	if _, err := Sweep(ctx, s.DB()); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEnvelope(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want failed after %d attempts", got.Status, MaxBatchAttempts)
	}
}

func TestMailQueueLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := "77889900112233445566778899001122"
	env(t, s, id)

	if err := s.EnqueueMail(ctx, id, "p1", MailInvite, "abc"); err != nil {
		t.Fatal(err)
	}
	m, err := s.ClaimMail(ctx, time.Minute)
	if err != nil {
		t.Fatalf("claim mail: %v", err)
	}
	if m.Kind != MailInvite || m.Attempts != 1 {
		t.Fatalf("claimed %+v", m)
	}
	if _, err := s.ClaimMail(ctx, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("second claim succeeded while leased")
	}
	if err := s.MarkMailFailed(ctx, m.ID, timeNow(), "smtp refused"); err != nil {
		t.Fatal(err)
	}
	m2, err := s.ClaimMail(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Attempts != 2 || m2.LastError != "smtp refused" {
		t.Fatalf("reclaimed %+v", m2)
	}
	if err := s.MarkMailSent(ctx, m2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimMail(ctx, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("sent message was claimed again")
	}
	list, err := s.ListMail(ctx, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if list[0].SentAt == "" {
		t.Fatal("sent_at not recorded")
	}
}

func TestConsentOncePerParty(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := "88990011223344556677889900112233"
	env(t, s, id)
	p := &Party{ID: "p1", EnvelopeID: id, OrderIdx: 1, Email: "a@x.test", Status: PartyInvited,
		TokenHash: "tok003", TokenExpires: "2030-01-01T00:00:00Z"}
	if err := s.CreateParty(ctx, p); err != nil {
		t.Fatal(err)
	}
	c := &Consent{ID: "c1", PartyID: "p1", EnvelopeID: id, SignatureText: "Alice 2026-01-01",
		DocumentSHA: "ff", Appearance: `{"font":14}`}
	if err := s.AddConsent(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.AddConsent(ctx, &Consent{ID: "c2", PartyID: "p1", EnvelopeID: id,
		SignatureText: "again", DocumentSHA: "ff"}); err == nil {
		t.Fatal("a second consent for the same party was accepted")
	}
	got, err := s.GetConsentByParty(ctx, "p1")
	if err != nil || got.SignatureText != "Alice 2026-01-01" {
		t.Fatalf("consent = %+v %v", got, err)
	}
}

func TestListEnvelopesSearchAndPaging(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for i, title := range []string{"NDA Alpha", "NDA Beta", "Lease Gamma"} {
		e := &Envelope{ID: idOf(i), Title: title, Status: StatusReady, CreatedBy: 1,
			ExpiresAt: "2030-01-01T00:00:00Z"}
		if err := s.CreateEnvelope(ctx, e); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := s.CreateParty(ctx, &Party{ID: "sp" + idOf(i), EnvelopeID: e.ID,
				OrderIdx: 1, Email: "carol@x.test", Status: PartyInvited,
				TokenHash: "tok004", TokenExpires: "2030-01-01T00:00:00Z"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		status, search string
		want           int
	}{
		{"", "", 3},
		{"ready", "", 3},
		{"sent", "", 0},
		{"", "NDA", 2},
		{"", "carol@x.test", 1}, // search reaches party emails
		{"", "lease gamma", 1},  // case-insensitive LIKE
		{"", "%", 0},            // wildcards are matched literally
		{"", "_", 0},
	}
	for _, c := range cases {
		list, total, err := s.ListEnvelopes(ctx, c.status, c.search, 50, 0)
		if err != nil {
			t.Fatalf("list(%q,%q): %v", c.status, c.search, err)
		}
		if total != c.want || len(list) != c.want {
			t.Fatalf("list(%q,%q) = %d rows, total %d, want %d",
				c.status, c.search, len(list), total, c.want)
		}
	}
	page1, total, err := s.ListEnvelopes(ctx, "", "", 2, 0)
	if err != nil || len(page1) != 2 || total != 3 {
		t.Fatalf("page1 = %d/%d %v", len(page1), total, err)
	}
	page2, _, err := s.ListEnvelopes(ctx, "", "", 2, 2)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page2 = %d %v", len(page2), err)
	}
	if page1[0].ID == page2[0].ID {
		t.Fatal("paging returned the same row twice")
	}
}

func TestStatusValidationAndNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.CreateEnvelope(ctx, &Envelope{ID: "99001122334455667788990011223344",
		Status: StatusSent, Title: "x"}); err != nil {
		t.Fatalf("lowercase status rejected: %v", err)
	}
	if err := s.CreateEnvelope(ctx, &Envelope{ID: "00112233445566778899001122334455",
		Status: EnvelopeStatus("READY"), Title: "x"}); err == nil {
		t.Fatal("uppercase status accepted")
	}
	if err := s.CreateEnvelope(ctx, &Envelope{ID: "00112233445566778899001122334466",
		Status: EnvelopeStatus("made_up"), Title: "x"}); err == nil {
		t.Fatal("unknown status accepted")
	}
	if err := s.CreateParty(ctx, &Party{ID: "px", EnvelopeID: "99001122334455667788990011223344",
		OrderIdx: 0, Email: "e@x.test", Status: PartyInvited, TokenHash: "aa",
		TokenExpires: "2030-01-01T00:00:00Z"}); err == nil {
		t.Fatal("order_idx 0 accepted, signatures are numbered from 1")
	}
	if err := s.CreateEnvelope(ctx, &Envelope{ID: "short", Status: StatusReady}); err == nil {
		t.Fatal("short envelope id accepted")
	}
	if _, err := s.GetEnvelope(ctx, "00112233445566778899001122334455x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEnvelope missing: %v, want ErrNotFound", err)
	}
	eid := "00112233445566778899001122334477"
	if err := s.CreateEnvelope(ctx, &Envelope{ID: eid, Status: StatusReady, Title: "x",
		CreatedBy: 1, ExpiresAt: "2030-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateEnvelopeStatus(ctx, eid, StatusSent, "sent_at"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, err := s.GetEnvelope(ctx, eid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSent || got.SentAt == "" {
		t.Fatalf("after update: %+v", got)
	}
	if err := s.UpdateEnvelopeStatus(ctx, "does-not-exist", StatusSigned, ""); err == nil {
		t.Fatal("update of a missing envelope reported success")
	}
	if err := s.UpdateEnvelopeStatus(ctx, eid, StatusSigned, "bogus_at"); err == nil {
		t.Fatal("arbitrary timestamp column name accepted")
	}
	if err := s.UpdateEnvelopeStatus(ctx, eid, EnvelopeStatus("nope"), ""); err == nil {
		t.Fatal("arbitrary status written through UpdateEnvelopeStatus")
	}
}

func TestRevokeJTI(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.RevokeJTI(ctx, "jti-1", "2030-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeJTI(ctx, "jti-1", "2030-01-01T00:00:00Z"); err != nil {
		t.Fatalf("revoke is idempotent: %v", err)
	}
	if ok, err := s.IsJTIRevoked(ctx, "jti-1"); err != nil || !ok {
		t.Fatalf("revoked = %v %v", ok, err)
	}
	if ok, _ := s.IsJTIRevoked(ctx, "other"); ok {
		t.Fatal("unrelated jti reported revoked")
	}
	// The sweep drops entries past their expiry.
	if err := s.RevokeJTI(ctx, "jti-old", "2000-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := Sweep(ctx, s.DB()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.IsJTIRevoked(ctx, "jti-old"); ok {
		t.Fatal("expired jti survived the sweep")
	}
	if ok, _ := s.IsJTIRevoked(ctx, "jti-1"); !ok {
		t.Fatal("live jti was deleted by the sweep")
	}
}

func TestEventsAppendOnly(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := "112233445566778899001122334455aa"
	env(t, s, id)
	for _, k := range []string{"created", "sent", "consent"} {
		if err := s.AddEvent(ctx, id, "admin", k, `{"n":1}`); err != nil {
			t.Fatal(err)
		}
	}
	ev, err := s.ListEvents(ctx, id)
	if err != nil || len(ev) != 3 {
		t.Fatalf("events = %+v %v", ev, err)
	}
	if ev[0].Kind != "created" || ev[2].Kind != "consent" {
		t.Fatalf("events out of order: %+v", ev)
	}
	if ev[0].ID >= ev[1].ID {
		t.Fatal("event ids are not monotonic")
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.GetSetting(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing setting: %v", err)
	}
	if err := s.SetSetting(ctx, "ca_fingerprint", "AA"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "ca_fingerprint", "BB"); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetSetting(ctx, "ca_fingerprint")
	if err != nil || v != "BB" {
		t.Fatalf("setting = %q %v", v, err)
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow("select count(*) from " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func partyID(i int) string { return "p" + idOf(i) }

// idOf returns a deterministic 32 hex character id so a test can build
// distinct envelope ids without a random generator.
func idOf(i int) string { return fmt.Sprintf("%032x", i+1) }

// A nullable column is NULL in the schema and a plain string in the model.
// A NULL in an integer column must scan as 0. `GET /api/v1/envelopes` over a
// database that has envelopes with no creator is the case that broke first.
func TestScanMapsNullToZeroValues(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// CreatedBy 0 is stored as NULL.
	e := &Envelope{ID: idOf(50), Title: "no creator", Status: StatusReady,
		ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := s.CreateEnvelope(ctx, e); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, "envelopes"); n != 1 {
		t.Fatalf("envelopes: %d", n)
	}
	got, err := s.GetEnvelope(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CreatedBy != 0 {
		t.Fatalf("created_by = %d, want 0 for a NULL column", got.CreatedBy)
	}
	if got.Serial != "" {
		t.Fatalf("serial = %q, want empty for NULL", got.Serial)
	}
	// The same row read through the list query, which is the path the API
	// uses. A NULL in a scanned column must not fail the call.
	out, total, err := s.ListEnvelopes(ctx, "ready", "no creator", 100, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(out) != 1 || out[0].ID != e.ID {
		t.Fatalf("list = %d rows, total %d", len(out), total)
	}
	// A non-zero creator is stored as an integer.
	e2 := &Envelope{ID: idOf(51), Title: "has creator", Status: StatusReady,
		CreatedBy: 7, ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := s.CreateEnvelope(ctx, e2); err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetEnvelope(ctx, e2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.CreatedBy != 7 {
		t.Fatalf("created_by = %d, want 7", got2.CreatedBy)
	}
}
