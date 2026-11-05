package signflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Unit tests for consent, decline, and the state table. They live beside the
// code so that a change to the rules moves the tests in the same commit.
//
// Each test builds its own envelope. Consent moves state, and state is what is
// under test; a shared envelope would make every test depend on the order the
// tests happened to run in.

// consentFixture is a fresh store, one sent envelope with n parties, and the
// plaintext token of each party.
type consentFixture struct {
	t       *testing.T
	deps    *Deps
	env     *signstore.Envelope
	tokens  []string
	dsha    string
	partyID []string
}

func newConsentFixture(t *testing.T, nParties int) *consentFixture {
	t.Helper()
	d := newDeps(t)
	ctx := context.Background()

	// Create, fill and certify a real document, so the flow layer works against
	// real data rather than a fixture shaped like one.
	created, err := d.Create(ctx, CreateRequest{
		Template:  sampleBytes(t),
		Fill:      fillSpecFor(t, sampleBytes(t)),
		Parties:   parties(nParties),
		Title:     "Consent unit test",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	links, err := d.Send(ctx, created.Envelope.ID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(links) != nParties {
		t.Fatalf("send returned %d links, want %d", len(links), nParties)
	}

	env, err := d.Store.GetEnvelope(ctx, created.Envelope.ID)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if env.Status != Sent {
		t.Fatalf("envelope = %s, want sent", env.Status)
	}

	f2 := &consentFixture{t: t, deps: d, env: env, dsha: env.CurrentSHA}
	for _, l := range links {
		f2.tokens = append(f2.tokens, l.Token)
		f2.partyID = append(f2.partyID, l.PartyID)
	}
	return f2
}

// consent runs the flow with a valid body for one party's token.
func (f *consentFixture) consent(token, text, image string) (*ConsentResult, error) {
	f.t.Helper()
	return f.deps.Consent(context.Background(), token, ConsentInput{
		SignatureText: text, Consent: true, DocumentSHA: f.dsha, Image: image,
		IP:        "10.0.0.1",
		UserAgent: "signflow-unit-test",
	}, time.Now().UTC())
}

// --- helpers, local to this file ---

func countConsents(t *testing.T, s *signstore.Store, envelopeID string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`select count(*) from consents where envelope_id = ?`,
		envelopeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countBatches(t *testing.T, s *signstore.Store, envelopeID string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`select count(*) from batch_queue where envelope_id = ?`,
		envelopeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func eventKind(t *testing.T, s *signstore.Store, envelopeID, kind string) *signstore.Event {
	t.Helper()
	events, err := s.ListEvents(context.Background(), envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if events[i].Kind == kind {
			return &events[i]
		}
	}
	return nil
}

// realPNG and realJPEG encode a small image through the stdlib encoders, so the
// bytes carry real headers a decoder can read, and are then base64'd the way a
// canvas would present them.
func realPNG(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 6))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func realJPEG(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 6))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// --- tests ---

// Acceptance 2: consent happy path writes the row with its text, its timestamp,
// its IP, its user agent and the digest it is about; moves the party; kills the
// session; and writes no PDF.
func TestUnitConsentHappyPath(t *testing.T) {
	f := newConsentFixture(t, 2)
	ctx := context.Background()
	before := len(mustRevisions(t, f.deps.Store, f.env.ID))

	res, err := f.consent(f.tokens[0], "Ann Miller", "")
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	if !res.OK || res.Status != string(Collecting) {
		t.Fatalf("consent answer: %+v", res)
	}
	if res.AllConsented {
		t.Fatal("one consent of two says all parties are done")
	}

	c, err := f.deps.Store.GetConsentByParty(ctx, f.partyID[0])
	if err != nil {
		t.Fatalf("the consent row is missing: %v", err)
	}
	if c.SignatureText != "Ann Miller" {
		t.Fatalf("text = %q", c.SignatureText)
	}
	if c.ConsentAt == "" || c.IP != "10.0.0.1" || c.UserAgent == "" {
		t.Fatalf("the when and the who are missing: %+v", c)
	}
	if c.DocumentSHA != f.dsha {
		t.Fatalf("consent is bound to %q, want the certified sha %s", c.DocumentSHA, f.dsha)
	}

	p, err := f.deps.Store.GetParty(ctx, f.partyID[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != signstore.PartyConsented {
		t.Fatalf("party status = %s, want consented", p.Status)
	}
	if p.SessionHash != "" {
		t.Fatal("the session survived the consent")
	}

	if after := len(mustRevisions(t, f.deps.Store, f.env.ID)); after != before {
		t.Fatalf("consent wrote a PDF: %d -> %d revisions", before, after)
	}
	if eventKind(t, f.deps.Store, f.env.ID, "consent") == nil {
		t.Fatal("no consent event on the trail")
	}
}

// The trail records each consent by the digest it is about, and against the
// party that gave it.
func TestUnitConsentEventCarriesTheDigest(t *testing.T) {
	f := newConsentFixture(t, 2)

	if _, err := f.consent(f.tokens[0], "Ann", ""); err != nil {
		t.Fatalf("consent: %v", err)
	}
	ev := eventKind(t, f.deps.Store, f.env.ID, "consent")
	if ev == nil {
		t.Fatal("no consent event")
	}
	if !strings.Contains(ev.Payload, f.dsha) {
		t.Fatalf("the event does not carry the digest: %s", ev.Payload)
	}
	if ev.Actor != "party:"+f.partyID[0] {
		t.Fatalf("event actor %q, want the consenting party", ev.Actor)
	}
}

// Acceptance 4: a stale digest is a 409, and a refusal leaves nothing behind.
func TestUnitConsentStaleDigestIsRefused(t *testing.T) {
	f := newConsentFixture(t, 2)

	// A digest the envelope is not holding: the party is looking at a stale copy.
	_, err := f.deps.Consent(context.Background(), f.tokens[0], ConsentInput{
		SignatureText: "Ann", Consent: true, DocumentSHA: strings.Repeat("a", 64),
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("a consent about a digest the envelope is not holding was accepted")
	}
	if !errors.Is(err, ErrDocumentSHA) {
		t.Fatalf("stale digest: %v, want document_sha", err)
	}
	if n := countConsents(t, f.deps.Store, f.env.ID); n != 0 {
		t.Fatalf("a refused consent wrote %d rows", n)
	}

	// With the right digest it works, and the row carries the digest.
	if _, err := f.consent(f.tokens[0], "Ann", ""); err != nil {
		t.Fatalf("consent with the right digest: %v", err)
	}
	c, err := f.deps.Store.GetConsentByParty(context.Background(), f.partyID[0])
	if err != nil {
		t.Fatalf("the consent row is missing: %v", err)
	}
	if c.DocumentSHA != f.dsha {
		t.Fatalf("consent is bound to %q, want the certified sha %s", c.DocumentSHA, f.dsha)
	}
}

// Acceptance 3: the checkbox, the text.
func TestUnitConsentValidatesTheDeclaration(t *testing.T) {
	f := newConsentFixture(t, 2)

	cases := []struct {
		text string
		ok   bool
		why  string
	}{
		{"Ann", true, "a name"},
		{"", false, "empty signature text"},
		{"   ", false, "blank signature text"},
		{"a\nb", false, "newline in the text"},
		{"a\tb", false, "tab in the text"},
		{strings.Repeat("x", 120), true, "120 characters is the limit, inclusive"},
		{strings.Repeat("x", 121), false, "121 characters"},
	}
	for i, c := range cases {
		// Each case gets its own envelope, so one refusal cannot change the
		// state the next case is tested against.
		fx := newConsentFixture(t, 1)
		res, err := fx.consent(fx.tokens[0], c.text, "")
		switch {
		case c.ok && err != nil:
			t.Fatalf("%s: refused (%v)", c.why, err)
		case !c.ok && err == nil:
			t.Fatalf("%s: accepted (%+v)", c.why, res)
		case !c.ok && !errors.Is(err, ErrSignatureText):
			t.Fatalf("%s: wrong refusal %v", c.why, err)
		}
		_ = i
	}

	// The checkbox itself.
	fx := newConsentFixture(t, 1)
	res, err := fx.deps.Consent(context.Background(), fx.tokens[0], ConsentInput{
		SignatureText: "Ann", Consent: false, DocumentSHA: fx.dsha,
	}, time.Now().UTC())
	if err == nil {
		t.Fatalf("consent:false was accepted: %+v", res)
	}
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("consent:false: %v, want consent_required", err)
	}
	_ = f
}

// Acceptance 5: the image rules. A real PNG and a real JPEG pass; a bad base64,
// a non-image, and an oversized body are refused.
func TestUnitConsentImageRules(t *testing.T) {
	fx := newConsentFixture(t, 1)
	if _, err := fx.consent(fx.tokens[0], "Ann", realPNG(t)); err != nil {
		t.Fatalf("png: %v", err)
	}

	cases := []struct {
		image string
		why   string
	}{
		{"not base64 at all @@", "malformed base64"},
		{base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 a pdf is not a picture")), "not an image"},
		{base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 600*1024)...)), "over the size ceiling"},
	}
	for _, c := range cases {
		one := newConsentFixture(t, 1)
		_, err := one.consent(one.tokens[0], "Ann", c.image)
		if err == nil {
			t.Fatalf("%s: accepted", c.why)
		}
		if !errors.Is(err, ErrConsentImage) {
			t.Fatalf("%s: wrong refusal %v", c.why, err)
		}
		if n := countConsents(t, one.deps.Store, one.env.ID); n != 0 {
			t.Fatalf("%s: the refusal wrote %d rows", c.why, n)
		}
	}

	// A JPEG is accepted too, on a party of its own.
	two := newConsentFixture(t, 1)
	if _, err := two.consent(two.tokens[0], "Ann", realJPEG(t)); err != nil {
		t.Fatalf("jpeg: %v", err)
	}
	_ = fx
}

// Acceptance 2, second half: one consent per party. A second attempt cannot be
// accepted, and nothing is written twice.
func TestUnitConsentTwiceIsRefused(t *testing.T) {
	f := newConsentFixture(t, 1)

	if _, err := f.consent(f.tokens[0], "Ann", ""); err != nil {
		t.Fatalf("first consent: %v", err)
	}
	// The party row: the consent is recorded, and the session that proved the
	// address is gone, so a replay arrives as an unclaimed link.
	p, err := f.deps.Store.GetParty(context.Background(), f.partyID[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != signstore.PartyConsented {
		t.Fatalf("party status = %s, want consented", p.Status)
	}
	if p.SessionHash != "" {
		t.Fatal("the consent left the session standing")
	}
	if _, err := f.consent(f.tokens[0], "Ann again", ""); err == nil {
		t.Fatal("the party consented twice")
	}
	if n := countConsents(t, f.deps.Store, f.env.ID); n != 1 {
		t.Fatalf("the second consent wrote a row: %d rows", n)
	}
}

// Acceptance 8: the last consent enqueues exactly one batch, on the boundary,
// and it is queued and not run.
func TestUnitLastConsentEnqueuesOneBatch(t *testing.T) {
	f := newConsentFixture(t, 2)

	res, err := f.consent(f.tokens[0], "Ann", "")
	if err != nil {
		t.Fatalf("consent 1: %v", err)
	}
	if res.AllConsented {
		t.Fatal("the first consent claims all parties are done")
	}
	if got := countBatches(t, f.deps.Store, f.env.ID); got != 0 {
		t.Fatalf("the first consent queued a batch: %d", got)
	}
	env, err := f.deps.Store.GetEnvelope(context.Background(), f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Collecting {
		t.Fatalf("envelope = %s, want collecting after the first consent", env.Status)
	}

	res, err = f.consent(f.tokens[1], "Bob", "")
	if err != nil {
		t.Fatalf("consent 2: %v", err)
	}
	if !res.AllConsented {
		t.Fatalf("the last consent does not say all_consented: %+v", res)
	}
	if got := countBatches(t, f.deps.Store, f.env.ID); got != 1 {
		t.Fatalf("batch count %d, want exactly one", got)
	}
	if eventKind(t, f.deps.Store, f.env.ID, "batch_queued") == nil {
		t.Fatal("no batch_queued event")
	}
	// The envelope has not been signed. It moves to signed only through step 10.
	env, err = f.deps.Store.GetEnvelope(context.Background(), f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Collecting {
		t.Fatalf("the envelope advanced on its own: %s", env.Status)
	}
}

// Acceptance 7: decline fails the request, records the reason against the party
// for the admin, and closes every other link on the envelope.
func TestUnitDeclineRefusesTheEnvelope(t *testing.T) {
	f := newConsentFixture(t, 2)

	res, err := f.deps.Decline(context.Background(), f.tokens[0], "not comfortable",
		DeclineMeta{IP: "10.0.0.1", UserAgent: "signflow-unit-test"}, time.Now().UTC())
	if err != nil {
		t.Fatalf("decline: %v", err)
	}
	if !res.OK || res.Status != string(Failed) {
		t.Fatalf("decline answer: %+v", res)
	}

	env, err := f.deps.Store.GetEnvelope(context.Background(), f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Failed {
		t.Fatalf("envelope = %s, want failed", env.Status)
	}
	p, err := f.deps.Store.GetParty(context.Background(), f.partyID[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != signstore.PartyDeclined {
		t.Fatalf("party = %s, want declined", p.Status)
	}

	ev := eventKind(t, f.deps.Store, f.env.ID, "declined")
	if ev == nil {
		t.Fatal("no decline event for the admin")
	}
	if !strings.Contains(ev.Payload, "not comfortable") {
		t.Fatalf("the decline event does not carry the reason: %s", ev.Payload)
	}

	// A second decline is refused.
	if _, err := f.deps.Decline(context.Background(), f.tokens[0], "again",
		DeclineMeta{}, time.Now().UTC()); err == nil {
		t.Fatal("the envelope accepted a decline after it had failed")
	}
	if n := countConsents(t, f.deps.Store, f.env.ID); n != 0 {
		t.Fatalf("a declined request grew the consent table: %d rows", n)
	}
}

// The table, tested directly: every row of it, and a transition that is not in
// it.
func TestUnitTestStateTable(t *testing.T) {
	allowed := map[State][]State{
		Ready:      {Sent, Cancelled, Expired},
		Sent:       {Collecting, Failed, Cancelled, Expired},
		Collecting: {Signed, Failed, Cancelled, Expired},
		Signed:     {Completed, Failed},
		Completed:  {Delivered, Failed},
	}
	for from, tos := range allowed {
		for _, to := range tos {
			if !Can(from, to) {
				t.Fatalf("the table says %s -> %s is allowed, Can says no", from, to)
			}
		}
	}
	// Everything else is refused.
	for _, pair := range []struct{ from, to State }{
		{Ready, Collecting}, {Ready, Signed}, {Ready, Completed}, {Ready, Delivered},
		{Sent, Ready}, {Sent, Signed}, {Sent, Completed}, {Sent, Delivered},
		{Collecting, Ready}, {Collecting, Sent}, {Collecting, Completed}, {Collecting, Delivered},
		{Signed, Ready}, {Signed, Sent}, {Signed, Collecting}, {Signed, Cancelled},
		{Signed, Expired}, {Signed, Delivered},
		{Completed, Ready}, {Completed, Sent}, {Completed, Collecting}, {Completed, Signed},
		{Completed, Cancelled}, {Completed, Expired},
		{Delivered, Ready}, {Delivered, Failed},
	} {
		if Can(pair.from, pair.to) {
			t.Fatalf("the table allows %s -> %s, which it should not", pair.from, pair.to)
		}
	}
}

// A transition not in the table is refused and writes nothing.
func TestUnitTestTransitionRefusesIllegalAdvance(t *testing.T) {
	d := newDeps(t)
	ctx := context.Background()
	created, err := d.Create(ctx, CreateRequest{
		Template:  sampleBytes(t),
		Fill:      fillSpecFor(t, sampleBytes(t)),
		Parties:   parties(1),
		Title:     "State unit test",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	env, err := d.Store.GetEnvelope(ctx, created.Envelope.ID)
	if err != nil {
		t.Fatal(err)
	}

	before := countEvents(t, d.Store, env.ID)
	if err := d.Flow.Transition(ctx, env, Completed, "api:test", ""); err == nil {
		t.Fatal("ready -> completed was accepted")
	} else if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("refusal is %v, want state conflict", err)
	}
	if got := countEvents(t, d.Store, env.ID); got != before {
		t.Fatalf("a refused transition wrote %d events", got-before)
	}

	// An advance the table allows, and the event it writes.
	if err := d.Flow.Transition(ctx, env, Sent, "api:test", ""); err != nil {
		t.Fatalf("ready -> sent: %v", err)
	}
	env, err = d.Store.GetEnvelope(ctx, env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Sent {
		t.Fatalf("status = %s, want sent", env.Status)
	}
	if got := countEvents(t, d.Store, env.ID); got != before+1 {
		t.Fatalf("the transition wrote %d events, want 1", got-before)
	}
}

// The sweep. A party past its deadline is expired, the envelope is expired, and
// the admin is notified.
func TestUnitSweepMarksExpiry(t *testing.T) {
	d := newDeps(t)
	ctx := context.Background()
	created, err := d.Create(ctx, CreateRequest{
		Template:  sampleBytes(t),
		Fill:      fillSpecFor(t, sampleBytes(t)),
		Parties:   parties(2),
		Title:     "Sweep unit test",
		ExpiresIn: time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	envID := created.Envelope.ID

	// The deadline has passed. The test moves the data, not the clock, so the
	// sweep runs against the same rule it runs against in production.
	if _, err := d.Store.DB().Exec(
		`update envelopes set status = 'sent', expires_at = '2020-01-01T00:00:00Z' where id = ?`,
		envID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.DB().Exec(
		`update parties set status = 'claimed', token_expires_at = '2020-01-01T00:00:00Z'
		 where envelope_id = ?`, envID); err != nil {
		t.Fatal(err)
	}

	// signstore.Sweep is the sweep the worker runs: it expires the parties past
	// their token deadline and the envelopes past their deadline, and writes one
	// sweep event for the run. It reads its own clock, so the test moves the
	// data into the past rather than moving the clock.
	report, err := signstore.Sweep(ctx, d.Store.DB())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if report.EnvelopesExpired < 1 || report.PartiesExpired < 2 {
		t.Fatalf("sweep report: %d envelopes, %d parties; want 1 and 2",
			report.EnvelopesExpired, report.PartiesExpired)
	}

	env, err := d.Store.GetEnvelope(ctx, envID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Expired {
		t.Fatalf("envelope = %s, want expired", env.Status)
	}
	ps, err := d.Store.ListParties(ctx, envID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.Status != signstore.PartyExpired {
			t.Fatalf("party %d = %s, want expired", p.OrderIdx, p.Status)
		}
	}
	// The sweep writes one event for the run, against no envelope.
	var kind string
	if err := d.Store.DB().QueryRow(
		`select kind from events where envelope_id is null and kind = 'sweep'`).Scan(&kind); err != nil {
		t.Fatalf("the sweep wrote no event: %v", err)
	}
}

// mustRevisions is the harness helper this package's tests use.
func mustRevisions(t *testing.T, s *signstore.Store, envelopeID string) []signstore.Revision {
	t.Helper()
	revs, err := s.ListRevisions(context.Background(), envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	return revs
}

func countEvents(t *testing.T, s *signstore.Store, envelopeID string) int {
	t.Helper()
	events, err := s.ListEvents(context.Background(), envelopeID)
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}
