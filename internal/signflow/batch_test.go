package signflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signstore"
	"github.com/sunshine69/pdf-go/web"
)

// Batch acceptance, step 10.
//
// The batch is the part of the service that actually signs: it takes the
// certified document, adds one signature per consented party, in order, on one
// thread, and verifies the result twice before anything is mailed. Every test
// here runs against a real document produced by create/fill/certify, so the
// revisions the batch writes are real revisions of a real PDF.

// clockOffset shifts only the Deps clock. consent_at and signed_at are separate
// facts, and a test that needs them to differ advances this offset between
// consent and the batch. The store's own clock stays at real time, so queue
// rows remain due.
var clockOffset time.Duration

func clockVal() time.Time { return time.Now().Add(clockOffset) }

// advanceClock moves the fixture clock forward.
func advanceClock(t *testing.T, d time.Duration) {
	clockOffset += d
	t.Cleanup(func() { clockOffset -= d })
}

// batchFixture is one envelope, sent, with one token per party, plus the
// directory the outbox writes into.
type batchFixture struct {
	t       *testing.T
	deps    *Deps
	env     *signstore.Envelope
	dsha    string
	tokens  []string
	partyID []string
	outbox  string
	now     *time.Time
	storage string
}

// newBatchFixture creates, fills, certifies and sends an envelope with n
// parties. The mail queue is left undrained: the batch is about signatures, and
// the delivery test drains the queue when it needs the messages.
func newBatchFixture(t *testing.T, nParties int) *batchFixture {
	t.Helper()
	return newBatchFixtureWithTSA(t, nParties, "")
}

// newBatchFixtureWithTSA is the same fixture whose party signatures are stamped
// against a TSA of the test's choosing. The certification signature always uses
// a working TSA: the document has to be real, and the failure the retry tests
// want is the batch's, not create's. tsaURL empty means the service's own.
func newBatchFixtureWithTSA(t *testing.T, nParties int, tsaURL string) *batchFixture {
	t.Helper()
	ctx := context.Background()
	outbox := t.TempDir()
	dir := t.TempDir()

	tsa := newTestTSA(t)
	s, err := signpdfService(dir, "dev-passphrase-that-is-long-enough", tsa)
	if err != nil {
		t.Fatalf("signing service: %v", err)
	}
	store := newTestStore(t)
	renderer, err := signmail.NewRenderer(web.Templates())
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	d := &Deps{
		Store:     store,
		Signer:    s,
		Flow:      NewFlow(store),
		CertifyAs: "signsrv",
		Clock:     func() time.Time { return clockVal() },
		Mail: &Mailer{
			Renderer: renderer,
			Sender:   &signmail.FileSender{Dir: outbox},
			From:     "signsrv@example.test",
			LinkBase: "http://127.0.0.1:8090",
		},
		TSAOverride: tsaURL,
	}

	created, err := d.Create(ctx, CreateRequest{
		Template:  sampleBytes(t),
		Fill:      fillSpecFor(t, sampleBytes(t)),
		Parties:   parties(nParties),
		Title:     "Batch unit test",
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
	env, err := store.GetEnvelope(ctx, created.Envelope.ID)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	f := &batchFixture{t: t, deps: d, env: env, dsha: env.CurrentSHA, outbox: outbox}
	for _, l := range links {
		f.tokens = append(f.tokens, l.Token)
		f.partyID = append(f.partyID, l.PartyID)
	}
	return f
}

// consent records one party's consent with a hand-drawn PNG image, so the batch
// has a real appearance to read back.
func (f *batchFixture) consent(i int, text string) *ConsentResult {
	f.t.Helper()
	res, err := f.deps.Consent(context.Background(), f.tokens[i], ConsentInput{
		SignatureText: text,
		Consent:       true,
		DocumentSHA:   f.dsha,
		Image:         testPNGBase64(f.t),
		IP:            "10.0.0.1",
		UserAgent:     "signflow-batch-test",
	}, time.Now().UTC())
	if err != nil {
		f.t.Fatalf("consent party %d: %v", i+1, err)
	}
	return res
}

func (f *batchFixture) runBatch() (*BatchOutcome, error) {
	f.t.Helper()
	return f.deps.RunBatch(context.Background(), time.Minute)
}

// signNow is the operator's "sign now": the queue row is written first and the
// batch runs in the request, so a batch can be asked for on an envelope that is
// not ready and the answer is the batch's own refusal.
func (f *batchFixture) signNow() (*BatchOutcome, error) {
	f.t.Helper()
	ctx := context.Background()
	if err := f.deps.Store.EnqueueBatch(ctx, f.env.ID, ""); err != nil {
		f.t.Fatalf("enqueue batch: %v", err)
	}
	return f.deps.RunBatchFor(ctx, f.env.ID, time.Minute)
}

// driveBatch runs the queue the way the worker does, until the row is gone. A
// row whose next attempt is pushed back by a failure is pulled forward, because
// a test that slept through five backoffs would be measuring the clock and not
// the queue.
func (f *batchFixture) driveBatch(maxRuns int) ([]*BatchOutcome, error) {
	f.t.Helper()
	var outs []*BatchOutcome
	var lastErr error
	for i := 0; i < maxRuns; i++ {
		f.releaseLeases()
		out, err := f.deps.RunBatch(context.Background(), time.Second)
		if out != nil {
			outs = append(outs, out)
		}
		if err != nil {
			lastErr = err
			// A failed attempt is the queue's ordinary case, not the end of the
			// run: keep driving until the row is finished or the attempts run out.
			continue
		}
		if out == nil {
			// The queue is empty. Whatever the last attempt reported is the
			// answer the caller is waiting for.
			return outs, lastErr
		}
	}
	return outs, lastErr
}

// releaseLeases clears every lease in the queue and pulls every due time into
// the past. The worker waits out the backoff; a test that did the same would be
// measuring the clock instead of the queue, and the backoff itself is asserted
// separately in TestBatchFailureBackoffIsObserved.
func (f *batchFixture) releaseLeases() {
	f.t.Helper()
	_, err := f.deps.Store.DB().Exec(`update batch_queue set lease_until = null, next_at = ?`,
		formatTime(time.Now().UTC().Add(-time.Minute)))
	if err != nil {
		f.t.Fatal(err)
	}
}

// queueAttempt reads the attempt count the queue holds for the fixture's
// envelope, whether or not the row is still there.
func (f *batchFixture) queueAttempt() (int, error) {
	f.t.Helper()
	var n int
	err := f.deps.Store.DB().QueryRow(
		`select attempts from batch_queue where envelope_id = ?`, f.env.ID).Scan(&n)
	return n, err
}

// markAttempt pushes the queue's own count for this envelope to n, which is how
// a test reaches the edge of the retry budget without running the fault n times.
func (f *batchFixture) markAttempt(n int) {
	f.t.Helper()
	res, err := f.deps.Store.DB().Exec(
		`update batch_queue set attempts = ?, lease_until = null, next_at = ? where envelope_id = ?`,
		n, formatTime(time.Now().UTC().Add(-time.Minute)), f.env.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	if c, _ := res.RowsAffected(); c != 1 {
		f.t.Fatalf("no batch row to move for envelope %s", f.env.ID)
	}
}

// revisions lists the envelope's revision chain oldest first, the shape the
// acceptance reads with "sqlite3 :memory: select ... order by created_at".
func (f *batchFixture) revisions() []signstore.Revision {
	f.t.Helper()
	rows, err := f.deps.Store.DB().Query(
		`select id, sha256, prev_id, kind, sig_field, party_id, cert_serial, cert_fingerprint, size, created_at
		 from revisions where envelope_id = ? order by rowid`, f.env.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []signstore.Revision
	for rows.Next() {
		var r signstore.Revision
		var serial, fp sql.NullString
		if err := rows.Scan(&r.ID, &r.SHA256, &r.PrevID, &r.Kind, &r.SigField,
			&r.PartyID, &serial, &fp, &r.Size, &r.CreatedAt); err != nil {
			f.t.Fatal(err)
		}
		r.CertSerial = serial.String
		r.CertFingerprint = fp.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// baseRevisions is how many rows create/fill/certify leave behind: the template,
// the filled document, and the certified one the batch signs over. The batch's
// own work is always counted on top of that, never from zero.
func (f *batchFixture) baseRevisions() int {
	f.t.Helper()
	revs := f.revisions()
	for i, r := range revs {
		if r.Kind == KindSign {
			return i
		}
	}
	return len(revs)
}

// partyRevisions are the rows the batch wrote, in the order it wrote them.
func (f *batchFixture) partyRevisions() []signstore.Revision {
	f.t.Helper()
	revs := f.revisions()
	return revs[f.baseRevisions():]
}

func (f *batchFixture) queueRows() int {
	f.t.Helper()
	var n int
	if err := f.deps.Store.DB().QueryRow(`select count(*) from batch_queue where envelope_id = ?`,
		f.env.ID).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *batchFixture) status() string {
	f.t.Helper()
	env, err := f.deps.Store.GetEnvelope(context.Background(), f.env.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(env.Status)
}

func (f *batchFixture) events(kind string) []signstore.Event {
	f.t.Helper()
	all, err := f.deps.Store.ListEvents(context.Background(), f.env.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []signstore.Event
	for _, e := range all {
		if kind == "" || e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// testPNGBase64 is a 60x30 PNG in the base64 form a consent body carries.
func testPNGBase64(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample1.pdf"))
	if err != nil {
		t.Skipf("no sample to derive a consent image from: %v", err)
	}
	// A tiny valid PNG: 1x1 pixel, built by hand so the test needs no image lib.
	png := tinyPNG()
	if len(raw) == 0 {
		t.Fatal("unreachable")
	}
	return base64.StdEncoding.EncodeToString(png)
}

// tinyPNG returns a valid 1x1 RGBA PNG.
func tinyPNG() []byte {
	var b []byte
	b = append(b, 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a)
	chunk := func(name string, data []byte) []byte {
		out := []byte{byte(len(data) >> 24), byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}
		out = append(out, name...)
		out = append(out, data...)
		out = append(out, crc32Bytes(name+string(data))...)
		return out
	}
	ihdr := []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0}
	b = append(b, chunk("IHDR", ihdr)...)
	raw := []byte{0, 0x7f, 0x7f, 0x7f, 0xff}
	b = append(b, chunk("IDAT", zlibStore(raw))...)
	b = append(b, chunk("IEND", nil)...)
	return b
}

// crc32Bytes is CRC-32 (the PNG variant) over a byte slice.
func crc32Bytes(data string) []byte {
	var table [256]uint32
	for i := range table {
		c := uint32(i)
		for k := 0; k < 8; k++ {
			if c&1 != 0 {
				c = 0xedb88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	crc := uint32(0xffffffff)
	for i := 0; i < len(data); i++ {
		crc = table[byte(crc)^data[i]] ^ (crc >> 8)
	}
	crc ^= 0xffffffff
	return []byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)}
}

// zlibStore wraps bytes in an uncompressed zlib stream, which is a valid IDAT.
func zlibStore(data []byte) []byte {
	var out []byte
	out = append(out, 0x78, 0x01)
	for off := 0; off < len(data); off += 65535 {
		end := off + 65535
		if end > len(data) {
			end = len(data)
		}
		block := data[off:end]
		last := byte(1)
		if end < len(data) {
			last = 0
		}
		// LEN and NLEN are little-endian, and NLEN is the one's complement of
		// LEN — that is the stored-block header of RFC 1951.
		n := uint16(len(block))
		out = append(out, last, byte(n), byte(n>>8), byte(^n), byte(^n>>8))
		out = append(out, block...)
	}
	sum := adler32(data)
	out = append(out, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))
	return out
}

func adler32(data []byte) uint32 {
	var a, b uint32 = 1, 0
	for _, c := range data {
		a = (a + uint32(c)) % 65521
		b = (b + a) % 65521
	}
	return (b << 16) | a
}

// --- 1. Full happy path -------------------------------------------------

func TestBatchSignsAllPartiesInOrder(t *testing.T) {
	f := newBatchFixture(t, 3)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")

	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	if out.Signed != 3 {
		t.Fatalf("batch signed %d parties, want 3", out.Signed)
	}
	revs := f.revisions()
	base := f.baseRevisions()
	if len(revs) != base+3 {
		t.Fatalf("revisions = %d, want %d (the certified document plus 3 party signatures)",
			len(revs), base+3)
	}
	if revs[base-1].Kind != signstore.KindCertified {
		t.Fatalf("revision under the batch is %q, want %q", revs[base-1].Kind, signstore.KindCertified)
	}
	var names []string
	sigs := map[string]bool{}
	for i, r := range revs[base:] {
		if r.Kind != KindSign {
			t.Fatalf("revision %d kind = %q, want %q", i+1, r.Kind, KindSign)
		}
		if r.SigField == "" || sigs[r.SigField] {
			t.Fatalf("sig_field %q is missing or reused", r.SigField)
		}
		sigs[r.SigField] = true
		if r.PrevID == "" {
			t.Fatalf("party revision %d has no prev_id", i+1)
		}
		if r.PrevID != revs[base-1+i].ID {
			t.Fatalf("party revision %d prev_id = %q, want %q", i+1, r.PrevID, revs[base-1+i].ID)
		}
		if r.CertSerial == "" {
			t.Fatalf("party revision %d has no cert_serial", i+1)
		}
		if r.PartyID == "" {
			t.Fatalf("party revision %d has no party_id", i+1)
		}
		p, err := f.deps.Store.GetParty(ctx, r.PartyID)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, p.Name)
	}
	report := out.Report
	if report == nil {
		t.Fatal("outcome has no verification report")
	}
	if !report.Valid {
		t.Fatalf("final document does not verify: %v", report.Errors)
	}
	if len(report.Signers) != 4 {
		t.Fatalf("final document has %d signers, want 4", len(report.Signers))
	}
	for i := range names {
		if report.Signers[i+1].Name != names[i] {
			t.Fatalf("signer %d = %q, want %q", i+1, report.Signers[i+1].Name, names[i])
		}
	}
	if got := f.status(); got != string(Delivered) {
		t.Fatalf("envelope status = %q, want %q", got, Delivered)
	}
	// A party that consented and was signed is signed in the party row.
	for _, id := range f.partyID {
		p, err := f.deps.Store.GetParty(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != signstore.PartyConsented {
			t.Fatalf("party %s status = %q, want consented: the signature is recorded in the revisions, not in the party row", id, p.Status)
		}
	}
	// The queue row is gone.
	if n := f.queueRows(); n != 0 {
		t.Fatalf("batch_queue still holds %d rows", n)
	}
	// The download and the audit read the final document.
	env, err := f.deps.Store.GetEnvelope(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.CurrentSHA != out.Final {
		t.Fatalf("envelope current_sha = %s, want the final %s", env.CurrentSHA, out.Final)
	}
	if env.DeliveredAt == "" {
		t.Fatalf("envelope delivered_at is empty after delivery")
	}
	data, err := f.deps.Store.GetPDF(out.Final)
	if err != nil {
		t.Fatalf("read final document: %v", err)
	}
	rep, err := f.deps.Signer.Verify(ctx, data)
	if err != nil || !rep.Valid {
		t.Fatalf("verify after batch: valid=%v err=%v", rep != nil && rep.Valid, err)
	}
	if len(rep.Signers) != 4 {
		t.Fatalf("verify after batch: %d signers, want 4", len(rep.Signers))
	}
}

// --- 2. Sequential nesting ------------------------------------------------

func TestBatchSignaturesNestInOrder(t *testing.T) {
	f := newBatchFixture(t, 3)
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")
	if _, err := f.runBatch(); err != nil {
		t.Fatalf("run batch: %v", err)
	}
	revs := f.revisions()
	base := f.baseRevisions()
	if len(revs) != base+3 {
		t.Fatalf("revisions = %d, want %d (the certified document plus 3 party signatures)",
			len(revs), base+3)
	}
	ctx := context.Background()
	// Verify after each party signature: party 1's signature is still valid
	// inside the document party 3 signed.
	for i := base; i < len(revs); i++ {
		data, err := f.deps.Store.GetPDF(revs[i].SHA256)
		if err != nil {
			t.Fatalf("read revision %d: %v", i, err)
		}
		rep, err := f.deps.Signer.Verify(ctx, data)
		if err != nil {
			t.Fatalf("verify revision %d: %v", i, err)
		}
		if !rep.Valid {
			t.Fatalf("revision %d does not verify: %v", i, rep.Errors)
		}
		if want := i - base + 2; len(rep.Signers) != want {
			t.Fatalf("revision %d has %d signers, want %d", i, len(rep.Signers), want)
		}
	}
	// And the party names appear in the order the envelope ordered them.
	var want []string
	for _, id := range f.partyID {
		p, err := f.deps.Store.GetParty(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, p.Name)
	}
	// The last revision is the document every party signed, so its signers,
	// past the certification signature, are the parties in envelope order.
	data, err := f.deps.Store.GetPDF(revs[len(revs)-1].SHA256)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.deps.Signer.Verify(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Signers) < len(want)+1 {
		t.Fatalf("final document has %d signers, want %d parties plus the certification",
			len(rep.Signers), len(want))
	}
	for i := range want {
		if rep.Signers[i+1].Name != want[i] {
			t.Fatalf("signer %d = %q, want %q (order)", i+1, rep.Signers[i+1].Name, want[i])
		}
	}
}

// --- 3. consent -> batch_queue --------------------------------------------

func TestConsentEnqueuesBatchRow(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	if n := f.queueRows(); n != 0 {
		t.Fatalf("queue holds %d rows before any consent", n)
	}
	f.consent(0, "Alice Adamson")
	if n := f.queueRows(); n != 0 {
		t.Fatalf("queue holds %d rows after one consent of two, want 0: the batch runs over "+
			"every party, so an envelope with a party outstanding is not work", n)
	}
	f.consent(1, "Berta Brandt")
	if n := f.queueRows(); n != 1 {
		t.Fatalf("queue holds %d rows after two consents, want 1 (one row per envelope)", n)
	}
	item, err := f.deps.Store.ClaimBatchFor(ctx, f.env.ID, time.Minute)
	if err != nil {
		t.Fatalf("claim batch for envelope: %v", err)
	}
	if item.EnvelopeID != f.env.ID {
		t.Fatalf("claimed envelope %s, want %s", item.EnvelopeID, f.env.ID)
	}
	if item.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", item.Attempts)
	}
}

// --- 4. TSA failure: retries, then failed ---------------------------------

func TestBatchTSAFailureRetriesThenFails(t *testing.T) {
	f := newBatchFixtureWithTSA(t, 2, unreachableTSA(t))
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")

	outs, err := f.driveBatch(BatchAttempts + 2)
	if !errors.Is(err, ErrBatchAttemptsExhausted) {
		t.Fatalf("batch error = %v, want %v", err, ErrBatchAttemptsExhausted)
	}
	// Five runs failed and were requeued; the sixth closed the envelope.
	if len(outs) != BatchAttempts+1 {
		t.Fatalf("queue ran %d times, want %d", len(outs), BatchAttempts+1)
	}
	for i, out := range outs[:BatchAttempts] {
		if out.Attempt != i+1 {
			t.Fatalf("run %d reported attempt %d", i+1, out.Attempt)
		}
		if out.Signed != 0 {
			t.Fatalf("run %d signed %d parties on a dead TSA", i+1, out.Signed)
		}
	}
	if last := outs[len(outs)-1]; last.Attempt != BatchAttempts+1 {
		t.Fatalf("final run reported attempt %d, want %d", last.Attempt, BatchAttempts+1)
	}
	if got := f.status(); got != string(Failed) {
		t.Fatalf("envelope status = %q, want %q", got, Failed)
	}
	// The queue row is finished, not left for a sixth attempt.
	if n := f.queueRows(); n != 0 {
		t.Fatalf("batch_queue still holds %d rows after the final failure", n)
	}
	finalOut := outs[len(outs)-1]
	if finalOut.Attempt < BatchAttempts+1 {
		t.Fatalf("final run reports attempt %d, want >= %d", finalOut.Attempt, BatchAttempts+1)
	}
	// Every attempt is in the events, and the last one names the TSA.
	var failed []signstore.Event
	for _, e := range f.events("failed") {
		failed = append(failed, e)
	}
	// One failed event per attempt, and the closure is its own event: the trail
	// reads five attempts with a reason, then the queue giving up.
	if len(failed) != BatchAttempts {
		t.Fatalf("batch failure events = %d, want %d (one per attempt)", len(failed), BatchAttempts)
	}
	var exhausted []signstore.Event
	for _, e := range f.events("attempts_exhausted") {
		exhausted = append(exhausted, e)
	}
	if len(exhausted) != 1 {
		t.Fatalf("attempts_exhausted events = %d, want 1", len(exhausted))
	}
	last := failed[len(failed)-1]
	var payload map[string]any
	if err := json.Unmarshal([]byte(last.Payload), &payload); err != nil {
		t.Fatalf("decode batch failure payload: %v", err)
	}
	reason, _ := payload["reason"].(string)
	low := strings.ToLower(reason)
	if !strings.Contains(low, "tsa") && !strings.Contains(low, "timestamp") {
		t.Fatalf("final failure reason = %q, want it to name the timestamp authority", reason)
	}
	if payload["attempt"] == nil {
		t.Fatalf("final failure payload has no attempt count: %s", last.Payload)
	}
	// No signature was written, and the document is still the certified one.
	if n := len(f.partyRevisions()); n != 0 {
		t.Fatalf("revisions written by a failed batch: %d, want 0", n)
	}
	// No delivery rows: a failure never reaches a party.
	if dl, err := f.deps.Store.ListDeliveries(ctx, f.env.ID); err != nil || len(dl) != 0 {
		t.Fatalf("deliveries after a TSA failure = %d (err %v), want 0", len(dl), err)
	}
}

func TestBatchTSAFailureKeepsEnvelopeOpenForRetry(t *testing.T) {
	f := newBatchFixtureWithTSA(t, 2, unreachableTSA(t))
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")

	// One run: the envelope stays collecting and the row is requeued, so a
	// temporary TSA outage is an outage and not a lost document.
	out, err := f.deps.RunBatchFor(ctx, f.env.ID, time.Minute)
	if err == nil {
		t.Fatal("expected the signature to fail on a dead TSA")
	}
	if out.Attempt != 1 {
		t.Fatalf("attempts = %d, want 1", out.Attempt)
	}
	if got := f.status(); got != string(Collecting) {
		t.Fatalf("envelope status after one failed attempt = %q, want %q", got, Collecting)
	}
	if n := f.queueRows(); n != 1 {
		t.Fatalf("queue holds %d rows after one failure, want 1 (requeued)", n)
	}
	var nextAt string
	if err := f.deps.Store.DB().QueryRow(`select next_at from batch_queue where envelope_id = ?`,
		f.env.ID).Scan(&nextAt); err != nil {
		t.Fatal(err)
	}
	nxt, err := time.Parse(time.RFC3339, nextAt)
	if err != nil {
		t.Fatalf("next_at = %q: %v", nextAt, err)
	}
	if !nxt.After(time.Now().UTC()) {
		t.Fatalf("next_at = %q is in the past: the failure has no backoff", nextAt)
	}
	// The earlier signature attempt left nothing behind but events.
	if n := len(f.partyRevisions()); n != 0 {
		t.Fatalf("revisions after one failed attempt: %d, want none: the document is written "+
			"only once a signature is complete", n)
	}
}

func unreachableTSA(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no timestamp for you", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/tsr"
}

// --- 5. consent with no batch_run -> batch produces it --------------------

func TestBatchRunsConsentedPartyWithoutConsentRun(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	// Consent records agreement and queues the work; it never signs. If the
	// consent path ever called SignParty, the document would be signed by an
	// HTTP handler and the batch's two gates would never see it.
	if n := len(f.partyRevisions()); n != 0 {
		t.Fatalf("consent wrote %d signature revisions, want 0: signing happens in the batch", n)
	}
	if n := f.queueRows(); n != 1 {
		t.Fatalf("queue holds %d rows, want 1: the last consent queues the batch", n)
	}
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	if out.Signed != 2 {
		t.Fatalf("batch signed %d parties, want 2", out.Signed)
	}
	sigs := f.partyRevisions()
	if len(sigs) != 2 {
		t.Fatalf("batch wrote %d signature revisions, want 2", len(sigs))
	}
	for i, r := range sigs {
		if r.Kind != KindSign {
			t.Fatalf("revision %d kind = %q, want %q", i+1, r.Kind, KindSign)
		}
	}
	if got := f.status(); got != string(Delivered) {
		t.Fatalf("envelope status = %q, want %q: every party is signed and mailed", got, Delivered)
	}
	if out.Status != string(Delivered) {
		t.Fatalf("outcome status = %q, want %q", out.Status, Delivered)
	}
	// The event names the batch, not the party's own request.
	var found bool
	for _, e := range f.events("party_signed") {
		var p map[string]any
		if err := json.Unmarshal([]byte(e.Payload), &p); err != nil {
			t.Fatal(err)
		}
		if p["party_id"] != nil {
			found = true
		}
	}
	if !found {
		t.Fatal("no batch party_signed event")
	}
	_ = ctx
}

// --- 6. Gate 1: signer count ----------------------------------------------

// A document that verifies but is missing a party's signature is the failure
// this step exists to stop: the copy a party is mailed has to carry that party's
// signature. The batch refuses to sign an envelope with a party outstanding, and
// delivery refuses a document whose signer count is short of the party list.
func TestBatchGate1RejectsMissingPartySignature(t *testing.T) {
	f := newBatchFixture(t, 3)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")

	// The batch will not sign for two of three: signing now would produce a
	// document that cannot be delivered to the third party. The operator asks
	// for it explicitly, because the queue has no row for an envelope whose
	// parties are not all in.
	out, err := f.signNow()
	if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("run batch with a party outstanding: err = %v, want %v", err, ErrStateConflict)
	}
	if out == nil {
		t.Fatal("batch returned no outcome alongside the refusal")
	}
	if out.Signed != 0 {
		t.Fatalf("batch signed %d parties with one party outstanding, want 0", out.Signed)
	}
	if got := f.status(); got != string(Collecting) {
		t.Fatalf("envelope status = %q, want %q: the envelope is waiting, not signed", got, Collecting)
	}
	if n := len(f.partyRevisions()); n != 0 {
		t.Fatalf("batch wrote %d signatures on an incomplete envelope, want 0", n)
	}

	// Now complete the envelope and check the delivery gate on a short document:
	// the certified copy verifies, carries one signature, and must not be mailed
	// as the signed document of a three-party envelope.
	f.consent(2, "Cesar Costa")
	full, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch after the last consent: %v", err)
	}
	if full.Signed != 3 {
		t.Fatalf("batch signed %d parties, want 3", full.Signed)
	}
	if len(full.Report.Signers) != 4 {
		t.Fatalf("final document carries %d signers, want 4", len(full.Report.Signers))
	}

	certified := f.baseRevisions() - 1
	certSHA := f.revisions()[certified].SHA256
	if _, err := f.deps.Deliver(ctx, f.env.ID, certSHA); !errors.Is(err, ErrVerifyGate) {
		t.Fatalf("deliver the pre-batch document: err = %v, want %v", err, ErrVerifyGate)
	}
	var gateEvent []signstore.Event
	for _, e := range f.events("verify_failed") {
		gateEvent = append(gateEvent, e)
	}
	if len(gateEvent) == 0 {
		t.Fatal("gate refused delivery with no verify_failed event")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(gateEvent[len(gateEvent)-1].Payload), &payload); err != nil {
		t.Fatalf("decode verify_failed payload: %v", err)
	}
	if payload["expected_sha"] != certSHA {
		t.Fatalf("verify_failed expected_sha = %v, want the document that was offered %s",
			payload["expected_sha"], certSHA)
	}
	if errs, ok := payload["errors"].([]any); !ok || len(errs) == 0 ||
		!strings.Contains(fmt.Sprint(errs[0]), "signatures") {
		t.Fatalf("verify_failed errors do not name the signer count: %s",
			gateEvent[len(gateEvent)-1].Payload)
	}
}

// --- 7. receipt.json ------------------------------------------------------

func TestBatchWritesReceipt(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	data, err := f.deps.GetReceipt(out.Final)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var rec Receipt
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if rec.EnvelopeID != f.env.ID {
		t.Fatalf("receipt envelope_id = %q, want %q", rec.EnvelopeID, f.env.ID)
	}
	if rec.FinalSHA256 != out.Final {
		t.Fatalf("receipt final_sha256 = %q, want the final %q", rec.FinalSHA256, out.Final)
	}
	if rec.ServerKey == "" {
		t.Fatal("receipt has no server_key")
	}
	if len(rec.Parties) != 2 {
		t.Fatalf("receipt has %d parties, want 2", len(rec.Parties))
	}
	// The chain the receipt attests is the envelope's chain: certification, then
	// one signature per party.
	if want := len(f.revisions()); len(rec.Revisions) != want {
		t.Fatalf("receipt has %d revisions, want the envelope's %d", len(rec.Revisions), want)
	}
	kinds := map[string]int{}
	for _, r := range rec.Revisions {
		kinds[r.Kind]++
	}
	if kinds[signstore.KindCertified] != 1 {
		t.Fatalf("receipt revisions = %+v, want one certified row", rec.Revisions)
	}
	if kinds[KindSign] != 2 {
		t.Fatalf("receipt revisions = %+v, want two sign rows", rec.Revisions)
	}
	if !rec.Verification.Valid || len(rec.Verification.Signers) != 3 {
		t.Fatalf("receipt verification = %+v, want valid with 3 signers", rec.Verification)
	}
	// envelope.current_sha == receipt final_sha256 == sha(stored bytes)
	env, err := f.deps.Store.GetEnvelope(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.CurrentSHA != rec.FinalSHA256 {
		t.Fatalf("envelope current_sha = %q, want receipt final_sha256 %q", env.CurrentSHA, rec.FinalSHA256)
	}
	blob, err := f.deps.Store.GetPDF(rec.FinalSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(blob); got != rec.FinalSHA256 {
		t.Fatalf("sha(document) = %q, want receipt final_sha256 %q", got, rec.FinalSHA256)
	}
	// The receipt is stored under the document it describes, so a reader who has
	// the document can find the evidence without being told where it is.
	if _, err := os.Stat(filepath.Join(f.deps.Store.StorageDir(), rec.FinalSHA256+".receipt.json")); err != nil {
		t.Fatalf("receipt is not stored beside the document: %v", err)
	}
}

// --- 8. completed -> delivery rows ----------------------------------------

// The batch's completion produces one delivery record per party, each naming
// the final bytes. The copy is sent in the request that produced it, so the
// record and the send are the same event: a party with a row has been mailed.
func TestBatchCompletionRecordsOneDeliveryPerParty(t *testing.T) {
	f := newBatchFixture(t, 3)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	for out.Status != string(Delivered) {
		out, err = f.runBatch()
		if err != nil {
			t.Fatalf("second batch run: %v", err)
		}
	}
	deliveries, err := f.deps.Store.ListDeliveries(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("deliveries = %d, want one per party", len(deliveries))
	}
	seen := map[string]bool{}
	for _, dl := range deliveries {
		if dl.Status != signstore.DeliveryAccepted {
			t.Fatalf("party %s delivery = %q, want %q",
				dl.PartyID, dl.Status, signstore.DeliveryAccepted)
		}
		if dl.SHA256 != out.Final {
			t.Fatalf("party %s delivery is of %q, want the final %q",
				dl.PartyID, dl.SHA256, out.Final)
		}
		if dl.DeliveredAt == "" {
			t.Fatalf("party %s delivery has no delivered_at", dl.PartyID)
		}
		seen[dl.PartyID] = true
	}
	for _, id := range f.partyID {
		if !seen[id] {
			t.Fatalf("party %s has no delivery record", id)
		}
	}
}

// --- 9. delivery: one signed message per party ----------------------------

func TestDeliverySendsOneSignedDocumentPerParty(t *testing.T) {
	f := newBatchFixture(t, 3)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	for out.Status != string(Delivered) {
		out, err = f.runBatch()
		if err != nil {
			t.Fatalf("second batch run: %v", err)
		}
	}

	files := emlFiles(t, f.outbox)
	var signed []string
	for _, name := range files {
		if strings.HasPrefix(name, "signed-") {
			signed = append(signed, name)
		}
	}
	if len(signed) != 3 {
		t.Fatalf("outbox holds %d signed messages, want one per party: %v", len(signed), files)
	}
	env, err := f.deps.Store.GetEnvelope(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	finalSHA := env.CurrentSHA
	partyEmails := map[string]string{}
	for _, id := range f.partyID {
		p, err := f.deps.Store.GetParty(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		partyEmails[p.Email] = p.Name
	}
	seen := map[string]int{}
	for _, name := range signed {
		raw, err := os.ReadFile(filepath.Join(f.outbox, name))
		if err != nil {
			t.Fatal(err)
		}
		msg, _, err := signmail.Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		to := strings.ToLower(strings.TrimSpace(msg.To))
		if strings.Contains(to, ",") {
			t.Fatalf("%s goes to more than one recipient: %q", name, to)
		}
		if _, ok := partyEmails[to]; !ok {
			t.Fatalf("%s goes to %q, which is not a party of this envelope", name, to)
		}
		seen[to]++
		if len(msg.Files) != 2 {
			t.Fatalf("%s carries %d attachments, want the document and the receipt: %v",
				name, len(msg.Files), attachmentNames(msg))
		}
		var blob, rcpt []byte
		for _, fl := range msg.Files {
			switch {
			case strings.HasSuffix(fl.Name, "-signed.pdf"):
				blob = fl.Data
			case strings.HasSuffix(fl.Name, "receipt.json"):
				rcpt = fl.Data
			default:
				t.Fatalf("%s carries an attachment nobody asked for: %q", name, fl.Name)
			}
		}
		if blob == nil || rcpt == nil {
			t.Fatalf("%s attachments = %v, want a signed pdf and a receipt", name, attachmentNames(msg))
		}
		var attached Receipt
		if err := json.Unmarshal(rcpt, &attached); err != nil {
			t.Fatalf("%s receipt attachment does not decode: %v", name, err)
		}
		if attached.FinalSHA256 != finalSHA {
			t.Fatalf("%s receipt names %q, want the final document %q", name, attached.FinalSHA256, finalSHA)
		}
		if got := sha256Hex(blob); got != finalSHA {
			t.Fatalf("%s attachment sha = %q, want the final document %q", name, got, finalSHA)
		}
		rep, err := f.deps.Signer.Verify(ctx, blob)
		if err != nil || !rep.Valid {
			t.Fatalf("%s attachment does not verify: valid=%v err=%v", name, rep != nil && rep.Valid, err)
		}
		if len(rep.Signers) != 4 {
			t.Fatalf("%s attachment has %d signers, want 4", name, len(rep.Signers))
		}
	}
	for _, email := range []string{"party1@example.test", "party2@example.test", "party3@example.test"} {
		if seen[email] != 1 {
			t.Fatalf("%s received %d signed copies, want exactly 1", email, seen[email])
		}
	}
	// A party with no consent gets no copy.
	if n := countEmlWith(t, f.outbox, "signed-"); n != 3 {
		t.Fatalf("outbox signed files = %d, want 3", n)
	}
}

// TestDeliveryOfLargeDocumentUsesADownloadLink is the other half of acceptance
// 6: a document past AttachLimit cannot travel as an attachment, so the message
// offers a download link and carries only the receipt. The link is exercised for
// real, because a URL in a body that does not resolve is a party with no
// document.
func TestDeliveryOfLargeDocumentUsesADownloadLink(t *testing.T) {
	// The limit is dropped to a few bytes so the signed document of the fixture
	// counts as "too large". The number is not the point; the branch it selects
	// is.
	saved := AttachLimit
	t.Cleanup(func() { AttachLimit = saved })
	AttachLimit = 128

	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	for out.Status != string(Delivered) {
		out, err = f.runBatch()
		if err != nil {
			t.Fatalf("second batch run: %v", err)
		}
	}

	env, err := f.deps.Store.GetEnvelope(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	finalSHA := env.CurrentSHA

	signed := 0
	for _, name := range emlFiles(t, f.outbox) {
		if !strings.HasPrefix(name, "signed-") {
			continue
		}
		signed++
		raw, err := os.ReadFile(filepath.Join(f.outbox, name))
		if err != nil {
			t.Fatal(err)
		}
		msg, _, err := signmail.Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		// Only the receipt travels; the document does not.
		if len(msg.Files) != 1 || !strings.HasSuffix(msg.Files[0].Name, "receipt.json") {
			t.Fatalf("%s carries %v, want only the receipt", name, attachmentNames(msg))
		}
		var attached Receipt
		if err := json.Unmarshal(msg.Files[0].Data, &attached); err != nil {
			t.Fatalf("%s receipt attachment does not decode: %v", name, err)
		}
		if attached.FinalSHA256 != finalSHA {
			t.Fatalf("%s receipt names %q, want the final document %q",
				name, attached.FinalSHA256, finalSHA)
		}
	}
	if signed != 2 {
		t.Fatalf("outbox holds %d signed messages, want one per party", signed)
	}

	// Every party's delivery record says "link", the message sent to that party
	// carries its own link in full, and the link serves the document.
	deliveries, err := f.deps.Store.ListDeliveries(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("delivery records = %d, want 2", len(deliveries))
	}
	for _, rec := range deliveries {
		if rec.Method != "link" {
			t.Fatalf("party %s delivered by %q, want link", rec.PartyID, rec.Method)
		}
		if rec.DownloadID == "" {
			t.Fatalf("party %s has no download token", rec.PartyID)
		}
		p, err := f.deps.Store.GetParty(ctx, rec.PartyID)
		if err != nil {
			t.Fatal(err)
		}
		url := DownloadLinkFor(f.deps.linkBase(), rec.DownloadID)
		if !f.bodyCarries(t, p.Email, url) {
			t.Fatalf("the message for %s does not carry the download link %s", p.Email, url)
		}
		// The link resolves, and serves the document Gate 2 verified.
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.deps.DownloadHandler(f.deps.Store, w, req, rec.DownloadID)
		if w.Code != http.StatusOK {
			t.Fatalf("download of party %s: status %d", rec.PartyID, w.Code)
		}
		if w.Header().Get("Content-Type") != "application/pdf" {
			t.Fatalf("download content type %q", w.Header().Get("Content-Type"))
		}
		if got := sha256Hex(w.Body.Bytes()); got != finalSHA {
			t.Fatalf("download served sha %q, want the final document %q", got, finalSHA)
		}
		rep, err := f.deps.Signer.Verify(ctx, w.Body.Bytes())
		if err != nil || !rep.Valid {
			t.Fatalf("downloaded document does not verify: valid=%v err=%v",
				rep != nil && rep.Valid, err)
		}
	}
}

// bodyCarries reports whether the signed message addressed to one email contains
// a string in full. The address is what ties a message on disk to a party.
func (f *batchFixture) bodyCarries(t *testing.T, email, want string) bool {
	t.Helper()
	for _, name := range emlFiles(t, f.outbox) {
		if !strings.HasPrefix(name, "signed-") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(f.outbox, name))
		if err != nil {
			t.Fatal(err)
		}
		msg, _, err := signmail.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(strings.TrimSpace(msg.To), email) {
			return strings.Contains(msg.Text, want)
		}
	}
	t.Fatalf("no signed message in %s addressed to %s", f.outbox, email)
	return false
}

func countEmlWith(t *testing.T, dir, prefix string) int {
	t.Helper()
	n := 0
	for _, name := range emlFiles(t, dir) {
		if strings.HasPrefix(name, prefix) {
			n++
		}
	}
	return n
}

func emlFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".eml") {
			out = append(out, e.Name())
		}
	}
	return out
}

// attachmentNames is what a failure reads: the file names one message carries.
func attachmentNames(msg *signmail.Message) []string {
	out := make([]string, 0, len(msg.Files))
	for _, f := range msg.Files {
		out = append(out, fmt.Sprintf("%s (%d bytes)", f.Name, len(f.Data)))
	}
	return out
}

// mustRead reads a file the test has already been told exists.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- 10. Gate 2: tampered storage -----------------------------------------

// TestDeliveryGate2RefusesTamperedDocument is acceptance 7: a document that
// passed Gate 1 is swapped under Gate 2's feet, and Gate 2 is the thing that
// notices.
//
// The swap is staged from outside the service on purpose. The store is
// content-addressed and immutable, so nothing inside it can produce a file whose
// name does not match its bytes; writing the bytes under the wrong name is
// exactly the attack the gate exists for.
func TestDeliveryGate2RefusesTamperedDocument(t *testing.T) {
	// A relay that refuses everything keeps the copies in the outbox unwritten,
	// so the gate is the last thing standing between the tampered bytes and a
	// party's inbox.
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	// The relay is dead before a single copy can be built, so the only thing
	// that can stop the tampered bytes reaching an inbox is the gate.
	f.deps.Mail.Sender = &failingSender{}
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	out, err := f.runBatch()
	if err == nil {
		t.Fatal("the batch reported success with a relay that refuses everything")
	}
	if out == nil || out.Final == "" {
		t.Fatal("the batch did not report which document it produced")
	}
	if n := countEmlWith(t, f.outbox, "signed-"); n != 0 {
		t.Fatalf("outbox signed files = %d with a dead relay, want 0", n)
	}
	tamperStoredPDF(t, f.deps.Store, out.Final)
	dl, err := f.deps.Deliver(ctx, f.env.ID, out.Final)
	if !errors.Is(err, ErrVerifyGate) {
		t.Fatalf("deliver tampered bytes: err = %v, want %v", err, ErrVerifyGate)
	}
	if dl != nil && dl.Accepted != 0 {
		t.Fatalf("tampered document reached %d parties, want 0", dl.Accepted)
	}
	// Nothing was mailed, and nothing will be: the gate ran before the send.
	if n := countEmlWith(t, f.outbox, "signed-"); n != 0 {
		t.Fatalf("outbox signed files = %d after Gate 2 refused, want 0", n)
	}
	for _, id := range f.partyID {
		rec, rerr := f.deps.Store.GetDelivery(ctx, f.env.ID, id)
		if rerr != nil {
			t.Fatalf("read delivery record for %s: %v", id, rerr)
		}
		if rec.Status != signstore.DeliveryRefused {
			t.Fatalf("party %s delivery status = %q, want %q", id, rec.Status, signstore.DeliveryRefused)
		}
		if rec.SHA256 != out.Final {
			t.Fatalf("delivery record names %q, want the document it refused (%q)", rec.SHA256, out.Final)
		}
		if !strings.Contains(rec.LastError, "hash") {
			t.Fatalf("delivery refusal reason = %q, want it to state the digest mismatch", rec.LastError)
		}
	}
	if got := f.status(); got == string(Delivered) {
		t.Fatalf("envelope status = %q although no party received a document", got)
	}
	// The audit event states both digests in full: what the name promised, and
	// what the bytes actually were.
	events := f.events("verify_failed")
	if len(events) == 0 {
		t.Fatal("Gate 2 refused without writing a verify_failed event")
	}
	var gate map[string]any
	if err := json.Unmarshal([]byte(events[len(events)-1].Payload), &gate); err != nil {
		t.Fatalf("decode verify_failed payload: %v", err)
	}
	if gate["expected_sha"] != out.Final {
		t.Fatalf("verify_failed expected_sha = %v, want the finished document %s", gate["expected_sha"], out.Final)
	}
	gotSHA, _ := gate["got_sha"].(string)
	if len(gotSHA) != 64 || gotSHA == out.Final {
		t.Fatalf("verify_failed got_sha = %q, want the digest the tampered bytes hash to", gotSHA)
	}
	// A refused envelope has no live download link either: an unknown token is
	// gone, not a way in.
	w := httptest.NewRecorder()
	f.deps.DownloadHandler(f.deps.Store, w, httptest.NewRequest(http.MethodGet, "/d/x", nil),
		strings.Repeat("0", 64))
	if w.Code != http.StatusGone {
		t.Fatalf("unknown download token answers %d, want %d", w.Code, http.StatusGone)
	}
}

// TestDeliveryReissueOverTamperedBytesKeepsTheAcceptedRecords is the same attack
// one step later: the copies already went out, and a re-delivery is asked for
// after the file was swapped.
func TestDeliveryReissueOverTamperedBytesKeepsTheAcceptedRecords(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	tamperStoredPDF(t, f.deps.Store, out.Final)
	if _, err := f.deps.Deliver(ctx, f.env.ID, out.Final); !errors.Is(err, ErrVerifyGate) {
		t.Fatalf("reissue over tampered bytes: err = %v, want %v", err, ErrVerifyGate)
	}
	if n := countEmlWith(t, f.outbox, "signed-"); n != 2 {
		t.Fatalf("outbox signed files = %d after a refused reissue, want the 2 already sent", n)
	}
	// A copy a party already received is not rewritten by a later refusal; the
	// refusal is recorded as an event.
	events := f.events("verify_failed")
	if len(events) == 0 {
		t.Fatal("the refused reissue wrote no verify_failed event")
	}
	var gate map[string]any
	if err := json.Unmarshal([]byte(events[len(events)-1].Payload), &gate); err != nil {
		t.Fatalf("decode verify_failed payload: %v", err)
	}
	if gate["expected_sha"] != out.Final {
		t.Fatalf("verify_failed expected_sha = %v, want %s", gate["expected_sha"], out.Final)
	}
	if gotSHA, _ := gate["got_sha"].(string); len(gotSHA) != 64 || gotSHA == out.Final {
		t.Fatalf("verify_failed got_sha = %q, want the tampered digest", gotSHA)
	}
}

// tamperStoredPDF flips a byte inside the signed document's content, leaving a
// readable PDF whose signatures no longer hold.
func tamperStoredPDF(t *testing.T, store *signstore.Store, sha string) {
	t.Helper()
	data, err := store.GetPDF(sha)
	if err != nil {
		t.Fatalf("read stored document: %v", err)
	}
	// Tamper inside the last content stream: bytes the signatures cover, away
	// from the xref table at the tail, so the file stays a readable PDF whose
	// signatures no longer hold.
	i := bytes.LastIndex(data, []byte("stream"))
	if i < 0 {
		t.Fatalf("cannot find a place to tamper in the stored document")
	}
	i += len("stream") + 3
	if i >= len(data)-16 {
		t.Fatalf("the document is too small to tamper inside")
	}
	data[i] = 'X'
	data[i+1] = 'Y'
	// The storage is content-addressed, so a swap is not a write: the file that
	// carries the name of the digest stops carrying the bytes the digest was
	// computed over. That is exactly the attack Gate 2 exists for, and it is the
	// only way to stage it — the store itself would never produce it.
	path := filepath.Join(store.StorageDir(), sha+".pdf")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("swap the stored document: %v", err)
	}
	if got := sha256Hex(mustRead(t, path)); got == sha || len(got) != 64 {
		t.Fatalf("the swap did not take: %s hashes to %s", path, got)
	}
}

func envelopeIDForSHA(t *testing.T, store *signstore.Store, sha string) string {
	t.Helper()
	var id string
	if err := store.DB().QueryRow(`select envelope_id from revisions where sha256 = ? limit 1`, sha).
		Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// --- 11. batch settings ---------------------------------------------------

// TestBatchSettingsAreValidatedAtTheBoundary checks the settings the batch
// depends on. tsa_url decides whether a signature can be time-stamped at all,
// so a value the batch cannot use has to be refused when it is written, not
// five attempts later.
func TestBatchSettingsAreValidatedAtTheBoundary(t *testing.T) {
	bad := map[string]string{
		"tsa_url":  "not-a-url",
		"link_ttl": "not-a-duration",
	}
	for field, value := range bad {
		err := validateSettingValue(field, value)
		if err == nil {
			t.Fatalf("setting %s = %q was accepted", field, value)
		}
		var ve *ErrValidation
		if !errors.As(err, &ve) {
			t.Fatalf("setting %s error = %v, want a field validation error", field, err)
		}
		if ve.Field != field {
			t.Fatalf("setting %s blamed field %q", field, ve.Field)
		}
		if ve.Hint == "" {
			t.Fatalf("setting %s has no hint", field)
		}
	}
	good := map[string]string{
		"tsa_url":  "https://freetsa.org/tsr",
		"link_ttl": "48h",
	}
	for field, value := range good {
		if err := validateSettingValue(field, value); err != nil {
			t.Fatalf("setting %s = %q rejected: %v", field, value, err)
		}
	}
	// A setting the batch would read but no code owns is refused rather than
	// silently ignored: a typo in a name is how an operator ends up with a
	// setting that does nothing.
	f := newBatchFixture(t, 1)
	_, err := f.deps.WriteSettings(context.Background(), map[string]string{"batch.tries": "9"}, "admin:test")
	if err == nil {
		t.Fatal("an unknown settings key was accepted")
	}
	var ve *ErrValidation
	if !errors.As(err, &ve) {
		t.Fatalf("unknown key error = %v, want a field validation error", err)
	}
}

// --- 12. idempotency ------------------------------------------------------

func TestBatchIsIdempotent(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")

	first, err := f.runBatch()
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	before := len(f.revisions())
	// The first run consumed the queue row, so the second run is the operator
	// asking for the batch again on an envelope that is already signed.
	second, err := f.signNow()
	if err != nil {
		t.Fatalf("second batch: %v", err)
	}
	after := len(f.revisions())
	if after != before {
		t.Fatalf("second batch added %d revisions: %d -> %d", after-before, before, after)
	}
	if second.Signed != 0 {
		t.Fatalf("second batch signed %d parties, want 0", second.Signed)
	}
	if second.Final != first.Final {
		t.Fatalf("second batch final = %q, want the same document %q", second.Final, first.Final)
	}
	// A batch requeued on purpose re-verifies and re-delivers, but does not sign
	// the same party twice: the consent row is the gate, and it is already spent.
	if err := f.deps.Store.EnqueueBatch(ctx, f.env.ID, ""); err != nil {
		t.Fatalf("requeue batch: %v", err)
	}
	third, err := f.runBatch()
	if err != nil {
		t.Fatalf("third batch: %v", err)
	}
	if third.Signed != 0 {
		t.Fatalf("requeued batch signed %d parties, want 0", third.Signed)
	}
	if n := len(f.revisions()); n != before {
		t.Fatalf("revisions after a requeued batch = %d, want %d", n, before)
	}
	if dl, err := f.deps.Store.ListDeliveries(ctx, f.env.ID); err != nil || len(dl) != 2 {
		t.Fatalf("deliveries = %d (err %v), want 2 (one per party, not two each)", len(dl), err)
	}
	if n := countEmlWith(t, f.outbox, "signed-"); n != 2 {
		t.Fatalf("outbox signed files = %d after three batch runs, want 2", n)
	}
}

// --- 12b. a tampered batch input is refused, and nothing is mailed ---------

// The batch input is the certified document. When the bytes under that digest
// have been changed, every signature the batch adds is an approval of tampered
// content, and the verification at Gate 1 is what says so. The envelope closes
// as failed and the outbox stays empty: a document nobody can vouch for is not
// sent to three people and called signed.
func TestBatchTamperedInputFailsAndSendsNoEmail(t *testing.T) {
	f := newBatchFixture(t, 3)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")

	certified := f.baseRevisions() - 1
	tamperStoredPDF(t, f.deps.Store, f.revisions()[certified].SHA256)

	out, err := f.runBatch()
	if err == nil {
		t.Fatal("batch over tampered bytes returned no error")
	}
	if out == nil {
		t.Fatal("batch over tampered bytes returned no outcome")
	}
	if out.Status != string(Failed) {
		t.Fatalf("envelope status after tampered batch = %q, want %q", out.Status, Failed)
	}
	if got := f.status(); got != string(Failed) {
		t.Fatalf("stored status = %q, want %q", got, Failed)
	}
	if n := countEmlWith(t, f.outbox, "signed-"); n != 0 {
		t.Fatalf("outbox signed files = %d, want 0: a refused document is not mailed", n)
	}
	if dl, err := f.deps.Store.ListDeliveries(ctx, f.env.ID); err != nil || len(dl) != 0 {
		t.Fatalf("deliveries = %d (err %v), want 0", len(dl), err)
	}
	if len(f.events("batch_failed")) == 0 && len(f.events("verify_failed")) == 0 {
		t.Fatal("a refused batch left no failure event")
	}
}

// --- 12c. GET /report is the receipt --------------------------------------

// The report endpoint returns the receipt of the current document, and the
// receipt's signature records name the certificates the signatures carry: the
// serial and the SHA-256 of the leaf certificate's DER, which an auditor can
// match against the certificate embedded in the PDF.
func TestReportMatchesStoredLeafCertificates(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	// The batch runs a minute later. consent_at and signed_at are separate
	// facts and the receipt must not collapse them into one timestamp.
	advanceClock(t, time.Minute)
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	for out.Status != string(Delivered) {
		out, err = f.runBatch()
		if err != nil {
			t.Fatalf("second batch run: %v", err)
		}
	}
	dl, err := f.deps.Store.ListDeliveries(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dl) != 2 {
		t.Fatalf("deliveries = %d, want 2", len(dl))
	}
	data, err := f.deps.GetReceipt(out.Final)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var rec Receipt
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if !rec.Valid {
		t.Fatal("receipt of a clean batch is not valid")
	}
	if len(rec.Verification.Signers) != 3 {
		t.Fatalf("report signers = %d, want 3 (certification and two parties)",
			len(rec.Verification.Signers))
	}
	revs := f.partyRevisions()
	if len(revs) != 2 {
		t.Fatalf("party revisions = %d, want 2", len(revs))
	}
	byParty := map[string]signstore.Revision{}
	for _, r := range revs {
		byParty[r.PartyID] = r
	}
	for _, rp := range rec.Parties {
		r, ok := byParty[f.partyID[rp.Order-1]]
		if !ok {
			t.Fatalf("receipt party order %d has no party revision", rp.Order)
		}
		if rp.CertSerial == "" || rp.CertSerial != r.CertSerial {
			t.Fatalf("receipt party %d cert_serial = %q, stored %q: want the serial on the revision",
				rp.Order, rp.CertSerial, r.CertSerial)
		}
		if len(rp.CertFingerprint) != 64 || rp.CertFingerprint != r.CertFingerprint {
			t.Fatalf("receipt party %d cert_fingerprint = %q, stored %q: want the leaf DER digest",
				rp.Order, rp.CertFingerprint, r.CertFingerprint)
		}
		if rp.ConsentAt == "" || rp.SignedAt == "" || rp.ConsentAt == rp.SignedAt {
			t.Fatalf("receipt party %d consent_at=%q signed_at=%q: want both, and not equal",
				rp.Order, rp.ConsentAt, rp.SignedAt)
		}
		if !rp.TSA.Present {
			t.Fatalf("receipt party %d reports no timestamp token", rp.Order)
		}
	}
}

// --- 13. party rows and link lifetime -------------------------------------

func TestBatchMarksPartyRowsAndClosesSigningLinks(t *testing.T) {
	f := newBatchFixture(t, 2)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	// Delivered_at is the delivery stamp, so the queue must be drained to the
	// point every party's copy has been accepted.
	defer advanceClock(t, time.Minute)
	// The tokens are live before the batch.
	for i, tok := range f.tokens {
		if _, err := ResolveSigner(ctx, f.deps.Store, tok, time.Now()); err != nil {
			t.Fatalf("token %d is not live before the batch: %v", i+1, err)
		}
	}
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("run batch: %v", err)
	}
	for out.Status != string(Delivered) {
		out, err = f.runBatch()
		if err != nil {
			t.Fatalf("delivery batch: %v", err)
		}
	}
	for i, id := range f.partyID {
		p, err := f.deps.Store.GetParty(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != signstore.PartyConsented {
			t.Fatalf("party %d status = %q, want consented", i+1, p.Status)
		}
		if p.DeliveredAt == "" {
			t.Fatalf("party %d has no delivered_at stamp", i+1)
		}
		if p.ConsentAt == "" {
			t.Fatalf("party %d has no consent_at stamp", i+1)
		}
	}
	// After delivery, the same token is refused: the link's purpose is spent, and
	// the refusal is ErrLinkClosed, not a token problem.
	for i, tok := range f.tokens {
		if _, err := ResolveSigner(ctx, f.deps.Store, tok, time.Now()); !errors.Is(err, ErrLinkClosed) {
			t.Fatalf("token %d after delivery: err = %v, want %v", i+1, err, ErrLinkClosed)
		}
	}
	_ = out
}

// --- 14. one consent, other parties outstanding ---------------------------

func TestBatchWithOneConsentLeavesEnvelopeOpen(t *testing.T) {
	f := newBatchFixture(t, 3)
	ctx := context.Background()
	f.consent(0, "Alice Adamson")

	// Nothing is signed: the batch signs the envelope as a whole, so an envelope
	// with a party outstanding is not ready work. The queue has no row for it;
	// the operator's explicit "sign now" is what reaches the batch here.
	out, err := f.signNow()
	if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("run batch with two parties outstanding: err = %v, want %v", err, ErrStateConflict)
	}
	if out == nil {
		t.Fatal("batch returned no outcome alongside the refusal")
	}
	if out.Signed != 0 {
		t.Fatalf("batch signed %d parties, want 0", out.Signed)
	}
	if got := f.status(); got != string(Collecting) {
		t.Fatalf("envelope status = %q, want %q", got, Collecting)
	}
	if n := len(f.partyRevisions()); n != 0 {
		t.Fatalf("revisions written = %d, want 0", n)
	}
	// Every party's link is still live, including the one that consented: a
	// consent is an agreement, not a signature, and the party can return.
	for i := 0; i < 3; i++ {
		if _, err := ResolveSigner(ctx, f.deps.Store, f.tokens[i], time.Now()); err != nil {
			t.Fatalf("party %d link is closed after one consent: %v", i+1, err)
		}
	}
	// No delivery, no delivered_at, and the document is still the certified one.
	if dl, err := f.deps.Store.ListDeliveries(ctx, f.env.ID); err != nil || len(dl) != 0 {
		t.Fatalf("deliveries = %d (err %v), want 0", len(dl), err)
	}
	env, err := f.deps.Store.GetEnvelope(ctx, f.env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.DeliveredAt != "" {
		t.Fatalf("envelope delivered_at = %q before every party has signed", env.DeliveredAt)
	}
	if env.CurrentSHA != f.dsha {
		t.Fatalf("envelope current_sha = %s, want the certified document %s", env.CurrentSHA, f.dsha)
	}
}
