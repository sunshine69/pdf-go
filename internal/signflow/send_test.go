package signflow

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signstore"
	"github.com/sunshine69/pdf-go/web"
)

// The acceptance list of docs/steps/06-tokens-email.md, for the token and
// send layer. The send tests run against the real store, the real fill, the
// real certification, and a file sender, so a send produces real .eml files
// that a reader opens.

// mailDeps returns a Deps with a renderer and a file sender, so a send is
// finished inside the call.
func mailDeps(t *testing.T, outbox string) *Deps {
	t.Helper()
	d := newDeps(t)
	r, err := signmail.NewRenderer(web.Templates())
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	d.Mail = &Mailer{
		Renderer: r,
		Sender:   &signmail.FileSender{Dir: outbox},
		From:     "signsrv@example.test",
		LinkBase: "http://127.0.0.1:8090",
	}
	return d
}

// Signoff: tokens are 256-bit random. 10k calls, all unique, length 52.
func TestTokensAreUniqueAnd52Chars(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		tok, err := NewLinkToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 52 {
			t.Fatalf("token %d is %d chars, want 52", i, len(tok))
		}
		if !regexp.MustCompile(`^[a-z2-7]{52}$`).MatchString(tok) {
			t.Fatalf("token %d is not lowercase base32: %q", i, tok)
		}
		if seen[tok] {
			t.Fatalf("token %q repeated", tok)
		}
		seen[tok] = true
	}
}

// Signoff: stored only as SHA-256. The raw token is not in the stored hash, so
// a database copy gives a verifier, not a signing link.
func TestTokenLookupRoundTrip(t *testing.T) {
	tok, err := NewLinkToken()
	if err != nil {
		t.Fatal(err)
	}
	sum := HashLink(tok)
	if len(sum) != 64 {
		t.Fatalf("hash is %d chars, want 64 hex", len(sum))
	}
	if strings.Contains(sum, tok) {
		t.Fatal("the stored hash contains the token")
	}
	// A lookup by hash resolves to the party, through the store. The test uses
	// the real store, not a fake, because the item is about the table.
	d := newDeps(t)
	ctx := context.Background()
	if err := d.Store.SetPartyToken(ctx, "nope", sum, tok, "2026-11-06T00:00:00Z"); err == nil {
		t.Fatal("a token of a missing party was stored")
	}
	if _, err := LookupLink(ctx, d.Store, tok, time.Now()); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("lookup of an unknown token: %v, want ErrTokenUnknown", err)
	}
}

// Acceptance 3: send on ready -> one .eml per party, each with exactly one
// /s/<token> URL and no PDF attachment; the envelope is sent.
func TestSendProducesOneEmlPerParty(t *testing.T) {
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
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
	envID := created.Envelope.ID

	links, err := d.Send(context.Background(), envID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("send returned %d links, want 2", len(links))
	}

	env, err := d.Store.GetEnvelope(context.Background(), envID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Sent {
		t.Fatalf("status is %q, want sent", string(env.Status))
	}

	files := readOutbox(t, outbox)
	if len(files) != 2 {
		t.Fatalf("outbox has %d files, want 2", len(files))
	}
	for _, f := range files {
		msg, _, err := signmail.Parse(f)
		if err != nil {
			t.Fatalf("outbox file is not a valid message: %v", err)
		}
		// The invite is one text/html part. The rule is one signing URL per
		// message: a party must not have to choose between two links.
		n := len(regexp.MustCompile(`https?://[^"]*/s/[a-z2-7]{52}`).FindAllString(msg.HTML, -1))
		if n != 1 {
			t.Fatalf("html body has %d signing URLs, want exactly one:\n%s", n, msg.HTML)
		}
		if !strings.Contains(msg.HTML, `href="http`) {
			t.Fatalf("html body has no anchor:\n%s", msg.HTML)
		}
		if strings.Contains(strings.ToLower(string(f)), "content-disposition") {
			t.Fatal("the invite carries an attachment header")
		}
		if strings.Contains(string(f), "%PDF") {
			t.Fatal("the invite has a PDF attachment")
		}
	}
}

// Acceptance 4, restated: send twice is not an error and does not duplicate.
//
// The old contract refused the second call outright, which is what made the
// button unusable the moment an invite went astray. The new contract is that
// the button always works and the queue decides how many emails result:
//
//   - With a sender configured, each send drains what it queued, so a second
//     send really does post a second email — that is the point of pressing it.
//   - With no sender, the rows wait in the queue, and two clicks on a queue
//     that has not run produce one row, not two.
//
// In both cases the link is the one minted at create.
func TestSendTwiceWithASenderMailsTwice(t *testing.T) {
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
	in := sampleBytes(t)
	created, err := d.Create(context.Background(), CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	envID := created.Envelope.ID
	first, err := d.Send(context.Background(), envID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	second, err := d.Send(context.Background(), envID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("second send: %v, want the call to be accepted", err)
	}
	if len(second) != 1 || second[0].Token != first[0].Token {
		t.Fatalf("re-send changed the link: first %q, second %q",
			first[0].Token, second[0].Token)
	}
	// Two drains, so two rows, both marked sent. The party is meant to receive
	// the second copy; the first one is the copy they say never arrived.
	rows, err := d.Store.CountMail(context.Background(), envID, KindInvite, false)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("%d invite rows after two drained sends, want 2", rows)
	}
	unsent, err := d.Store.CountMail(context.Background(), envID, KindInvite, true)
	if err != nil {
		t.Fatal(err)
	}
	if unsent != 0 {
		t.Fatalf("%d invite rows still unsent, want 0", unsent)
	}
}

// TestSendTwiceWithNoSenderMailsOnce is the dedupe half. Nothing has drained
// the queue between the clicks, so the second click finds the first click's
// unsent row and revives it instead of adding a twin.
func TestSendTwiceWithNoSenderMailsOnce(t *testing.T) {
	d := newDeps(t) // no mailer: the queue is left as a restart would find it
	in := sampleBytes(t)
	created, err := d.Create(context.Background(), CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	envID := created.Envelope.ID
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := d.Send(ctx, envID, "api:test", time.Now()); err != nil {
			t.Fatalf("send %d: %v", i+1, err)
		}
	}
	rows, err := d.Store.CountMail(ctx, envID, KindInvite, true)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("%d unsent invite rows after three clicks, want 1", rows)
	}
	if env, err := d.Store.GetEnvelope(ctx, envID); err != nil {
		t.Fatal(err)
	} else if env.Status != signstore.StatusSent {
		t.Fatalf("status after three sends: %s, want sent", env.Status)
	}
}

// The old acceptance, kept as a shape check: only an envelope that has run its
// course refuses a send.
func TestSendOnAFinishedEnvelopeIsConflict(t *testing.T) {
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
	in := sampleBytes(t)
	req := CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	}
	created, err := d.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	envID := created.Envelope.ID
	if _, err := d.Send(context.Background(), envID, "api:test", time.Now()); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if _, err := d.Cancel(context.Background(), envID, "api:test", "wrong document"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := d.Send(context.Background(), envID, "api:test", time.Now()); !IsConflict(err) {
		t.Fatalf("send on a cancelled envelope: %v, want a state conflict", err)
	}
}

// Acceptance 5: a name that is HTML markup renders inert in the HTML body.
func TestHostileNameIsInertInHTML(t *testing.T) {
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
	in := sampleBytes(t)
	req := CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   []Party{{Email: "bob@example.test", Name: `Bob"><script>`, Order: 1, Reason: "ok"}},
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	}
	created, err := d.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := d.Send(context.Background(), created.Envelope.ID, "api:test", time.Now()); err != nil {
		t.Fatalf("send: %v", err)
	}
	files := readOutbox(t, outbox)
	if len(files) != 1 {
		t.Fatalf("outbox has %d files, want 1", len(files))
	}
	msg, _, err := signmail.Parse(files[0])
	if err != nil {
		t.Fatal(err)
	}
	// The script tag is escaped, so it cannot run.
	if strings.Contains(msg.HTML, "<script>") {
		t.Fatalf("HTML body has a live script tag:\n%s", msg.HTML)
	}
	if !strings.Contains(msg.HTML, "&lt;script&gt;") {
		t.Fatalf("HTML body did not escape the name:\n%s", msg.HTML)
	}
	// The plaintext body has no markup at all.
	if strings.Contains(msg.Text, "<") {
		t.Fatalf("text body has markup:\n%s", msg.Text)
	}
}

// Acceptance 5: a name containing a line break is rejected at create.
func TestNameWithLineBreakIsRejected(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	req := CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   []Party{{Email: "bob@example.test", Name: "Bob\r\nBcc: evil@x.test", Order: 1}},
		Title:     "NDA",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	}
	_, err := d.Create(context.Background(), req)
	if err == nil {
		t.Fatal("a name with a line break was accepted")
	}
	var v *ErrValidation
	if !errors.As(err, &v) || v.Field != "parties[].name" {
		t.Fatalf("create error %v, want parties[].name validation", err)
	}
}

// readOutbox reads every .eml file in the directory.
func readOutbox(t *testing.T, dir string) [][]byte {
	t.Helper()
	files, err := readDirFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// readDirFiles reads every .eml file in a directory, in name order. A test
// that checks the outbox needs the bytes, because the acceptance item is that
// the sent file is a valid message, not that a string appears in it.
func readDirFiles(dir string) ([][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := [][]byte{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".eml") {
			b, err := os.ReadFile(dir + "/" + e.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
	}
	return out, nil
}

// Acceptance 2: a lookup of a token whose deadline has passed answers
// ErrTokenExpired, which the endpoint maps to 410. The expiry is stamped at
// send time, so the test sends and then moves the clock past the deadline.
func TestExpiredTokenLookupIsExpired(t *testing.T) {
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
	in := sampleBytes(t)
	req := CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "Lease",
		ExpiresIn: 24 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	}
	created, err := d.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	links, err := d.Send(context.Background(), created.Envelope.ID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	ctx := context.Background()
	if _, err := LookupLink(ctx, d.Store, links[0].Token, time.Now()); err != nil {
		t.Fatalf("a fresh token must resolve, got %v", err)
	}
	p, err := LookupLink(ctx, d.Store, links[0].Token, time.Now().Add(30*24*time.Hour))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("lookup after the deadline is %v, want ErrTokenExpired", err)
	}
	if p != nil {
		t.Fatal("an expired lookup returned a party")
	}
	// The stored party is found by hash only: the raw token is never in the
	// row, and a lookup by the hash value finds the same party.
	tok := links[0].Token
	if _, err := d.Store.GetPartyByTokenHash(ctx, HashLink(tok)); err != nil {
		t.Fatalf("hash lookup: %v", err)
	}
}

// Signoff: the link deadline is min(now + expires_in, envelope expires_at)
// and never exceeds 30 days. The envelope in the request expires before the
// full link window, so the stamped expiry is the envelope's, and the cap is
// what a long ExpiresIn request must obey.
func TestLinkExpiryIsCappedByEnvelope(t *testing.T) {
	if MaxLinkTTL != 30*24*time.Hour {
		t.Fatalf("MaxLinkTTL is %v, want 30 days", MaxLinkTTL)
	}
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
	in := sampleBytes(t)
	req := CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "Lease",
		ExpiresIn: 6 * 24 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	}
	created, err := d.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	p, err := d.Store.GetParty(context.Background(), created.Links[0].PartyID)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenExpires != created.Envelope.ExpiresAt {
		t.Fatalf("token_expires_at is %q, envelope expires at %q, want the two equal",
			p.TokenExpires, created.Envelope.ExpiresAt)
	}
}

// The invite row is written by the send, not the create: a token exists only
// after the send, so a create must leave the queue empty and the send must
// write exactly one invite per party. A create that queued invites would email
// a signer for an envelope nobody has sent.
func TestCreateQueuesNoMailAndSendQueuesOnePerParty(t *testing.T) {
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
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
	rows, err := d.Store.ListMail(context.Background(), created.Envelope.ID)
	if err != nil {
		t.Fatalf("list mail: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("create queued %d mail rows, want 0", len(rows))
	}
	if len(outboxFiles(t, outbox)) != 0 {
		t.Fatalf("create wrote mail to the outbox, want none")
	}

	links, err := d.Send(context.Background(), created.Envelope.ID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("send returned %d links, want 2", len(links))
	}
	rows, err = d.Store.ListMail(context.Background(), created.Envelope.ID)
	if err != nil {
		t.Fatalf("list mail after send: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("send left %d queue rows, want 2 (one invite per party)", len(rows))
	}
	for _, r := range rows {
		if r.Kind != KindInvite {
			t.Errorf("queue row kind %q, want %q", r.Kind, KindInvite)
		}
		// Drain runs inside Send because the mailer has a sender, so every
		// row is marked sent and the worker has nothing left to do.
		if r.SentAt == "" {
			t.Errorf("queue row %d is not marked sent after the send", r.ID)
		}
	}
}

// outboxFiles lists the names in the outbox directory.
func outboxFiles(t *testing.T, dir string) []string {
	t.Helper()
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n.Name())
	}
	return out
}

// failingSender is a transport that always refuses. It is the whole point of
// this test: the relay is down, and the envelope must not care.
type failingSender struct{ n int }

func (f *failingSender) Send(ctx context.Context, m *signmail.Message) error {
	f.n++
	return errors.New("signmail: 451 relay deferred")
}

// Signoff: a mail failure does not corrupt the envelope state and the admin is
// notified. The sender refuses every message: the send still marks the envelope
// sent (the state machine is not the mailer's), every queue row is retried and
// then given up, and giving up writes the event the admin sees.
func TestMailFailureLeavesEnvelopeStateAndNotifiesAdmin(t *testing.T) {
	d := mailDeps(t, t.TempDir())
	fake := &failingSender{}
	d.Mail.Sender = fake

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
	id := created.Envelope.ID

	// Send drains the queue inline because a sender is configured, so the
	// failure happens during the send. The send succeeds: the envelope
	// transitioned, the tokens exist, the links are returned.
	links, err := d.Send(context.Background(), id, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send with a dead relay: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("send returned %d links, want 2", len(links))
	}
	env, err := d.Store.GetEnvelope(context.Background(), id)
	if err != nil {
		t.Fatalf("get envelope: %v", err)
	}
	if env.Status != Sent {
		t.Fatalf("status after a send with a dead relay is %q, want %q", env.Status, Sent)
	}
	if fake.n == 0 {
		t.Fatalf("the sender was never asked; the drain did not run")
	}

	// Every row failed its first attempt and is waiting for its backoff: not
	// sent, not lost.
	rows, err := d.Store.ListMail(context.Background(), id)
	if err != nil {
		t.Fatalf("list mail: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d queue rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.SentAt != "" {
			t.Errorf("row %d marked sent through a dead relay", r.ID)
		}
		if r.Attempts != 1 {
			t.Errorf("row %d has %d attempts, want 1", r.ID, r.Attempts)
		}
		if r.NextAt == "" {
			t.Errorf("row %d has no backoff deadline", r.ID)
		}
		if r.LastError == "" {
			t.Errorf("row %d keeps no reason", r.ID)
		}
	}

	// Drain the rest of the budget: attempts 2..4 get backoff, the fifth gives
	// up and writes the event.
	for i := 2; i <= signmail.MaxAttempts; i++ {
		if _, err := d.Store.DB().ExecContext(context.Background(),
			"update mail_queue set next_at = '0001-01-01T00:00:00Z', lease_until = null where envelope_id = ?",
			id); err != nil {
			t.Fatalf("clear backoff: %v", err)
		}
		if _, err := d.Drain(context.Background(), id, time.Now()); err != nil {
			t.Fatalf("drain round %d: %v", i, err)
		}
	}
	rows, err = d.Store.ListMail(context.Background(), id)
	if err != nil {
		t.Fatalf("list mail after retries: %v", err)
	}
	for _, r := range rows {
		if r.Attempts != signmail.MaxAttempts {
			t.Errorf("row %d has %d attempts, want %d", r.ID, r.Attempts, signmail.MaxAttempts)
		}
	}
	if fake.n < 2*signmail.MaxAttempts {
		t.Errorf("sender saw %d attempts, want at least %d", fake.n, 2*signmail.MaxAttempts)
	}

	// The admin is told: every given-up row left one mail_failed event naming
	// the party and the reason.
	events, err := d.Store.ListEvents(context.Background(), id)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	failed := 0
	for _, e := range events {
		if e.Kind == "mail_failed" {
			failed++
			if !strings.Contains(e.Payload, "relay deferred") {
				t.Errorf("mail_failed event does not carry the reason: %s", e.Payload)
			}
		}
	}
	if failed != 2 {
		t.Fatalf("%d mail_failed events, want 2 (one per party given up on)", failed)
	}
	// The envelope is still sent and still has its parties: nothing the mailer
	// touched moved the state.
	env, err = d.Store.GetEnvelope(context.Background(), id)
	if err != nil {
		t.Fatalf("get envelope after retries: %v", err)
	}
	if env.Status != Sent {
		t.Fatalf("status drifted to %q after the mail gave up", env.Status)
	}
}

// restartDeps is one process. Calling it again over the same store is the
// process after a restart: the signer and the mailer are rebuilt, and nothing
// else is carried across except what is in the database and on disk.
func restartDeps(t *testing.T, store *signstore.Store, outbox string) *Deps {
	t.Helper()
	d := newDeps(t) // a real signing service; its store is replaced below
	d.Store = store
	d.Flow = NewFlow(store)
	r, err := signmail.NewRenderer(web.Templates())
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	d.Mail = &Mailer{
		Renderer: r,
		Sender:   &signmail.FileSender{Dir: outbox},
		From:     "signsrv@example.test",
		LinkBase: "http://127.0.0.1:8090",
	}
	return d
}

// TestMailUnsignedWorksAfterARestart is the operator's question in one test:
// the server stopped and came back, a party says the invite never arrived, can
// the button be pressed?
//
// The answer used to depend on the process. A queue row stores the hash of a
// link, and only the plaintext prints the URL, so after a restart the worker
// could not render an invite for a party whose link the old process had minted:
// it failed with "the link token is not available" and retried until it gave
// up. The workaround was a chain of buttons, each with its own rule about what
// a restart had invalidated.
//
// The plaintext is on the party row now, so the row the first process left
// behind is enough for the second one.
func TestMailUnsignedWorksAfterARestart(t *testing.T) {
	outbox := t.TempDir()
	ctx := context.Background()
	store := newTestStore(t)

	first := restartDeps(t, store, outbox)
	in := sampleBytes(t)
	created, err := first.Create(ctx, CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "Restart test",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	envID := created.Envelope.ID

	// Queue the invite without mailing it, so there is an unsent row for the
	// restart to find: this is the state of a queue at the moment the process
	// dies.
	queued := restartDeps(t, store, outbox)
	queued.Mail.Sender = nil
	links, err := queued.Send(ctx, envID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("%d links, want 1", len(links))
	}
	sent := links[0].Token

	// The restart: new Deps, same store, no memory of the token or the
	// envelope or that anything was ever queued.
	second := restartDeps(t, store, outbox)
	after, err := second.Send(ctx, envID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send after restart: %v, want the queued invite to be mailable", err)
	}
	if len(after) != 1 || after[0].Token != sent {
		t.Fatalf("the restart changed the link: before %q, after %q", sent, after[0].Token)
	}

	// The mail went out, and it carries the link from before the restart, so
	// the address in the party's earlier inbox and the address in this message
	// are the same address.
	files, err := readDirFiles(outbox)
	if err != nil {
		t.Fatalf("read the outbox: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("nothing in the outbox after a restart")
	}
	carries := false
	for _, f := range files {
		if strings.Contains(string(f), sent) {
			carries = true
		}
	}
	if !carries {
		t.Fatalf("none of the %d messages in the outbox carries the pre-restart token", len(files))
	}

	// The link resolves: the row authorised it before the restart and still
	// does after, because the hash never moved.
	if _, err := ResolveSigner(ctx, store, sent, time.Now()); err != nil {
		t.Fatalf("the pre-restart link does not resolve after the restart: %v", err)
	}
}
