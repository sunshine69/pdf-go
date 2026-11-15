package signflow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The drafter's notices, end to end through the real store and the real
// renderer: a decline tells whoever asked for the signature, and an invitation
// that gave up tells them too. The two rules that matter most are that the
// notice goes to the drafter and not to the party, and that a notice that fails
// to send does not spawn another notice.

// notifyFixture is a sent envelope that carries a drafter address, plus the
// token and party ID of its first party.
type notifyFixture struct {
	deps      *Deps
	outbox    string
	envID     string
	token     string
	partyID   string
	partyMail string
}

// relayFails sends through a dead transport, so the fixture's invites are in
// the state a real outage leaves them in: created, attempted once, waiting for
// their backoff — which is where the give-up and its notice happen.
func newNotifyFixture(t *testing.T, notifyEmail string, relayFails bool) *notifyFixture {
	t.Helper()
	outbox := t.TempDir()
	d := mailDeps(t, outbox)
	if relayFails {
		d.Mail.Sender = &failingSender{}
	}
	ctx := context.Background()

	in := sampleBytes(t)
	created, err := d.Create(ctx, CreateRequest{
		Template:    in,
		Fill:        fillSpecFor(t, in),
		Parties:     parties(2),
		Title:       "Lease 2026",
		ExpiresIn:   48 * time.Hour,
		Actor:       "api:test",
		LinkBase:    "http://127.0.0.1:8090",
		NotifyEmail: notifyEmail,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	links, err := d.Send(ctx, created.Envelope.ID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return &notifyFixture{
		deps:      d,
		outbox:    outbox,
		envID:     created.Envelope.ID,
		token:     links[0].Token,
		partyID:   links[0].PartyID,
		partyMail: parties(2)[0].Email,
	}
}

// mailRows returns the queue rows of one envelope keyed by kind.
func mailRows(t *testing.T, d *Deps, envID string) map[string][]signstore.MailItem {
	t.Helper()
	rows, err := d.Store.ListMail(context.Background(), envID)
	if err != nil {
		t.Fatalf("list mail: %v", err)
	}
	out := map[string][]signstore.MailItem{}
	for _, r := range rows {
		out[r.Kind] = append(out[r.Kind], r)
	}
	return out
}

// The drafter's address is stored on the envelope and reads back normalised, so
// a create that wrote "Ann <ann@corp.test>" tells the address, not the phrase.
func TestEnvelopeStoresNotifyEmail(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "Ann <ann@corp.test>", false)

	env, err := f.deps.Store.GetEnvelope(ctx, f.envID)
	if err != nil {
		t.Fatal(err)
	}
	if env.NotifyEmail != "ann@corp.test" {
		t.Fatalf("notify_email = %q, want the bare address", env.NotifyEmail)
	}
}

// An address that is not an address is refused at create, before anything is
// written: a typo here becomes a notice that retries for three days and is then
// given up on, which is the failure mode the whole feature is meant to avoid.
func TestCreateRefusesABadNotifyEmail(t *testing.T) {
	d := newDeps(t)
	in := sampleBytes(t)
	for _, bad := range []string{"ann-at-corp.test", "ann@", "@corp.test"} {
		_, err := d.Create(context.Background(), CreateRequest{
			Template:    in,
			Fill:        fillSpecFor(t, in),
			Parties:     parties(1),
			Title:       "NDA",
			ExpiresIn:   48 * time.Hour,
			NotifyEmail: bad,
		})
		if err == nil {
			t.Fatalf("create accepted notify_email %q", bad)
		}
		if !strings.Contains(err.Error(), "notify_email") {
			t.Fatalf("error does not name the field: %v", err)
		}
	}
}

// A decline queues one notice to the drafter, addressed to the drafter and
// about the party who declined.
func TestDeclineNotifiesTheDrafter(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "ann@corp.test", false)

	res, err := f.deps.Decline(ctx, f.token, "the term sheet is not the one we discussed",
		DeclineMeta{IP: "10.0.0.1", UserAgent: "signflow-unit-test"}, time.Now().UTC())
	if err != nil {
		t.Fatalf("decline: %v", err)
	}
	if !res.OK {
		t.Fatalf("decline answer: %+v", res)
	}

	rows := mailRows(t, f.deps, f.envID)
	if len(rows[KindDeclined]) != 1 {
		t.Fatalf("%d declined rows, want 1: %+v", len(rows[KindDeclined]), rows[KindDeclined])
	}
	r := rows[KindDeclined][0]
	if r.Recipient != "ann@corp.test" {
		t.Fatalf("notice addressed to %q, want the drafter", r.Recipient)
	}
	if r.PartyID != f.partyID {
		t.Fatalf("notice party_id = %q, want the declining party %q", r.PartyID, f.partyID)
	}
	if r.Detail == "" {
		t.Fatal("the notice carries no reason to quote")
	}

	// And the address the party is *not* told: the notice must not go back to
	// the mailbox of the person who just declined.
	outbox := readOutbox(t, f.outbox)
	if len(outbox) == 0 {
		t.Fatal("the notice was never sent")
	}
	// Drain the notice through the configured sender.
	if _, err := f.deps.Drain(ctx, f.envID, time.Now()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	sent := false
	for _, raw := range readOutbox(t, f.outbox) {
		s := string(raw)
		if strings.Contains(s, "To: ann@corp.test") &&
			strings.Contains(s, "the term sheet is not the one we discussed") {
			sent = true
		}
	}
	if !sent {
		t.Fatalf("no outbox message to the drafter carrying the reason; %d files", len(outbox))
	}
}

// An envelope with no drafter address declines exactly as it did before the
// feature existed: the party gets their answer, and nothing is queued.
func TestDeclineWithoutADrafterAddressIsUnchanged(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "", false)

	if _, err := f.deps.Decline(ctx, f.token, "no thanks",
		DeclineMeta{}, time.Now().UTC()); err != nil {
		t.Fatalf("decline on an envelope with no notify_email: %v", err)
	}
	rows := mailRows(t, f.deps, f.envID)
	if n := len(rows[KindDeclined]); n != 0 {
		t.Fatalf("%d declined rows for an envelope that asked for none", n)
	}
	env, err := f.deps.Store.GetEnvelope(ctx, f.envID)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != Failed {
		t.Fatalf("status = %s, want failed", env.Status)
	}
}

// giveUpInvites drives an invite row past its attempt limit through a dead
// relay, the same way the acceptance test does.
// deadRelay kills the transport and spends the retry budget on the rows that
// are waiting, the way a real outage does: the send fails on its first drain,
// and every later round clears only the backoff, never a row's own state. A
// reset that rewound attempts would rewind the notices too, and the loop the
// test below is looking for would be the test's own doing.
func deadRelay(t *testing.T, f *notifyFixture) {
	t.Helper()
	ctx := context.Background()
	f.deps.Mail.Sender = &failingSender{}

	for i := 2; i <= signmail.MaxAttempts; i++ {
		if _, err := f.deps.Store.DB().ExecContext(ctx,
			`update mail_queue set next_at = '0001-01-01T00:00:00Z', lease_until = null
			 where envelope_id = ? and sent_at is null`, f.envID); err != nil {
			t.Fatalf("clear backoff: %v", err)
		}
		if _, err := f.deps.Drain(ctx, f.envID, time.Now()); err != nil {
			t.Fatalf("drain round %d: %v", i, err)
		}
	}
}

// makeDue clears the backoff of every row still waiting, leaving the rows the
// queue has parked at its give-up deadline alone. A test needs the waiting rows
// now, not in three days; a parked row is parked for a reason.
func makeDue(t *testing.T, f *notifyFixture) {
	t.Helper()
	if _, err := f.deps.Store.DB().ExecContext(context.Background(),
		`update mail_queue set next_at = '0001-01-01T00:00:00Z', lease_until = null
		 where envelope_id = ? and sent_at is null and next_at < '9999-12-31T00:00:00Z'`,
		f.envID); err != nil {
		t.Fatalf("clear backoff: %v", err)
	}
}

// An invitation that gave up tells the drafter, and tells them the transport's
// answer rather than "it failed".
func TestUndeliverableInviteNotifiesTheDrafter(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "ann@corp.test", true)
	deadRelay(t, f)

	rows := mailRows(t, f.deps, f.envID)
	if len(rows[KindInvite]) != 2 {
		t.Fatalf("%d invite rows, want 2", len(rows[KindInvite]))
	}
	if len(rows[KindUndeliverable]) != 2 {
		t.Fatalf("%d undeliverable rows, want one per given-up invite: %+v",
			len(rows[KindUndeliverable]), rows)
	}
	for _, r := range rows[KindUndeliverable] {
		if r.Recipient != "ann@corp.test" {
			t.Fatalf("notice addressed to %q, want the drafter", r.Recipient)
		}
		if !strings.Contains(r.Detail, "relay deferred") {
			t.Fatalf("notice carries no transport reason: %q", r.Detail)
		}
	}

	// The notice reaches the drafter's mailbox and not the party's: the party's
	// row never existed for them to read, and telling them their own invitation
	// failed adds nothing they can act on. The notices may already have spent an
	// attempt against the dead relay inside the same drain that created them, so
	// their backoff is cleared before the transport is fixed.
	makeDue(t, f)
	f.deps.Mail.Sender = &signmail.FileSender{Dir: f.outbox}
	if _, err := f.deps.Drain(ctx, f.envID, time.Now()); err != nil {
		t.Fatalf("drain notices: %v", err)
	}
	var bodies []string
	for _, raw := range readOutbox(t, f.outbox) {
		s := string(raw)
		if strings.Contains(s, "To: ann@corp.test") {
			bodies = append(bodies, s)
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("%d notices to the drafter, want 2", len(bodies))
	}
	for _, b := range bodies {
		if !strings.Contains(b, "relay deferred") {
			t.Fatalf("notice does not quote the rejection:\n%s", b)
		}
		if strings.Contains(b, "Content-Type: text/html") {
			t.Fatalf("notice carries an HTML part")
		}
	}
}

// A notice that fails to send gets no notice of its own. Two rows describing
// each other's failure is a loop, and a loop against a dead relay is a queue
// that never empties.
func TestUndeliverableNoticeDoesNotSpawnANotice(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "ann@corp.test", true)
	deadRelay(t, f)

	before := len(mailRows(t, f.deps, f.envID)[KindUndeliverable])
	if before == 0 {
		t.Fatal("no notices to fail; the previous drain raised none")
	}

	// The relay is already dead. Drive the notices to their own give-up by
	// clearing their backoff — and only theirs: a row the queue has parked at
	// its give-up deadline is parked for a reason, and rewinding it would make
	// the invites give up a second time and raise a second notice each, which
	// is the test manufacturing the loop it means to disprove.
	for i := 0; i < signmail.MaxAttempts+1; i++ {
		if _, err := f.deps.Store.DB().ExecContext(ctx,
			`update mail_queue set next_at = '0001-01-01T00:00:00Z', lease_until = null
			 where envelope_id = ? and sent_at is null and next_at < '9999-12-31T00:00:00Z'`,
			f.envID); err != nil {
			t.Fatalf("clear backoff: %v", err)
		}
		if _, err := f.deps.Drain(ctx, f.envID, time.Now()); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}
	after := len(mailRows(t, f.deps, f.envID)[KindUndeliverable])
	if after != before {
		t.Fatalf("undeliverable notices grew from %d to %d; a notice queued a notice", before, after)
	}
}

// Only an invite earns the notice. A reminder is not the reason a party has not
// signed, and a cancellation notice nobody received changes nothing.
func TestOnlyAnInviteGivesUpToANotice(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "ann@corp.test", true)

	// Leave one row and make it a reminder on its last attempt. The row is due
	// now, so the next drain takes it to the give-up branch. Deleting the
	// second party's row keeps the test about the reminder: an invite still
	// waiting would give up in the same drain and raise a notice that is
	// correct but not what is under test.
	if _, err := f.deps.Store.DB().ExecContext(ctx,
		`delete from mail_queue where envelope_id = ? and party_id <> ?`,
		f.envID, f.partyID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.deps.Store.DB().ExecContext(ctx,
		`update mail_queue set kind = ?, attempts = ?, next_at = '0001-01-01T00:00:00Z',
		 lease_until = null where envelope_id = ? and party_id = ?`,
		KindReminder, signmail.MaxAttempts-1, f.envID, f.partyID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.deps.Drain(ctx, f.envID, time.Now()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	rows := mailRows(t, f.deps, f.envID)
	if len(rows[KindReminder]) != 1 || rows[KindReminder][0].SentAt != "" {
		t.Fatalf("reminder row did not behave: %+v", rows[KindReminder])
	}
	if n := len(rows[KindUndeliverable]); n != 0 {
		t.Fatalf("%d notices for a reminder that gave up, want none", n)
	}
	// The give-up itself is still recorded: refusing the notice is not the same
	// as pretending the message never died.
	events, err := f.deps.Store.ListEvents(ctx, f.envID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Kind == "mail_failed" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d mail_failed events, want 1", n)
	}
}

// The notice is built from the row, so it renders after a restart: the drafter's
// address is on the row, and the party's token is not needed.
func TestNoticeRendersWithoutTheRawToken(t *testing.T) {
	ctx := context.Background()
	f := newNotifyFixture(t, "ann@corp.test", false)

	if _, err := NotifyDrafter(ctx, f.deps.Store, f.envID, f.partyID, KindDeclined, "no reason needed"); err != nil {
		t.Fatal(err)
	}

	item, err := f.deps.Store.ClaimMailFor(ctx, f.envID, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if item.Kind != KindDeclined {
		t.Fatalf("claimed %q, want the declined notice", item.Kind)
	}
	msg, err := Build(ctx, f.deps.Mail.Renderer, f.deps.Store, item,
		"signsrv@example.test", "http://127.0.0.1:8090", 2, time.Now())
	if err != nil {
		t.Fatalf("build the notice with no token in hand: %v", err)
	}
	if msg.To != "ann@corp.test" {
		t.Fatalf("notice addressed to %q, want the drafter", msg.To)
	}
	// A drafter's notice must not carry a link it cannot justify.
	if strings.Contains(msg.Text, "http") {
		t.Fatalf("notice carries a URL:\n%s", msg.Text)
	}
}
