package signstore

// Schema v8 is the one migration in this store that has to do something to
// existing rows rather than only add to them, so it gets a test of its own, run
// against a database built by the migrations before it rather than by the
// current build.
//
// Three things could go wrong on a real database and none of them are visible
// from the Go code:
//
//   - CREATE UNIQUE INDEX on mail_queue(envelope_id, party_id, kind) fails
//     outright if the live database holds two unsent rows for one party, which
//     is exactly the state an operator who clicked a button twice leaves
//     behind. The migration deletes the older of each group first.
//   - An upgrade must not disturb the links a party already holds. The rows
//     written before v8 have a hash and no plaintext; the migration adds the
//     column as NULL and leaves it NULL, so the old hash keeps authorising the
//     old link.
//   - A partial index is only correct if it is partial. Two SENT rows for the
//     same party and kind are history, not a duplicate, and must still be
//     insertable. An index that accidentally covered them would refuse the
//     second email to a party who is being mailed again tomorrow.

import (
	"context"
	"database/sql"
	"testing"
)

// openAtV7 builds a database by applying every migration up to but not
// including v8, which is the state of a live install the moment before the
// upgrade. Rows go in as raw SQL after that, because a v7 database cannot hold
// a party with a plaintext token and the interesting rows are the old ones.
func openAtV7(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/signsrv.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.ExecContext(ctx,
		"create table if not exists settings(key text primary key, value text not null, updated_at text not null)"); err != nil {
		t.Fatalf("settings: %v", err)
	}
	for _, m := range migrations {
		if m.version >= CurrentVersion {
			break
		}
		if err := migrateOne(ctx, db, m); err != nil {
			t.Fatalf("migration %d: %v", m.version, err)
		}
	}
	if v, err := SchemaVersion(ctx, db); err != nil {
		t.Fatal(err)
	} else if v != CurrentVersion-1 {
		t.Fatalf("built a version %d database, want %d", v, CurrentVersion-1)
	}
	return db
}

func TestMigrateV8CollapsesQueueDuplicates(t *testing.T) {
	ctx := context.Background()
	db := openAtV7(t)
	// envelopes.id carries CHECK (length(id) = 32), so the fixture id has to be
	// a real one. It appears as a literal in the raw SQL below and as this
	// constant in the prepared insert; both must agree.
	const envID = "00112233445566778899001122334455"

	// One envelope, one party, as v7 would have written them: a hash and no
	// plaintext column at all.
	if _, err := db.ExecContext(ctx,
		`insert into settings(key, value, updated_at) values('noop', '1', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`insert into envelopes(id, title, status, template_sha, filled_sha, current_sha,
		                     created_by, created_at, updated_at, expires_at)
		 values('00112233445566778899001122334455', 'NDA', 'sent', 'aa', 'bb', 'cc',
		        1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-12-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`insert into parties(id, envelope_id, order_idx, email, name, status, token_hash, token_expires_at)
		 values('p1', '00112233445566778899001122334455', 1, 'ann@x.test', 'Ann', 'invited', 'deadbeef', '2026-12-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	// Three unsent invites for the same party — two double-clicks' worth — and
	// two sent ones, which are history and must survive.
	ins, err := db.PrepareContext(ctx,
		`insert into mail_queue(envelope_id, party_id, kind, next_at, sent_at) values(?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer ins.Close()
	rows := []struct {
		party, kind, sentAt string
	}{
		{"p1", "invite", ""},
		{"p1", "invite", ""},
		{"p1", "invite", ""},
		{"p1", "reminder", "2026-01-02T00:00:00Z"},
		{"p1", "reminder", "2026-01-03T00:00:00Z"},
		{"p1", "signed", "2026-01-04T00:00:00Z"},
	}
	for _, r := range rows {
		sent := any(nil)
		if r.sentAt != "" {
			sent = r.sentAt
		}
		if _, err := ins.ExecContext(ctx, envID, r.party, r.kind, "2026-01-01T00:00:00Z", sent); err != nil {
			t.Fatalf("queue %s: %v", r.kind, err)
		}
	}

	applied, err := Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if applied != 1 {
		t.Fatalf("%d migrations applied, want 1", applied)
	}
	if v, err := SchemaVersion(ctx, db); err != nil {
		t.Fatal(err)
	} else if v != CurrentVersion {
		t.Fatalf("version %d, want %d", v, CurrentVersion)
	}

	// The newest unsent row of the group is the one kept: it is the most recent
	// click, and its next_at and attempt count describe the state the operator
	// asked for.
	var kept int64
	if err := db.QueryRowContext(ctx,
		`select id from mail_queue where envelope_id = '00112233445566778899001122334455' and kind = 'invite' and sent_at is null`).Scan(&kept); err != nil {
		t.Fatalf("the surviving invite: %v", err)
	}
	if kept != 3 {
		t.Fatalf("kept invite row %d of 1,2,3, want the newest", kept)
	}

	// Sent rows are untouched, including the pair that shares a party and kind.
	// A group of two is only possible if the index does not cover sent rows.
	var reminders, signed int
	if err := db.QueryRowContext(ctx,
		`select count(*) from mail_queue where kind = 'reminder' and sent_at is not null`).Scan(&reminders); err != nil {
		t.Fatal(err)
	}
	if reminders != 2 {
		t.Fatalf("%d sent reminders survived, want 2", reminders)
	}
	if err := db.QueryRowContext(ctx,
		`select count(*) from mail_queue where kind = 'signed'`).Scan(&signed); err != nil {
		t.Fatal(err)
	}
	if signed != 1 {
		t.Fatalf("%d signed notices survived, want 1", signed)
	}

	// The index is enforced for unsent rows and silent for sent ones.
	if _, err := db.ExecContext(ctx,
		`insert into mail_queue(envelope_id, party_id, kind, next_at) values('00112233445566778899001122334455','p1','invite','2026-01-05T00:00:00Z')`); err == nil {
		t.Fatal("a second unsent invite for one party was accepted; the index is not enforcing")
	}
	if _, err := db.ExecContext(ctx,
		`insert into mail_queue(envelope_id, party_id, kind, next_at, sent_at)
		 values('00112233445566778899001122334455','p1','invite','2026-01-05T00:00:00Z','2026-01-05T00:00:00Z')`); err != nil {
		t.Fatalf("a second SENT invite was refused, so the index is not partial: %v", err)
	}
	// Another party, and the same party under a different kind, are unaffected.
	if _, err := db.ExecContext(ctx,
		`insert into parties(id, envelope_id, order_idx, email, name, status, token_hash, token_expires_at)
		 values('p2', '00112233445566778899001122334455', 2, 'bob@x.test', 'Bob', 'invited', 'beefdead', '2026-12-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`insert into mail_queue(envelope_id, party_id, kind, next_at) values('00112233445566778899001122334455','p2','invite','2026-01-05T00:00:00Z')`,
		`insert into mail_queue(envelope_id, party_id, kind, next_at) values('00112233445566778899001122334455','p1','reminder','2026-01-05T00:00:00Z')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("unrelated insert refused: %v", err)
		}
	}

	// The pre-existing party keeps its authority and gains no plaintext it
	// never had. A NULL here is honest: there is nothing to reprint, and
	// ensureToken mints a fresh link the next time that party is mailed.
	var raw sql.NullString
	probe, err := db.QueryContext(ctx, "select token_raw from parties where id = 'p1'")
	if err != nil {
		t.Fatalf("token_raw column missing after v8: %v", err)
	}
	probe.Close()
	if err := db.QueryRowContext(ctx, "select token_raw from parties where id = 'p1'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw.Valid {
		t.Fatalf("an upgraded party gained a plaintext token %q out of nowhere", raw.String)
	}
	var hash string
	if err := db.QueryRowContext(ctx, "select token_hash from parties where id = 'p1'").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != "deadbeef" {
		t.Fatalf("the stored hash changed on upgrade: %q", hash)
	}

	// Idempotent: running it again applies nothing, so a restart of the service
	// on an upgraded database cannot re-run the DELETE.
	if applied, err := Migrate(ctx, db); err != nil {
		t.Fatalf("second migrate: %v", err)
	} else if applied != 0 {
		t.Fatalf("second migrate applied %d, want 0", applied)
	}
}
