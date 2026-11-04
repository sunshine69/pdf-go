package signstore

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestDriverProbe checks what the modernc driver supports, so the store is
// written against verified behaviour: named placeholders, pragmas in the DSN,
// pragma defaults, and RETURNING.
func TestDriverProbe(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "p.db")+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"journal_mode", "foreign_keys", "busy_timeout"} {
		var v string
		if err := db.QueryRowContext(ctx, "pragma "+p).Scan(&v); err != nil {
			t.Fatalf("pragma %s: %v", p, err)
		}
		t.Logf("pragma %s = %s", p, v)
	}

	var one int
	if err := db.QueryRowContext(ctx, "select :a", sql.Named("a", 1)).Scan(&one); err != nil {
		t.Errorf("named parameter :a: %v", err)
	} else {
		t.Logf("named :a = %d", one)
	}
	var two int
	if err := db.QueryRowContext(ctx, "select $a", sql.Named("a", 2)).Scan(&two); err != nil {
		t.Errorf("named parameter $a: %v", err)
	} else {
		t.Logf("named $a = %d", two)
	}
	var three int
	if err := db.QueryRowContext(ctx, "select ?1", 3).Scan(&three); err != nil {
		t.Errorf("numbered ?1: %v", err)
	} else {
		t.Logf("numbered ?1 = %d", three)
	}

	if _, err := db.ExecContext(ctx, "create table t(id text primary key, n integer)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "insert into t(id, n) values(?, ?)", "id1", 7); err != nil {
		t.Fatal(err)
	}
	var id string
	err = db.QueryRowContext(ctx, "update t set n = ? where id = ? returning id", 8, "id1").Scan(&id)
	if err != nil {
		t.Errorf("RETURNING: %v", err)
	} else {
		t.Logf("RETURNING id = %s", id)
	}

	// Cascade delete needs the foreign_keys pragma on the same connection.
	if _, err := db.ExecContext(ctx, "create table p(pid text references t(id) on delete cascade)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "insert into p(pid) values('id1')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "delete from t where id = 'id1'"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "select count(*) from p").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("cascade delete left %d rows", n)
	}
}
