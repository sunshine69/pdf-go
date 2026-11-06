package signstore

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strconv"
)

// schemaSQL is the version 1 schema. Later steps add a migration entry
// rather than editing this file: a released migration is never changed.
//
//go:embed schema.sql
var schemaSQL string

// CurrentVersion is the schema version this build expects.
const CurrentVersion = 4

type migration struct {
	version int
	apply   func(ctx context.Context, tx *sql.Tx) error
}

// migrations is ordered. Every entry runs inside one transaction together
// with its version row, so a half-applied migration cannot be observed.
var migrations = []migration{
	{version: 1, apply: func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, schemaSQL)
		return err
	}},
	{version: 2, apply: func(ctx context.Context, tx *sql.Tx) error {
		// Refresh token storage, added in step 03. CREATE TABLE IF NOT EXISTS
		// keeps this safe on a database that was built by an earlier release
		// that already created the table by hand.
		_, err := tx.ExecContext(ctx, schemaV2)
		return err
	}},
	{version: 3, apply: func(ctx context.Context, tx *sql.Tx) error {
		// Revisions become per-envelope. Step 05 creates several envelopes
		// from one template, and version 1's UNIQUE on revisions.sha256
		// refuses the second one.
		_, err := tx.ExecContext(ctx, schemaV3)
		return err
	}},
	{version: 4, apply: func(ctx context.Context, tx *sql.Tx) error {
		// Deliveries and large-document download links, added in step 10.
		_, err := tx.ExecContext(ctx, schemaV4)
		return err
	}},
}

// Migrate applies every migration newer than the stored version and returns
// how many it applied, so running it twice reports 0. The version reached is
// available from SchemaVersion.
func Migrate(ctx context.Context, db *sql.DB) (int, error) {
	if _, err := db.ExecContext(ctx,
		"create table if not exists settings(key text primary key, value text not null, updated_at text not null)"); err != nil {
		return 0, err
	}

	version, err := SchemaVersion(ctx, db)
	if err != nil {
		return 0, err
	}
	if version > CurrentVersion {
		return 0, fmt.Errorf("signstore: database schema version %d is newer than this build (%d); refusing to run",
			version, CurrentVersion)
	}

	applied := 0
	for _, m := range migrations {
		if m.version <= version {
			continue
		}
		if err := migrateOne(ctx, db, m); err != nil {
			return applied, fmt.Errorf("signstore: migration %d: %w", m.version, err)
		}
		version = m.version
		applied++
	}
	return applied, nil
}

func migrateOne(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := m.apply(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"insert into settings(key, value, updated_at) values('schema_version', ?, ?)"+
			" on conflict(key) do update set value = excluded.value, updated_at = excluded.updated_at",
		strconv.Itoa(m.version), timeNow()); err != nil {
		return err
	}
	return tx.Commit()
}

// SchemaVersion reads the schema version recorded in the database.
func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v string
	err := db.QueryRowContext(ctx, "select value from settings where key = 'schema_version'").Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(v)
}
