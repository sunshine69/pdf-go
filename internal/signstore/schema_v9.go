package signstore

import (
	"context"
	"database/sql"
)

// Schema version 9: an ownership marker so each client can see only its own
// envelopes from a web dashboard.
//
// schema_v9 adds created_by_subject (e.g. client:7, admin:3) to envelopes.
// ListEnvelopes and GetEnvelope both filter on it, so a client logged in via
// its key sees only envelopes its subject created, plus the server always
// lets admins see everything.

const schemaV9 = `
ALTER TABLE envelopes ADD COLUMN created_by_subject TEXT;
`

func init() {
	migrations = append(migrations, migration{
		version: 9,
		apply: func(ctx context.Context, tx *sql.Tx) error {
			// An ownership marker added in step 14: a client's dashboard
			// filters ListEnvelopes and GetEnvelope on this, so a caller
			// logged in with its key sees only the envelopes its subject
			// created. Pre-version-9 envelopes read back as NULL, which
			// means "no owner recorded" and matches every one of them.
			_, err := tx.ExecContext(ctx, schemaV9)
			return err
		},
	})
}
