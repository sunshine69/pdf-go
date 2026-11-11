package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// openAndMigrate opens the database and brings it to this build's schema.
//
// The guard at the top is the reason this file exists separately. signstore.Open
// creates the file and mkdirs the parent — correct for a service booting for the
// first time, and exactly wrong here. An operator pointing this tool at the
// wrong path, or at a path with a typo, would otherwise get a silently empty
// database, "no admins", and a directory that did not exist a second ago. Then
// the real database still holds the accounts, and the confusion compounds.
//
// So: if the file is not there, stop. The exception is a directory, which means
// the operator named a folder that contains the database — worth naming, because
// it is a common mistake and the SQLite error for it is unhelpful.
func openAndMigrate(ctx context.Context, path string) (*signstore.Store, error) {
	if strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://") {
		return nil, fmt.Errorf("this build only reads SQLite databases; %q needs the postgres driver", path)
	}
	fi, err := os.Stat(path)
	switch {
	case err != nil && os.IsNotExist(err):
		return nil, fmt.Errorf("no database at %s (refusing to create one: this tool only reads and edits an existing database)", path)
	case err != nil:
		return nil, err
	case fi.IsDir():
		return nil, fmt.Errorf("%s is a directory, not a database file", path)
	}

	db, err := signstore.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	// Migrations run because an operator reading this database is asking a
	// question about a service that expects this build's schema, and because
	// the admin tables this tool writes to are created by them. Migrate is
	// idempotent; running it here is the same as the service running it at boot.
	applied, err := signstore.Migrate(ctx, db)
	if err != nil {
		db.Close()
		return nil, err
	}
	if applied > 0 {
		fmt.Fprintf(os.Stderr, "# %d migration(s) applied, schema version %d\n",
			applied, schemaVersion(ctx, db))
	}
	// storageDir is unused by every command here. NewStore needs the argument,
	// and passing "" is honest: this tool does not touch stored documents.
	return signstore.NewStore(db, ""), nil
}

func schemaVersion(ctx context.Context, db *sql.DB) int {
	v, err := signstore.SchemaVersion(ctx, db)
	if err != nil {
		return -1
	}
	return v
}
