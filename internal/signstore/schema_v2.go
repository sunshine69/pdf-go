package signstore

// Schema version 2: refresh tokens.
//
// A refresh token is a 256-bit random value; only its SHA-256 is stored, for
// the same reason a signer link token is stored as a hash: a copied database
// must not be enough to authenticate.
//
// subject is the owner, in the same encoding a JWT "sub" uses
// ("admin:7", "client:3"), so a chain can be deleted on logout or on a
// password change.
//
// The same migration adds admins.pw_changed_at: the moment a password was
// last changed. An access token minted before that moment is refused, so
// `signsrv admin passwd` ends the sessions the password protected. It is
// NULL for a row created by version 1, which reads as epoch 0.
//
// consumed is what makes a refresh token single-use. Using one marks it
// consumed and inserts its replacement in the same statement. A replayed
// refresh token is then refused.
//
// expires_at is the refresh token's own deadline (TTL 12 days), so the sweep
// deletes a chain that has gone stale and the table stays small.
const schemaV2 = `
CREATE TABLE IF NOT EXISTS refresh_tokens(
  hash TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS refresh_subject ON refresh_tokens(subject);
CREATE INDEX IF NOT EXISTS refresh_expires ON refresh_tokens(expires_at);

ALTER TABLE admins ADD COLUMN pw_changed_at TEXT;
`
