package signstore

// Schema version 5: one account table, so a machine caller and a future web
// portal login share one row and one endpoint.
//
// The row carries three credentials, and each is a string for a different
// reason:
//
//   - password  is an argon2id encoded string ($argon2id$v=19$m=…, the same
//     encoding admins.pw_hash uses). It is read by the server only, and only
//     to verify a login. A plaintext password in a column would put every
//     operator's login into every database copy, every backup and every
//     sqlite3 session — which is exactly why clients stores a key hash and
//     never a key.
//
//   - jwt_secret is a 256-bit random value handed to the CLI. The CLI signs
//     its own access token with it (alg HS256, sub = username) and sends it
//     as Authorization: Bearer. That is the point of the row: no login
//     round trip, so the server can sit on one machine and the CLI on
//     another. The server reads the secret to verify, so it cannot be
//     hashed.
//
//   - scopes is what the row grants. A token claims scopes, and the guard
//     uses the row's scopes, so a caller cannot grant itself a scope by
//     editing the JSON it signs.
//
// One secret per user, not one secret for all. With one shared secret, the
// holder can write "sub": "admin:1" and "role": "admin" in its own token and
// is the whole system; and revoking one caller means rotating every caller.
// Per-user secrets keep the CLI's convenience and cost nothing.
//
// Backfill: every admin and every live client becomes a user. Nothing is
// dropped here; admins and clients keep working, and dropping them is its own
// later step so a bad migration can be rolled back without touching this one.
//
// A client row has no usable password. The '!' in its password column is not
// an argon2 string and cannot verify: argon2 encodings start with $argon2.

const schemaV5 = `
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password      TEXT NOT NULL,
  jwt_secret    TEXT NOT NULL UNIQUE,
  scopes        TEXT NOT NULL DEFAULT 'envelope:read,envelope:write',
  role          TEXT NOT NULL DEFAULT 'user',
  created_at    TEXT NOT NULL,
  last_login    TEXT,
  pw_changed_at TEXT,
  revoked_at    TEXT
);
`
