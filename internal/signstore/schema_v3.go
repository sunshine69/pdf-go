package signstore

// Schema version 3: revisions are per-envelope.
//
// Version 1 declared revisions.sha256 UNIQUE. That is wrong for a real
// deployment: two envelopes built from the same template hold the same
// template bytes, so the second create fails on the constraint. A hash is a
// content address, and the same content legitimately appears in many
// envelopes. The store keeps one copy of the bytes on disk (content
// addressing is the point), and the revisions table records one row per
// envelope.
//
// The rebuild keeps a uniqueness that is meaningful: within one envelope a
// given hash appears once. prev_id stays a plain text column, because the
// chain is built inside one transaction and a foreign key on it would make
// the insert order matter.
//
// The rebuild runs inside the migration transaction. Dropping a table that
// is referenced by nothing is safe with foreign_keys = 1; revisions is a
// child, not a parent.

const schemaV3 = `
CREATE TABLE revisions_v3(
  id TEXT PRIMARY KEY,
  envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  prev_id TEXT,
  kind TEXT NOT NULL,
  sig_field TEXT,
  party_id TEXT,
  cert_serial TEXT,
  cert_fingerprint TEXT,
  produced_by TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO revisions_v3 SELECT * FROM revisions;

DROP TABLE revisions;

ALTER TABLE revisions_v3 RENAME TO revisions;

CREATE UNIQUE INDEX revisions_sha ON revisions(envelope_id, sha256);
CREATE INDEX revisions_idx ON revisions(envelope_id, created_at);
`
