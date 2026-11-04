-- signsrv schema, version 1. Applied by internal/signstore in one
-- transaction; the version is recorded in settings('schema_version').
-- Timestamps are TEXT in UTC, RFC 3339 with seconds, so lexical order is
-- chronological. Status values are validated in Go (internal/signflow owns
-- the transitions), not by SQL CHECK.

CREATE TABLE admins(
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at TEXT NOT NULL,
  last_login TEXT
);

CREATE TABLE clients(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  key_hash TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE revoked_jtis(
  jti TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);

CREATE TABLE envelopes(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  template_sha TEXT NOT NULL,
  filled_sha TEXT,
  current_sha TEXT NOT NULL,
  serial TEXT,
  created_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  sent_at TEXT,
  delivered_at TEXT,
  cancelled_at TEXT,
  CHECK (length(id) = 32)
);

CREATE TABLE parties(
  id TEXT PRIMARY KEY,
  envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  order_idx INTEGER NOT NULL,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'invited',
  token_hash TEXT UNIQUE,
  token_expires_at TEXT NOT NULL,
  claim_at TEXT,
  consent_at TEXT,
  delivered_at TEXT,
  session_hash TEXT,
  reason TEXT NOT NULL DEFAULT '',
  UNIQUE (envelope_id, order_idx),
  UNIQUE (envelope_id, email)
);

CREATE TABLE revisions(
  id TEXT PRIMARY KEY,
  envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL UNIQUE,
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

CREATE TABLE consents(
  id TEXT PRIMARY KEY,
  party_id TEXT NOT NULL UNIQUE REFERENCES parties(id) ON DELETE CASCADE,
  envelope_id TEXT NOT NULL,
  signature_text TEXT NOT NULL,
  document_sha TEXT NOT NULL,
  image_sha TEXT,
  appearance_json TEXT,
  consent_at TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL
);

CREATE TABLE batch_queue(
  envelope_id TEXT PRIMARY KEY REFERENCES envelopes(id) ON DELETE CASCADE,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at TEXT NOT NULL,
  lease_until TEXT,
  enqueued_at TEXT NOT NULL
);

CREATE TABLE mail_queue(
  id INTEGER PRIMARY KEY,
  envelope_id TEXT NOT NULL,
  party_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha256 TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at TEXT NOT NULL,
  lease_until TEXT,
  sent_at TEXT,
  last_error TEXT
);

CREATE TABLE events(
  id INTEGER PRIMARY KEY,
  envelope_id TEXT,
  actor TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX parties_token_idx ON parties(token_hash);
CREATE INDEX parties_status_idx ON parties(envelope_id, status);
CREATE INDEX revisions_idx ON revisions(envelope_id, created_at);
CREATE INDEX events_idx ON events(envelope_id, created_at);
CREATE INDEX envelopes_idx ON envelopes(status, created_at);
CREATE INDEX mail_queue_idx ON mail_queue(next_at, sent_at);
