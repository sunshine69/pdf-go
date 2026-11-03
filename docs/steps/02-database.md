# 02 — Database

Depends: 01.

## Deliverables

- `internal/signstore/schema.sql` (embedded), `store.go`, `migrations.go`,
  `models.go`, `sweeps.go`
- `signsrv migrate` and `signsrv admin add <email>` subcommands
- `internal/signstore/store_test.go` running against a temp SQLite file

## Design

Driver: `modernc.org/sqlite` through `database/sql`, DSN
`file:DB_PATH?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)`.
Single writer assumption: `db.SetMaxOpenConns(1)` for writes is acceptable in v1.

All access through `Store` methods that take `context.Context` and return typed
structs. **No SQL string concatenation anywhere** — named placeholders only.
Text search uses a `LIKE` on whitelisted columns.

Schema (v1, single migration file, applied inside a transaction, `schema_version` row):

```sql
CREATE TABLE admins(id INTEGER PK, email TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'admin', created_at TEXT NOT NULL);
CREATE TABLE clients(id INTEGER PK, name TEXT UNIQUE NOT NULL, key_hash TEXT NOT NULL,
                     scopes TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE revoked_jtis(jti TEXT PK, expires_at TEXT NOT NULL);
CREATE TABLE envelopes(
  id TEXT PK, title TEXT NOT NULL, status TEXT NOT NULL,
  template_sha TEXT NOT NULL, filled_sha TEXT, current_sha TEXT NOT NULL,
  serial TEXT, template_path TEXT,
  created_by INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, sent_at TEXT, delivered_at TEXT, cancelled_at TEXT,
  CHECK (length(id)=32));
CREATE TABLE parties(
  id TEXT PK, envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  order_idx INTEGER NOT NULL, email TEXT NOT NULL, name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'invited', token_hash TEXT UNIQUE,
  token_expires_at TEXT NOT NULL, claim_at TEXT, consent_at TEXT, delivered_at TEXT,
  session_hash TEXT, reason TEXT NOT NULL DEFAULT '',
  UNIQUE (envelope_id, order_idx), UNIQUE (envelope_id, email));
CREATE TABLE revisions(
  id TEXT PK, envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL UNIQUE, prev_id TEXT, kind TEXT NOT NULL,
  sig_field TEXT, party_id TEXT, cert_serial TEXT, cert_fingerprint TEXT,
  produced_by TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE consents(
  id TEXT PK, party_id TEXT NOT NULL UNIQUE REFERENCES parties(id) ON DELETE CASCADE,
  envelope_id TEXT NOT NULL, signature_text TEXT NOT NULL,
  document_sha TEXT NOT NULL, image_sha TEXT, appearance_json TEXT,
  consent_at TEXT NOT NULL, ip TEXT NOT NULL, user_agent TEXT NOT NULL);
CREATE TABLE batch_queue(
  envelope_id TEXT PK REFERENCES envelopes(id) ON DELETE CASCADE,
  attempts INTEGER NOT NULL DEFAULT 0, next_at TEXT NOT NULL,
  lease_until TEXT, enqueued_at TEXT NOT NULL);
CREATE TABLE mail_queue(
  id INTEGER PK, envelope_id TEXT NOT NULL, party_id TEXT NOT NULL,
  kind TEXT NOT NULL, sha256 TEXT, attempts INTEGER NOT NULL DEFAULT 0,
  next_at TEXT NOT NULL, sent_at TEXT, last_error TEXT);
CREATE TABLE events(id INTEGER PK, envelope_id TEXT, actor TEXT NOT NULL,
                    kind TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE settings(key TEXT PK, value TEXT NOT NULL, updated_at TEXT NOT NULL);
```

Indexes: `parties(token_hash)`, `parties(envelope_id,status)`,
`revisions(envelope_id,created_at)`, `events(envelope_id,created_at)`,
`envelopes(status,created_at)`.

Key rules:

- `token_hash`, `key_hash`, `pw_hash`: argon2id (passwords) / SHA-256 (opaque
  tokens, machine keys). Raw token, raw key, raw password exist only in memory
  for the response that prints them once.
- Status columns are validated in Go, not by SQL CHECK, so the state machine
  lives in one place (`internal/signflow`). Party status is
  `invited|claimed|consented|declined|expired`; envelope status is
  `draft|ready|sent|collecting|signed|completed|delivered|expired|cancelled|failed`.
- `consents.party_id` is UNIQUE: one consent per party, enforced by the schema,
  not only by the handler.
- Sweeps (`sweeps.go`, run by the worker every 5 min): expire envelopes and
  parties past `expires_at`; delete `revoked_jtis` past expiry; requeue
  `batch_queue`/`mail_queue` rows whose `lease_until` is past. Every sweep
  writes an `events` row.
- Storage: `Store.PutPDF(data []byte) (sha256 string, err)` writes
  `var/storage/<sha>.pdf`, refuses > 50 MB, refuses non-`%PDF-` prefix.
  `Store.PutBlob(data []byte, ext string)` writes `var/storage/<sha>.<ext>` for
  consent images, refuses > 1 MB. Files are content-addressed, immutable,
  never overwritten.

## Acceptance

```
go test ./internal/signstore            # migrations, CRUD, sweeps, unique constraints
signsrv migrate                          # idempotent: running twice is a no-op
signsrv admin add admin@example.org      # prompts twice for password, argon2 hash in db
sqlite3 var/signsrv.db 'select name from sqlite_master where type="table"'
```

Test list that must exist and pass: migration idempotency, cascade delete of
parties with envelope, duplicate party email rejected, token hash lookup,
`PutPDF` rejects non-PDF, sweep expires an old envelope.

## Signoff

- [ ] No string-built SQL; all parameters bound
- [ ] Passwords argon2id, tokens hashed; no plaintext secret in any column
- [ ] Migration is idempotent and versioned
- [ ] Sweeps tested; state transitions are in signflow, not in SQL
- Reviewer: ____________  Date: ________
