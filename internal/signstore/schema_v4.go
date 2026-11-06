package signstore

// Schema version 4: delivery, as step 10 defines it.
//
// A delivery is not a mail row. A mail row says "a message was sent"; a
// delivery says "this party's copy was accepted by the transport, here are the
// bytes it carried, and here is the proof that the bytes were verified at the
// moment they were handed over". The distinction is the whole point of Gate 2:
// a message that left the building with tampered bytes must be recorded as a
// refusal, not as an email with a bad attachment.
//
// deliveries is keyed by envelope and party, so a re-run updates the row that
// exists instead of accumulating a history of attempts — and delivery_status
// is not null, so the envelope's "delivered" state is answerable with one
// EXISTS/NOT EXISTS query rather than a scan.
//
// downloads is the large-document path: a random 32-byte token stored as its
// sha256, one document per row, an expiry, and no party list, so a link cannot
// be walked sideways into someone else's document.

const schemaV4 = `
CREATE TABLE IF NOT EXISTS deliveries(
  envelope_id     TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  party_id        TEXT NOT NULL REFERENCES parties(id) ON DELETE CASCADE,
  sha256          TEXT NOT NULL,
  bytes           INTEGER NOT NULL,
  verified_at     TEXT NOT NULL,
  verified        INTEGER NOT NULL,
  delivery_method TEXT NOT NULL,
  download_token  TEXT,
  download_until  TEXT,
  delivered_at    TEXT,
  delivery_status TEXT NOT NULL,
  last_error      TEXT,
  PRIMARY KEY (envelope_id, party_id)
);

CREATE TABLE IF NOT EXISTS downloads(
  token_hash  TEXT PRIMARY KEY,
  envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
  party_id    TEXT NOT NULL REFERENCES parties(id) ON DELETE CASCADE,
  sha256      TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS downloads_expiry ON downloads(expires_at);
`
