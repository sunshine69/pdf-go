package signstore

// Schema version 8: the link token outlives the process that minted it.
//
// A party's link token existed in two places: its SHA-256 in the database,
// which is what authorises a signing request, and the plaintext in a process-
// wide map. Only the hash survives a restart, and an email needs the plaintext
// to print a URL. So a message still in the queue when the server stopped could
// not be rendered when it started again -- "the link token is not available" --
// and the only repair was to mint a token the party never asked for, invalidating
// the link they were already holding. The comment in send.go called this a
// design choice; in practice it made every restart an email-recovery event and
// made the operator's buttons order-dependent.
//
// The hash stays the authority: a token is still looked up by hashing what the
// link carried, so storing this column changes no authorisation decision. It is
// the "how do I reprint the URL" fact, and it is the same length as the hash
// column beside it. A database dump can now hand out live links, which is the
// accepted cost: at rest this store protects nothing that the file system, the
// backup policy, and a 72-hour expiry do not already protect, and a hash that
// cannot be reversed protects the token from a reader while leaving it unable to
// be used again -- the worse of both.
//
// The partial unique index is the other half. Every queue producer already
// means "at most one message per party per kind", and each filters by status
// before inserting, but the insert was unconditional: two clicks on the same
// button wrote two rows and mailed the party twice. A partial index on the
// unsent rows states that intent in the schema, so the insert can be an upsert
// and the operator's button becomes safe to press twice. Sent rows are outside
// the index on purpose -- they are history, and a party is allowed to be mailed
// again tomorrow.
//
// The DELETE runs first. A database that has already had a button clicked twice
// holds duplicate unsent rows, and CREATE UNIQUE INDEX would fail outright on
// them; keeping the newest of each group is the choice that both succeeds and
// preserves the most recent click.
const schemaV8 = `
ALTER TABLE parties ADD COLUMN token_raw TEXT;

DELETE FROM mail_queue
 WHERE sent_at IS NULL
   AND id NOT IN (
     SELECT MAX(id) FROM mail_queue WHERE sent_at IS NULL
      GROUP BY envelope_id, party_id, kind
   );

CREATE UNIQUE INDEX mail_queue_unsent
    ON mail_queue(envelope_id, party_id, kind)
 WHERE sent_at IS NULL;
`
