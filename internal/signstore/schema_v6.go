package signstore

// Schema version 6: an address the drafter can be told at.
//
// Every mail this service sends has gone to a party — invite, reminder,
// cancellation. A drafter, the person who asked for the signature, had no
// address anywhere: envelopes.created_by records which admin or user row
// created the envelope, but no query has ever joined it out to an email, and a
// CLI-created envelope has no user row at all. So when a party declined, the
// reason was written to parties.reason and to an event, and nobody was
// notified. Declining reads exactly as "they have not opened the link yet".
//
// An explicit address on the envelope is the smallest thing that closes it.
// Not the creator's user.email (users has no such column), not a reply-to on
// the invite (mail_from is a mailbox that does not read it), not a webhook
// (that is step 14). One column, filled at create, used by the two mails that
// are addressed to the drafter rather than to a signer.
//
// NULL means "nobody asked to be told". Every existing envelope keeps NULL,
// so a decline on an old envelope behaves exactly as it does today — no mail,
// no error.
//
// The undeliverable notice needs one more thing. Its whole value is the
// specific SMTP rejection the invitation got ("550 5.1.1 no such mailbox"),
// and that text lives on the row that failed, not on the notice that describes
// it — so it is copied across. Telling the drafter "it failed, go look at the
// queue" is the same dead end wearing a different hat.
//
// SQLite cannot attach a CHECK to a column added by ALTER TABLE — that needs a
// table rebuild — so the shape rule lives where it can be enforced honestly:
// the create endpoint refuses an address with no @ before the row is ever
// written, because a typo there becomes a mail that retries for three days and
// is then given up on. The Go writer stores an empty address as NULL, so
// notify_email=” is the same stored fact as leaving it out.
//
// The queue needs one column too. Every mail row so far has been addressed by
// party_id: Build reads the party and sends to p.Email, which is right for the
// four messages that exist today, all of which go to a signer. A notice to the
// drafter has no party to address it to — the person who asked for the
// signature is not in the parties table — so the row carries its own
// recipient, and party_id stays what it always was, the party the message is
// *about*. NULL recipient means the old rule: address it to the party row.
const schemaV6 = `
ALTER TABLE envelopes ADD COLUMN notify_email TEXT;
ALTER TABLE mail_queue ADD COLUMN recipient TEXT;
ALTER TABLE mail_queue ADD COLUMN detail TEXT;
`
