package signstore

// Schema version 7: where the signatures go.
//
// An envelope create takes a widget — a signature field name, a page, an X/Y —
// and always has. What it never had was somewhere to keep it. Create wrote the
// widget into the `created` audit event, which records what happened but is not
// a column anything can select, and the batch runner signed with
// signpdf.PartyWidget(i): page 1, bottom-left column, every envelope, whatever
// the caller asked for. A drafter who specified page 4 got page 1 and no error,
// which is the worst kind of wrong answer.
//
// Four columns rather than one JSON blob, for the same reason the rest of this
// schema is flat: the batch reads them on every signature, and a page number
// that has to be unmarshalled is a page number that can be silently malformed.
// A zero page and zero coordinates mean "the service decides", which is exactly
// what they meant before the column existed — so every envelope already in the
// database, which stores NULL here, keeps the behaviour it has always had.
//
// The field name and the coordinates are kept as separate facts on purpose.
// A field name says "put it where the template's signature box is"; an X/Y says
// "put it here". They mean different things and a caller may set either. The
// service resolves the field against the document at signing time and lets an
// explicit coordinate win, because a name that drifts out of sync with a
// re-uploaded template should move the signature to the right page at worst,
// not fail a live signing session.
const schemaV7 = `
ALTER TABLE envelopes ADD COLUMN widget_field TEXT;
ALTER TABLE envelopes ADD COLUMN widget_page INTEGER;
ALTER TABLE envelopes ADD COLUMN widget_x REAL;
ALTER TABLE envelopes ADD COLUMN widget_y REAL;
`
