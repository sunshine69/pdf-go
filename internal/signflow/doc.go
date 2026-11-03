// Package signflow is the state machine of the signing service.
//
// A document is an envelope: it is created from a template and a fill
// specification, filled and certified, sent to the parties as expiring
// single-use links, collects the parties' consents in any order, signs the
// frozen document in one batch once every party has consented, verifies the
// result and delivers it.
//
// Envelope states:
//
//	draft -> ready -> sent -> collecting -> signed -> completed -> delivered
//	                  \-> expired  \-> cancelled  \-> failed
//
// This package owns every transition. Nothing else changes an envelope
// status: transitions go through Transition, which refuses anything outside
// the table and appends an event to the audit log.
//
// Consent is data only. The only code that signs lives in the batch runner
// of this package, which calls signpdf.
package signflow
