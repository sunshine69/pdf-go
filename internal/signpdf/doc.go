// Package signpdf is the adapter over github.com/digitorus/pdfsign. It is
// the only place in the service that signs a document.
//
// It exposes three operations, all pure: bytes in, bytes out.
//
//	Certify   fill is done by signfill; this freezes the document with a
//	          certification signature (Permission(NoChanges)) so the bytes the
//	          parties review are the bytes that get signed.
//	SignParty one approval signature over the bytes given, using a key
//	          generated in memory for the call and discarded afterwards.
//	Verify    report every signature of a document and whether it is valid.
//
// Nothing in this package touches files, the database, HTTP, users, state,
// consent capture, batch orchestration, emails, timers, scheduling, logging,
// auth, or deployment. Those belong to signflow, signstore, signmail,
// signauth and cmd/signsrv. A function here takes a context, a byte slice
// and explicit options, and returns bytes: it knows nothing about envelopes.
//
// Private keys are never written to disk, never logged and never returned.
package signpdf

import (
	_ "github.com/digitorus/pdfsign"
)
