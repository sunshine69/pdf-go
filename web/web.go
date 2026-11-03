// Package web holds the static single-page apps of the signing service and
// the content security policy of each face of the site. The files are
// embedded, so the binary is a single artifact.
package web

// CSPSigner is the policy of the signing app and its assets. frame-src is
// 'self' because the app embeds the document it asks the party to review.
const CSPSigner = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"frame-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"base-uri 'self'; form-action 'self'; frame-ancestors 'self'"

// CSPAdmin is the policy of the admin app. It never embeds a document in a
// frame, so frame-ancestors is 'none'.
const CSPAdmin = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"connect-src 'self'; img-src 'self' data:; base-uri 'self'; " +
	"form-action 'self'; frame-ancestors 'none'"
