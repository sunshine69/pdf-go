// Package signauth issues and verifies the tokens of the signing service:
//
//   - API JWTs (Ed25519) for admins and machine clients, audience "api";
//   - opaque signer link tokens, stored only as SHA-256;
//   - the session cookie bound to a claimed party;
//   - HTTP middleware: rate limit -> authentication -> scope -> handler.
//
// Rule: a party never authenticates with an API token and an API token never
// authenticates a signing session. The two audiences are interchangeable
// nowhere in the system.
package signauth
