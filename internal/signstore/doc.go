// Package signstore is the persistence layer of the signing service:
// embedded schema, migrations, typed queries, the content-addressed PDF
// store, and the periodic sweeps.
//
// It talks to the database through database/sql with the pure-Go SQLite
// driver, so the service keeps the no-cgo property of the pdf-go project.
//
// Rules:
//   - No SQL is ever built by concatenation. Every value is a bound
//     parameter; identifiers come from a fixed list.
//   - Secrets (passwords, machine keys, link tokens) are stored hashed.
//   - Files in var/storage are content-addressed, immutable, and never
//     overwritten.
//   - The events table is append-only: this package never updates or
//     deletes an event row.
package signstore
