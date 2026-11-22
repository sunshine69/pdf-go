// Package signmail renders and sends the messages of the signing service:
// the invitation with its signing link, the reminder, the cancellation, and
// the delivery of the signed document with its receipt.
//
// Two senders implement the same interface: SMTP with STARTTLS for
// production, and a file sender that writes .eml messages into
// var/outbox for development (DEV=1) and for the tests.
//
// Rule: a message never contains a secret that is not meant for its
// recipient, and a recipient's address is never derived from message
// content.
package signmail
