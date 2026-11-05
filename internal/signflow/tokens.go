package signflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// Signer link tokens.
//
// A token is 32 random bytes. Its only stored form is the SHA-256 hex of
// itself, in parties.token_hash; the raw value exists in the create/send
// response and in the email, nowhere else. Lookup is by hash through a UNIQUE
// index, so a database copy is never enough to sign a document.
//
// The encoding is lowercase base32 without padding: 32 bytes is 256 bits,
// 256/5 is 51.2, so 52 characters. base32 uses [A-Z2-7]; lowercased that is
// [a-z2-7], URL-safe and needing no escaping in a path segment. It is not
// base64url: base64url of 32 bytes is 43 characters, and the specification
// asks for 52, so base32 is the encoding that fits the length.

// LinkTokenBytes is the entropy of a signing link.
const LinkTokenBytes = 32

// MaxLinkTTL is the 30-day ceiling of a signing link.
const MaxLinkTTL = 30 * 24 * time.Hour

// ErrTokenExpired is the answer of a lookup when the link's deadline has
// passed. The API maps it to 410.
var ErrTokenExpired = errors.New("signflow: link token expired")

// ErrTokenUnknown is the answer when the token is not in the store. A token
// that never existed and a token of another envelope get the same answer, so
// the caller cannot probe which envelopes exist.
var ErrTokenUnknown = errors.New("signflow: link token not found")

// NewLinkToken returns 52 lowercase base32 characters from 32 random bytes.
func NewLinkToken() (string, error) {
	b := make([]byte, LinkTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")), nil
}

// HashLink returns the lowercase hex SHA-256 of a token: the stored form.
// It is the same function signauth uses for its opaque tokens, so one hash
// rule covers every secret the service stores.
func HashLink(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// LinkTTL clamps a requested lifetime to the 30-day ceiling. A request for
// more is answered with the ceiling, not with an error: a create that asks for
// a year is a client that misread the product, and the safe answer is the
// longest link the service issues.
func LinkTTL(requested time.Duration) time.Duration {
	if requested <= 0 || requested > MaxLinkTTL {
		return MaxLinkTTL
	}
	return requested
}

// TokenExpiry is min(now+expiresIn, envelope.expiresAt). A party's link never
// outlives the envelope: a link that could sign after the envelope expired
// would write into a state the service has already closed.
func TokenExpiry(now time.Time, expiresIn time.Duration, envelopeExpires time.Time) time.Time {
	cand := now.Add(LinkTTL(expiresIn))
	if envelopeExpires.Before(cand) {
		return envelopeExpires
	}
	return cand
}

// LinkFor builds the signing URL of a token. Only scheme, host, and path
// appear: the token is a path segment, never a query parameter, so it cannot
// leak through a Referer header.
func LinkFor(base, token string) string {
	if base == "" {
		return "/s/" + token
	}
	return strings.TrimSuffix(base, "/") + "/s/" + token
}

// LookupLink resolves a token to its party through the stored hash. The token
// is never compared with a stored value; the store is asked for the hash.
// ErrTokenUnknown for a token that is not in the table, ErrTokenExpired once
// the deadline has passed.
func LookupLink(ctx context.Context, store *signstore.Store, token string, now time.Time) (*signstore.Party, error) {
	if token == "" {
		return nil, ErrTokenUnknown
	}
	p, err := store.GetPartyByTokenHash(ctx, HashLink(token))
	if err != nil {
		if errors.Is(err, signstore.ErrNotFound) {
			return nil, ErrTokenUnknown
		}
		return nil, err
	}
	if exp, err := time.Parse(time.RFC3339, p.TokenExpires); err == nil && exp.Before(now) {
		return nil, ErrTokenExpired
	}
	return p, nil
}
