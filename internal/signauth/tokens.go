package signauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Opaque tokens. A signer link token and a session id are random, high-
// entropy values whose only stored form is their SHA-256: a database copy
// must never be enough to sign a document.
//
// argon2 is the wrong tool here. It exists to stretch a human password, and a
// 256-bit random token has nothing to stretch.

const (
	// RandomBytes is the entropy of every opaque token this service issues.
	RandomBytes = 32

	jtiBytes = 16
)

// NewToken returns a 256-bit random token as URL-safe base64 without padding,
// so it survives a query string and a JSON body unchanged.
func NewToken() (string, error) {
	b := make([]byte, RandomBytes)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("signauth: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewJTI returns a token id: 16 random bytes in base32 (no padding, upper
// case). It appears in logs and in revoked_jtis, so it is kept short and
// readable; 128 bits is beyond any guess.
func NewJTI() (string, error) {
	b := make([]byte, jtiBytes)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("signauth: jti: %w", err)
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="), nil
}

// HashToken returns the lowercase hex SHA-256 of a token. This is what goes
// into parties.token_hash, clients.key_hash and parties.session_hash.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenHashEquals compares a token with a stored hash in constant time. The
// lookup by hash is already the primary path (a UNIQUE index); this is for the
// places where a hash is compared rather than searched.
func TokenHashEquals(token, storedHash string) bool {
	sum := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(storedHash)
	if err != nil || len(want) != len(sum) {
		return false
	}
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}
