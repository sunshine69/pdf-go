package signauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// HMAC access tokens: the compact JWS a caller signs for itself.
//
// This is the second algorithm in the service, and the separation is the
// security property. VerifyAccess (EdDSA) never looks at HS256 and this
// verifier never looks at EdDSA: neither takes an "alg" from the header and
// picks a key type accordingly, which is the classic break where a token
// signed with the service's *public* key passes as an HMAC.
//
// The caller's secret is per user (users.jwt_secret). It is not one secret for
// the whole system: with a shared secret, the holder writes "sub":"admin:1"
// and "role":"admin" into its own JSON and is the service. Here, sub picks the
// row, and the row's scopes and role override whatever the token claims —
// see Auth.RequireAPI.

// AlgHS256 is the algorithm of a caller-minted token.
const AlgHS256 = "HS256"

// RoleUser is the role of a caller-minted token. It is not RoleAdmin: the
// admin routes assert RoleAdmin, and a user row is never granted admin:read.
const RoleUser = "user"

// MintUserToken signs an access token with secret, in the same compact
// encoding as Keyring.MintAccess. The CLI calls this and never contacts the
// service to obtain a token.
//
// The claims are the caller's, with three exceptions: iss, aud and typ are
// pinned to this service, the expiry is computed from ttl (not taken from the
// caller), and a jti is generated so the token is loggable.
func MintUserToken(secret, username string, scopes []string, ttl time.Duration) (string, error) {
	if secret == "" || username == "" {
		return "", ErrTokenInvalid
	}
	if ttl <= 0 || ttl > AccessTTL {
		ttl = AccessTTL
	}
	jti, err := NewJTI()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	c := Claims{
		Issuer:   Issuer,
		Subject:  username,
		Audience: AudienceAPI,
		Role:     RoleUser,
		Scopes:   scopes,
		IssuedAt: now,
		Expires:  now + int64(ttl/time.Second),
		JTI:      jti,
	}
	header, err := json.Marshal(map[string]string{"alg": AlgHS256, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(hmacSHA(secret, body)), nil
}

// VerifyUserToken checks an HS256 token against one secret. It pins the
// algorithm to HS256, so an EdDSA token (with its own signature, or with the
// public key as an HMAC secret) is refused here on the algorithm, before the
// signature is considered.
//
// The claims returned are the token's. The caller must then override Scopes
// and Role from the users row: the token is signed by someone who holds the
// secret, and holding a secret is not a grant of scopes.
func VerifyUserToken(secret, token string) (*Claims, error) {
	if secret == "" {
		return nil, ErrTokenInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrTokenInvalid
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, ErrTokenInvalid
	}
	// Pinned. A header that says EdDSA, "none", HS384, or anything else fails
	// here; and a kid is not part of this scheme, so one present is refused.
	if header.Alg != AlgHS256 || header.Typ != "JWT" || header.Kid != "" {
		return nil, ErrTokenInvalid
	}
	want := hmacSHA(secret, parts[0]+"."+parts[1])
	if len(sig) != len(want) || subtle.ConstantTimeCompare(sig, want) != 1 {
		return nil, ErrTokenInvalid
	}
	c := &Claims{}
	if err := json.Unmarshal(payload, c); err != nil {
		return nil, ErrTokenInvalid
	}
	if err := c.Valid(time.Now()); err != nil {
		return nil, err
	}
	// sub is the username of the row this token is for. A subject in the
	// "kind:id" shape belongs to an admin or a client and is minted by the
	// service, so it is never valid on this path.
	if strings.ContainsRune(c.Subject, ':') {
		return nil, ErrTokenInvalid
	}
	return c, nil
}

// IsHS256Token reports whether a bearer token is a caller-minted one, by its
// header. The middleware uses it to choose the verifier, and the algorithm is
// pinned inside each verifier, so this is a routing hint only — never a trust
// decision.
func IsHS256Token(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct{ Alg string }
	if err := json.Unmarshal(raw, &header); err != nil {
		return false
	}
	return header.Alg == AlgHS256
}

func hmacSHA(secret, body string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return m.Sum(nil)
}
