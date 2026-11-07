package signauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Access tokens are compact JWS, signed with Ed25519 and assembled here from
// crypto/ed25519, encoding/base64 and JSON. There is no JWT dependency: the
// service needs one algorithm, one audience and a revocation list, and a
// library that negotiates algorithms is the risk, not the feature.
//
// header {"alg":"EdDSA","kid":"<sha256(pub)[0:8]>","typ":"JWT"}
// claims {"iss":"signsrv","sub":"<admin id|client id>","aud":"api",
//         "role":"admin|client","scopes":[...],"iat":...,"exp":...,"jti":...}

// Audience API is the only audience of an access token. Signer sessions are
// cookies and carry no JWT at all.
const (
	AudienceAPI = "api"
	Issuer      = "signsrv"

	// AccessTTL is short on purpose: revocation is a jti list, so a token
	// that is worth stealing must be worth little.
	AccessTTL = 15 * time.Minute

	// ClockSkew is tolerated on both ends of the validity window, for the
	// case where the API and the CLI that minted the token disagree by a
	// second or two.
	ClockSkew = 30 * time.Second
)

// Roles carried by an access token.
const (
	RoleAdmin  = "admin"
	RoleClient = "client"
)

var (
	// ErrTokenExpired reports a well-formed token past its exp.
	ErrTokenExpired = errors.New("signauth: token expired")
	// ErrTokenInvalid reports a token that cannot be trusted for any reason:
	// shape, signature, algorithm, issuer, audience, key id. It is one error
	// because the HTTP layer must not reveal which check failed.
	ErrTokenInvalid = errors.New("signauth: token invalid")
)

// Claims is the payload of an access token. Scopes is a slice, not a string,
// so a token that claims ["envelope:read,envelope:write"] as one element
// cannot silently pass a scope check for "envelope:write".
type Claims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience string   `json:"aud"`
	Role     string   `json:"role"`
	Scopes   []string `json:"scopes"`
	IssuedAt int64    `json:"iat"`
	Expires  int64    `json:"exp"`
	JTI      string   `json:"jti"`
}

// Valid reports whether the claims stand on their own at time t. Revocation is
// checked separately, against the database.
func (c *Claims) Valid(t time.Time) error {
	skew := int64(ClockSkew / time.Second)
	now := t.Unix()
	if c.Issuer != Issuer || c.Audience != AudienceAPI {
		return ErrTokenInvalid
	}
	if c.Subject == "" || c.JTI == "" {
		return ErrTokenInvalid
	}
	if c.Role != RoleAdmin && c.Role != RoleClient && c.Role != RoleUser {
		return ErrTokenInvalid
	}
	if c.Expires <= 0 || now-c.Expires > skew {
		return ErrTokenExpired
	}
	if c.IssuedAt != 0 && c.IssuedAt-now > skew {
		return ErrTokenInvalid
	}
	return nil
}

// HasScope reports whether the token carries a scope. An admin token carries
// every scope: the admin app is the operator, and listing its scopes in the
// token is a config file that can drift out of sync with the routes.
func (c *Claims) HasScope(scope string) bool {
	if c.Role == RoleAdmin {
		return true
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Keyring holds the Ed25519 signing key and the key id that the header
// advertises.
type Keyring struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	kid  string
}

// KeyID is the short fingerprint of the public key, "<sha256(pub)[0:8]>".
// A verifier that has been rotated keeps its old kid in the key file's
// sibling, so tokens minted before the rotation are rejected by kid, not by a
// signature failure that reads as tampering.
func (k *Keyring) KeyID() string { return k.kid }

// PublicKey exposes the public half, for the CLI and for the status command.
func (k *Keyring) PublicKey() ed25519.PublicKey { return k.pub }

// LoadKeyring reads the key from path, creating it with 0600 when it is
// missing, together with a ".pub" sibling that holds the public half in the
// same encoding. The private key is the seed+pub blob that crypto/ed25519
// produces, base64'd; it is the only place the key exists on disk.
func LoadKeyring(path string) (*Keyring, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createKeyring(path)
	}
	if err != nil {
		return nil, fmt.Errorf("signauth: read jwt key: %w", err)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signauth: %s is mode %o, must be 0600", path, info.Mode().Perm())
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("signauth: %s is not base64", path)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signauth: %s holds %d bytes, want %d", path, len(raw), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(raw)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signauth: %s has no public half", path)
	}
	return &Keyring{pub: pub, priv: priv, kid: keyID(pub)}, nil
}

func createKeyring(path string) (*Keyring, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signauth: generate jwt key: %w", err)
	}
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return nil, fmt.Errorf("signauth: key directory: %w", err)
	}
	blob := base64.StdEncoding.EncodeToString(priv)
	if err := writeFileOwner(path, []byte(blob+"\n")); err != nil {
		return nil, fmt.Errorf("signauth: write jwt key: %w", err)
	}
	pubBlob := base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path+".pub", []byte(pubBlob), 0o644); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("signauth: write jwt public key: %w", err)
	}
	return &Keyring{pub: pub, priv: priv, kid: keyID(pub)}, nil
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:8]
}

// MintAccess signs an access token. The jti is 16 random bytes in base32:
// short enough to read in a log line, long enough that a revoked id cannot be
// guessed by the caller that holds a valid token.
func (k *Keyring) MintAccess(c *Claims, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = AccessTTL
	}
	jti, err := NewJTI()
	if err != nil {
		return "", err
	}
	c.Issuer = Issuer
	c.Audience = AudienceAPI
	c.JTI = jti
	c.IssuedAt = time.Now().Unix()
	c.Expires = c.IssuedAt + int64(ttl/time.Second)
	return k.sign(c)
}

func (k *Keyring) sign(c *Claims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": k.kid, "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("signauth: header: %w", err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("signauth: claims: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(k.priv, []byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyAccess checks the signature, the algorithm, the key id, the issuer,
// the audience and the validity window. It does not consult the revocation
// list: that is a database lookup and belongs to the middleware, so a caller
// that only needs the cryptographic check can use this.
func (k *Keyring) VerifyAccess(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
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
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, ErrTokenInvalid
	}
	// "none" and every algorithm other than the one this service signs with
	// are rejected here, before the signature is looked at.
	if header.Alg != "EdDSA" || header.Typ != "JWT" {
		return nil, ErrTokenInvalid
	}
	if header.Kid != k.kid {
		return nil, ErrTokenInvalid
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrTokenInvalid
	}
	body := parts[0] + "." + parts[1]
	if !ed25519.Verify(k.pub, []byte(body), sig) {
		return nil, ErrTokenInvalid
	}
	c := &Claims{}
	if err := json.Unmarshal(payload, c); err != nil {
		return nil, ErrTokenInvalid
	}
	if err := c.Valid(time.Now()); err != nil {
		return nil, err
	}
	return c, nil
}
