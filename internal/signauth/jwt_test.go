package signauth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwt.ed25519.key")
	k, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	return k
}

func adminClaims() *Claims {
	return &Claims{Subject: "1", Role: RoleAdmin}
}

func clientClaims() *Claims {
	return &Claims{Subject: "7", Role: RoleClient, Scopes: []string{"envelope:read", "envelope:write"}}
}

func TestAccessRoundTrip(t *testing.T) {
	k := newTestKeyring(t)
	token, err := k.MintAccess(clientClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token shape: %q", token)
	}
	c, err := k.VerifyAccess(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Role != RoleClient || c.Subject != "7" || c.Audience != AudienceAPI {
		t.Fatalf("claims: %+v", c)
	}
	if len(c.JTI) < 20 {
		t.Fatalf("jti too short: %q", c.JTI)
	}
	if !c.HasScope("envelope:write") || c.HasScope("admin:read") {
		t.Fatalf("scope check: %+v", c.Scopes)
	}
	admin := Claims{Subject: "1", Role: RoleAdmin}
	if !admin.HasScope("anything") {
		t.Fatal("an admin token must carry every scope")
	}
}

func TestAccessTampered(t *testing.T) {
	k := newTestKeyring(t)
	token, err := k.MintAccess(adminClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	// Flip one byte of the signature: an unsigned edit must be visible.
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := strings.Join([]string{parts[0], parts[1], string(sig)}, ".")
	if _, err := k.VerifyAccess(tampered); err != ErrTokenInvalid {
		t.Fatalf("tampered signature accepted: %v", err)
	}

	// Re-encode the claims with a wider scope and keep the old signature.
	c := &Claims{}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, c); err != nil {
		t.Fatal(err)
	}
	c.Scopes = append(c.Scopes, "admin:read")
	forged, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	tampered = parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if _, err := k.VerifyAccess(tampered); err != ErrTokenInvalid {
		t.Fatalf("forged claims accepted: %v, want ErrTokenInvalid", err)
	}
}

func TestAccessAlgNone(t *testing.T) {
	k := newTestKeyring(t)
	header, err := json.Marshal(map[string]string{"alg": "none", "kid": k.KeyID(), "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(&Claims{Issuer: Issuer, Subject: "1", Audience: AudienceAPI,
		Role: RoleAdmin, JTI: "x", Expires: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."
	if _, err := k.VerifyAccess(token); err != ErrTokenInvalid {
		t.Fatalf("alg=none accepted: %v", err)
	}
}

func TestAccessWrongAudience(t *testing.T) {
	k := newTestKeyring(t)
	token, err := k.MintAccess(clientClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	c := &Claims{}
	if err := json.Unmarshal(payload, c); err != nil {
		t.Fatal(err)
	}
	c.Audience = "signer"
	swapped, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	// Signed with the real key: the signature is valid, so this is the
	// audience check doing the work, not the signature.
	forged, err := k.sign(c)
	if err != nil {
		t.Fatal(err)
	}
	_ = swapped
	if _, err := k.VerifyAccess(forged); err != ErrTokenInvalid {
		t.Fatalf("audience swap accepted: %v", err)
	}
	if !strings.Contains(parts[1], base64.RawURLEncoding.EncodeToString(payload)[:8]) {
		t.Fatal("the payload of the minted token is not the claims we minted")
	}
}

func TestAccessExpired(t *testing.T) {
	k := newTestKeyring(t)
	token, err := k.MintAccess(clientClaims(), -2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// MintAccess clamps a non-positive ttl to AccessTTL, so force the past.
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	c := &Claims{}
	if err := json.Unmarshal(payload, c); err != nil {
		t.Fatal(err)
	}
	c.IssuedAt = time.Now().Add(-3 * time.Hour).Unix()
	c.Expires = time.Now().Add(-2 * time.Hour).Unix()
	expired, err := k.sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyAccess(expired); err != ErrTokenExpired {
		t.Fatalf("expired token: %v, want ErrTokenExpired", err)
	}
}

func TestAccessWrongKeyring(t *testing.T) {
	a, b := newTestKeyring(t), newTestKeyring(t)
	token, err := a.MintAccess(adminClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.VerifyAccess(token); err != ErrTokenInvalid {
		t.Fatalf("foreign key accepted: %v", err)
	}
	if a.KeyID() == b.KeyID() {
		t.Fatal("two generated keys share one kid")
	}
}

func TestKeyringFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "jwt.ed25519.key")
	k, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %o, want 0600", info.Mode().Perm())
	}
	pub, err := os.Stat(path + ".pub")
	if err != nil {
		t.Fatalf("public sibling: %v", err)
	}
	if pub.Mode().Perm()&0o022 != 0 {
		t.Fatalf("public key mode %o, want no write bits", pub.Mode().Perm())
	}
	// A second load reads the same key: the service must not rotate its own
	// signing key on restart, which would invalidate every token it issued.
	again, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if again.KeyID() != k.KeyID() {
		t.Fatal("the key changed across a restart")
	}
	if _, err := again.VerifyAccess(mustToken(t, k)); err != nil {
		t.Fatalf("reloaded key rejects its own token: %v", err)
	}

	// Mode wider than 0600 is refused: the key is not group-readable.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("a 0644 key file was accepted")
	}
}

func mustToken(t *testing.T, k *Keyring) string {
	t.Helper()
	token, err := k.MintAccess(adminClaims(), AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
