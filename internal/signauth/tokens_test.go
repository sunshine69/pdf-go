package signauth

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestNewTokenShapeAndEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		a, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatal("two tokens are identical")
		}
		if len(a) < 40 {
			t.Fatalf("token too short: %d chars", len(a))
		}
		// URL-safe: no '+', '/', '=' so the token survives a query string.
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(a) {
			t.Fatalf("token is not URL-safe: %q", a)
		}
		seen[a] = true
	}
	if len(seen) != 8 {
		t.Fatal("collisions in 16 tokens")
	}
}

func TestHashToken(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := HashToken(token)
	if len(hash) != 64 {
		t.Fatalf("hash length %d, want 64 hex chars", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Fatalf("hash is not hex: %v", err)
	}
	if HashToken(token) != hash {
		t.Fatal("hash is not a function of the token")
	}
	sum := sha256.Sum256([]byte(token))
	if hex.EncodeToString(sum[:]) != hash {
		t.Fatal("hash is not SHA-256")
	}
	// A stored hash must never be the token, in any encoding.
	if hash == token || len(hash) == len(token) {
		t.Fatal("the hash is the token")
	}
	if !TokenHashEquals(token, hash) {
		t.Fatal("TokenHashEquals rejects the matching pair")
	}
	other, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if TokenHashEquals(other, hash) {
		t.Fatal("TokenHashEquals accepts a foreign token")
	}
	if TokenHashEquals(token, "not hex") {
		t.Fatal("TokenHashEquals accepts a malformed hash")
	}
}

func TestNewJTI(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		jti, err := NewJTI()
		if err != nil {
			t.Fatal(err)
		}
		if len(jti) != 26 {
			t.Fatalf("jti %q has length %d, want 26", jti, len(jti))
		}
		if !regexp.MustCompile(`^[A-Z2-7]+$`).MatchString(jti) {
			t.Fatalf("jti is not base32: %q", jti)
		}
		if seen[jti] {
			t.Fatalf("jti collision: %q", jti)
		}
		seen[jti] = true
	}
}
