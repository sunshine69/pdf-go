package signauth

import (
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("encoding shape: %q", hash)
	}
	if strings.Contains(hash, "correct") {
		t.Fatal("the password leaked into its own hash")
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
}

func TestPasswordWrongAndTampered(t *testing.T) {
	hash, err := HashPassword("a-long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("a-long-enough-passworD", hash)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
	// Flip a character of the stored hash value: the login must fail, and it
	// must fail as a mismatch, not as a corrupted database.
	// The last character is not used: a 32-byte key encodes to 43 base64
	// characters and the final one carries two bits that the encoding keeps at
	// zero, so flipping it is invisible. Pick a character that has weight.
	i := strings.LastIndex(hash, "$")
	c := hash[i+1]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	tampered := hash[:i+1] + string(c) + hash[i+2:]
	ok, err = VerifyPassword("a-long-enough-password", tampered)
	if err != nil || ok {
		t.Fatalf("tampered hash value accepted: ok=%v err=%v", ok, err)
	}

	// A tampered salt also fails: the salt is part of the derivation, so the
	// re-derived key is a different key.
	j := strings.LastIndex(hash[:i], "$")
	sc := hash[j+1]
	if sc == 'A' {
		sc = 'B'
	} else {
		sc = 'A'
	}
	tampered = hash[:j+1] + string(sc) + hash[j+2:]
	ok, err = VerifyPassword("a-long-enough-password", tampered)
	if err != nil || ok {
		t.Fatalf("tampered salt accepted: ok=%v err=%v", ok, err)
	}
}

func TestPasswordSaltIsRandom(t *testing.T) {
	a, err := HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}
	for _, h := range []string{a, b} {
		ok, err := VerifyPassword("same-password", h)
		if err != nil || !ok {
			t.Fatalf("cross verify: ok=%v err=%v", ok, err)
		}
	}
}

func TestPasswordRejectsForeignFormat(t *testing.T) {
	// A bcrypt-shaped or truncated string must be an error, so a corrupted
	// column is visible instead of reading as "wrong password".
	for _, h := range []string{"", "bcrypt$2b$10$abc", "$argon2i$v=19$m=1,t=1,p=1$AAA$BBB", "$argon2id$v=19$m=1,t=1,p=1$AAA"} {
		ok, err := VerifyPassword("anything", h)
		if err == nil {
			t.Fatalf("format %q accepted (ok=%v), want an error", h, ok)
		}
		if ok {
			t.Fatalf("format %q verified", h)
		}
	}
}
