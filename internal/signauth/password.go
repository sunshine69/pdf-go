package signauth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Admin password hashing: argon2id, the current standard for password
// storage, with the parameters the design asks for (docs/steps/03-auth.md):
// 64 MiB memory, 3 passes, 2 threads, 16-byte salt, 32-byte key. The cost is
// paid once per login and once per `admin add`, which is the right shape for a
// service with a handful of logins a day.
//
// The encoding is self-describing, so parameters can be raised later without
// breaking existing hashes:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<b64 salt>$<b64 hash>
const (
	argonTime     = 3
	argonMemoryKB = 65536
	argonThreads  = 2
	argonKeyLen   = 32
	argonSaltLen  = 16
)

// HashPassword returns an argon2id encoding of pw.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := randRead(salt); err != nil {
		return "", fmt.Errorf("signauth: salt: %w", err)
	}
	hash := argon2.IDKey([]byte(pw), salt, argonTime, argonMemoryKB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemoryKB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword compares a password with a stored encoding. Both the salt
// decode and the comparison are constant time; a malformed hash is an error,
// not a mismatch, so a corrupted database is visible.
func VerifyPassword(pw, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("signauth: unsupported password hash format")
	}
	// The header is m=<memory>, t=<time>, p=<threads>: bind each value to its
	// own variable. Swapping them re-derives a different key, so every stored
	// hash would read as a wrong password.
	var memory, time, threads int
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("signauth: hash version: %w", err)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("signauth: hash parameters: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("signauth: hash salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("signauth: hash value: %w", err)
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(time), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
