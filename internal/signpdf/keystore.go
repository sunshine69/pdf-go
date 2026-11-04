package signpdf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// keystore helpers: the encryption primitives, base64 fields, and the file
// mode rules. The keystore directory holds a private key, so every file it
// contains is written 0600 and checked at load.

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func b64(b []byte) string            { return base64.RawStdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }

// writeOwner writes a file with mode 0600, creating the parent directory. The
// private key is the file this is for: a group-readable key file is a finding.
func writeOwner(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// enforceMode refuses a key file that anyone other than the owner can read.
// The check happens at load, not at write, so a file copied in from elsewhere
// is caught.
func enforceMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("signpdf: %s has mode %04o, the key file must be 0600", path, info.Mode().Perm())
	}
	return nil
}
