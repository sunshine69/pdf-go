package signauth

import (
	"os"
	"path/filepath"
)

// dirOf is the directory a key file lives in, "." when the path has no
// directory part.
func dirOf(path string) string {
	dir := filepath.Dir(path)
	if dir == "" {
		return "."
	}
	return dir
}

// writeFileOwner writes a file with 0600 permissions, creating the parent
// directory. The private signing key is the file this is for: group and other
// read bits on it are a finding, not a style preference.
func writeFileOwner(path string, data []byte) error {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
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
