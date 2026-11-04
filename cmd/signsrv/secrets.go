package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// secretFileKeys are the secrets `secrets init` can write into the config
// file. The keystore passphrase is included, because a fresh install needs it
// in the file to open its own keystore; the command never overwrites a value
// that is already set, so it cannot rotate the passphrase out from under
// certificates that were written with it.
var secretFileKeys = []string{"keystore_pass", "admin_password"}

// secretsCmd implements `signsrv secrets init`. Secrets are asked for one per
// line with the keyboard echo silenced; a secret that is already in the file is
// left alone, which makes the command safe to run on a configured host.
func secretsCmd(configPath string, args []string) int {
	if len(args) != 1 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, `usage: signsrv secrets init [-config FILE]`)
		fmt.Fprintln(os.Stderr, `       writes the config secrets into the config file,`)
		fmt.Fprintln(os.Stderr, `       creating the lines that are missing and keeping the ones set.`)
		return 2
	}
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "signsrv secrets: -config is required; secrets have no home without a config file")
		return 1
	}

	lines, err := readConfigLines(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv secrets: %v\n", err)
		return 1
	}

	var added, kept []string
	keys := append([]string(nil), secretFileKeys...)
	sort.Strings(keys)
	if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
		lines[len(lines)-1] += "\n"
	}

	for _, key := range keys {
		if value := configValue(lines, key); value != "" {
			kept = append(kept, fmt.Sprintf("%s: already set, digest %s", key, short(sha256Of([]byte(value)))))
			continue
		}
		value, err := readSecret(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "signsrv secrets: %v\n", err)
			return 1
		}
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
		added = append(added, fmt.Sprintf("%s: set, digest %s", key, short(sha256Of([]byte(value)))))
	}

	if err := writeConfigLines(configPath, lines); err != nil {
		fmt.Fprintf(os.Stderr, "signsrv secrets: %v\n", err)
		return 1
	}
	for _, line := range appended(kept, added) {
		fmt.Println(line)
	}
	if len(added) == 0 {
		fmt.Println("nothing to do: every secret is already in", configPath)
	}
	fmt.Println("config file", configPath, "mode 0600")
	return 0
}

func appended(a, b []string) []string { return append(append([]string(nil), a...), b...) }

// readConfigLines loads a config file, tolerating a file that does not exist
// yet so the first `secrets init` can create it.
func readConfigLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{"# signsrv configuration"}, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// writeConfigLines writes atomically and restricts the file to its owner:
// this file holds secrets.
func writeConfigLines(path string, lines []string) error {
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0o600)
}

// configValue finds a key in config-file lines. Later lines win, matching the
// parser. The value is unquoted.
func configValue(lines []string, key string) string {
	value := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, val, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != key {
			continue
		}
		value = strings.Trim(strings.TrimSpace(val), `"'`)
	}
	return value
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readSecret reads a secret from the terminal with the keyboard echo silenced,
// falling back to plain stdin when stdin is not a terminal (scripts, pipes).
// The trailing newline is dropped; an empty line is an error, because an empty
// secret is not a secret.
// stdin is read through one shared buffered reader: a bufio.Reader fills its
// buffer eagerly, so a new reader per prompt would swallow the rest of a
// piped input on the first read.
var stdin = bufio.NewReader(os.Stdin)

func readSecret(label string) (string, error) {
	guard, isTTY := noEcho(int(os.Stdin.Fd()))
	defer guard.Restore()

	if isTTY {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, err := stdin.ReadString('\n')
	if isTTY {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	value := strings.TrimRight(line, "\r\n")
	if value == "" {
		return "", fmt.Errorf("%s is empty", label)
	}
	return value, nil
}

var _ = sha256Of

// readPassword reads a secret for an interactive command: the environment
// variable wins so a script can supply it, otherwise the terminal is prompted
// twice and the two answers must match. Prompting twice is the only defence
// against a typo in a password that cannot be read back afterwards.
func readPassword(label, envKey string) (string, error) {
	if value := os.Getenv(envKey); value != "" {
		return value, nil
	}
	value, err := readSecret(label)
	if err != nil {
		return "", err
	}
	again, err := readSecret("repeat it")
	if err != nil {
		return "", err
	}
	if value != again {
		return "", fmt.Errorf("the two entries of the %s do not match", label)
	}
	return value, nil
}
