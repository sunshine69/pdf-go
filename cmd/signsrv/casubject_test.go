package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// caSubjectConfig writes a minimal usable config with the given ca_* body and
// returns its path.
func caSubjectConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keystore"), 0o750); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "c.env")
	body = "listen=127.0.0.1:8080\npublic_url=https://sign.example.org\ndev=true\n" +
		"keystore_dir=$DIR/keystore\nkeystore_pass=secret\n" + body
	body = strings.ReplaceAll(body, "$DIR", dir)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCASubjectConfigNilWhenUnset is the compatibility guard: an operator with
// no ca_* keys must get the historical CA name, not a nearly-empty DN.
func TestCASubjectConfigNilWhenUnset(t *testing.T) {
	// LoadConfig returns the parsed config alongside its validation problems;
	// this test is about parsing, not about the config being complete.
	cfg, _ := LoadConfig(caSubjectConfig(t, ""))
	if cfg.CASubject != nil {
		t.Errorf("CASubject = %+v, want nil so the keystore keeps its defaults", cfg.CASubject)
	}
}

func TestCASubjectConfigParsed(t *testing.T) {
	path := caSubjectConfig(t, strings.Join([]string{
		"ca_common_name=Example.org Document Signing CA",
		"ca_org=Example Ltd",
		"ca_unit=Trust Services",
		"ca_street=1 Example Street",
		"ca_locality=Example City",
		"ca_province=Example County",
		"ca_postal=EX1 2AB",
		"ca_country=gb",
		"ca_email=signing@example.org",
	}, "\n")+"\n")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s := cfg.CASubject
	if s == nil {
		t.Fatalf("CASubject is nil, want the parsed subject")
	}
	want := map[string]string{
		"CommonName":         s.CommonName,
		"Organization":       s.Organization,
		"OrganizationalUnit": s.OrganizationalUnit,
		"StreetAddress":      s.StreetAddress,
		"Locality":           s.Locality,
		"Province":           s.Province,
		"PostalCode":         s.PostalCode,
		"Country":            s.Country,
		"Email":              s.Email,
	}
	checks := map[string]string{
		"CommonName":         "Example.org Document Signing CA",
		"Organization":       "Example Ltd",
		"OrganizationalUnit": "Trust Services",
		"StreetAddress":      "1 Example Street",
		"Locality":           "Example City",
		"Province":           "Example County",
		"PostalCode":         "EX1 2AB",
		"Country":            "gb", // case folding is signpdf's job, not config's
		"Email":              "signing@example.org",
	}
	for field, got := range want {
		if exp := checks[field]; got != exp {
			t.Errorf("CASubject.%s = %q, want %q", field, got, exp)
		}
	}
}

// TestCASubjectKeysAreRecognised proves the allowlist knows the new keys. An
// unrecognised key fails checkconfig, so a missing entry looks like a typo to
// an operator who typed the right thing.
func TestCASubjectKeysAreRecognised(t *testing.T) {
	for _, key := range []string{
		"ca_common_name", "ca_org", "ca_unit", "ca_email", "ca_locality",
		"ca_province", "ca_street", "ca_postal", "ca_country",
	} {
		if !configKeys[key] {
			t.Errorf("configKeys is missing %q; checkconfig would reject a valid setting", key)
		}
	}
}
