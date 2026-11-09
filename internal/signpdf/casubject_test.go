package signpdf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// createWithSubject creates a keystore in dir with the given subject.
func createWithSubject(t *testing.T, dir string, s *CASubject) *x509.Certificate {
	t.Helper()
	ca, err := LoadCAWith(dir, "pass", s)
	if err != nil {
		t.Fatalf("LoadCAWith: %v", err)
	}
	return ca.Cert
}

func TestCASubjectDefaults(t *testing.T) {
	for _, s := range []*CASubject{nil, {}} {
		cert := createWithSubject(t, t.TempDir(), s)
		if got := cert.Subject.CommonName; got != "signsrv CA" {
			t.Errorf("CommonName = %q, want the historical default \"signsrv CA\"", got)
		}
		if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "signsrv" {
			t.Errorf("Organization = %v, want the historical default [signsrv]", cert.Subject.Organization)
		}
	}
}

func TestCASubjectApplied(t *testing.T) {
	subj := &CASubject{
		CommonName:         "Example.org Document Signing CA",
		Organization:       "Example Ltd",
		OrganizationalUnit: "Trust Services",
		StreetAddress:      "1 Example Street",
		Locality:           "Example City",
		Province:           "Example County",
		PostalCode:         "EX1 2AB",
		Country:            "gb",
		Email:              "signing@example.org",
	}
	cert := createWithSubject(t, t.TempDir(), subj)

	checks := []struct {
		name string
		got  []string
		want string
	}{
		{"organization", cert.Subject.Organization, "Example Ltd"},
		{"unit", cert.Subject.OrganizationalUnit, "Trust Services"},
		{"locality", cert.Subject.Locality, "Example City"},
		{"province", cert.Subject.Province, "Example County"},
		{"street", cert.Subject.StreetAddress, "1 Example Street"},
		{"postal", cert.Subject.PostalCode, "EX1 2AB"},
		{"country", cert.Subject.Country, "GB"}, // upper-cased in place
	}
	for _, c := range checks {
		if len(c.got) != 1 || c.got[0] != c.want {
			t.Errorf("%s = %v, want [%q]", c.name, c.got, c.want)
		}
	}
	if cert.Subject.CommonName != subj.CommonName {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, subj.CommonName)
	}

	// ExtraNames is a marshal-only field; the round-tripped DN lands in
	// Names, so that is what a verifier sees.
	var email string
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}) {
			email, _ = atv.Value.(string)
		}
	}
	if email != subj.Email {
		t.Errorf("emailAddress = %q, want %q\n  DN: %s", email, subj.Email, cert.Subject.String())
	}
}

// TestCASubjectPartial asserts that setting a subset produces a DN with only
// the fields supplied, rather than one padded with empty strings.
func TestCASubjectPartial(t *testing.T) {
	cert := createWithSubject(t, t.TempDir(), &CASubject{Organization: "Acme GmbH"})

	full := cert.Subject.String()
	if !strings.Contains(full, "Acme GmbH") {
		t.Fatalf("subject %q does not contain the organisation", full)
	}
	for _, junk := range []string{"ST=", "L=", "OU=", "PC=", "STREET="} {
		if strings.Contains(full, junk) {
			t.Errorf("subject %q carries empty field %q; unset keys should be omitted", full, junk)
		}
	}
	// CommonName keeps the default so the certificate is still recognisable to
	// anything matching on it.
	if cert.Subject.CommonName != "signsrv CA" {
		t.Errorf("CommonName = %q, want the default preserved when unset", cert.Subject.CommonName)
	}
}

// TestCASubjectIgnoredWhenKeystoreExists is the footgun guard: the subject
// settings describe a certificate that already exists, so they must never
// silently re-issue or replace the CA -- doing so would invalidate every
// document signed under the old one.
func TestCASubjectIgnoredWhenKeystoreExists(t *testing.T) {
	dir := t.TempDir()
	first := createWithSubject(t, dir, nil)

	again, err := LoadCAWith(dir, "pass", &CASubject{
		CommonName:   "Totally Different CA",
		Organization: "Other Ltd",
	})
	if err != nil {
		t.Fatalf("second LoadCAWith: %v", err)
	}
	if again.Cert.Subject.CommonName != first.Subject.CommonName {
		t.Errorf("existing CA was renamed: got %q, want %q",
			again.Cert.Subject.CommonName, first.Subject.CommonName)
	}
	if again.Cert.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Errorf("existing CA was re-issued: serial changed from %s to %s",
			first.SerialNumber, again.Cert.SerialNumber)
	}
}

// TestCASubjectWrittenToDisk keeps the on-disk ca.crt in step with the
// configured subject, since operators fingerprint and distribute that file
// rather than the in-memory CA.
func TestCASubjectWrittenToDisk(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCAWith(dir, "pass", &CASubject{
		CommonName: "Example CA", Organization: "Example Ltd", Country: "GB",
	})
	if err != nil {
		t.Fatalf("LoadCAWith: %v", err)
	}

	pemBytes, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}

	// Parse it back the way an operator or a PDF reader would, rather than
	// trusting the in-memory copy.
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("ca.crt is not PEM")
	}
	onDisk, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse ca.crt: %v", err)
	}
	if onDisk.Subject.CommonName != "Example CA" {
		t.Errorf("ca.crt CommonName = %q, want %q", onDisk.Subject.CommonName, "Example CA")
	}
	if got := onDisk.Subject.Organization; len(got) != 1 || got[0] != "Example Ltd" {
		t.Errorf("ca.crt Organization = %v, want [Example Ltd]", got)
	}
	if got := onDisk.Subject.Country; len(got) != 1 || got[0] != "GB" {
		t.Errorf("ca.crt Country = %v, want [GB]", got)
	}
	if !onDisk.IsCA {
		t.Errorf("ca.crt is not marked as a CA certificate")
	}
}

// TestLeafInheritsCAOrganization keeps the chain readable. A verifier inspecting
// a signature sees the CA and the leaf next to each other; if the CA named the
// configured organisation while every signer still said "signsrv", the two
// would look unrelated.
func TestLeafInheritsCAOrganization(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadCAWith(dir, "pass", &CASubject{Organization: "Example Ltd"})
	if err != nil {
		t.Fatalf("LoadCAWith: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	s := &Service{ca: ca, clock: time.Now}
	leaf, err := s.issueLeaf(key, "Grace Hopper", "grace@example.test", time.Now())
	if err != nil {
		t.Fatalf("issueLeaf: %v", err)
	}

	got := leaf.Subject.Organization
	if len(got) != 1 || got[0] != "Example Ltd" {
		t.Errorf("leaf Organization = %v, want it inherited from the CA ([Example Ltd])", got)
	}
	if len(ca.Cert.Subject.Organization) != 1 || ca.Cert.Subject.Organization[0] != "Example Ltd" {
		t.Fatalf("CA Organization = %v, want [Example Ltd]", ca.Cert.Subject.Organization)
	}
}

// TestLeafFallsBackWhenCAHasNoOrganization covers a CA created outside this
// package whose subject omits the organisation: the leaf must still carry one.
func TestLeafFallsBackWhenCAHasNoOrganization(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadCAWith(dir, "pass", &CASubject{CommonName: "Bare CA"})
	if err != nil {
		t.Fatalf("LoadCAWith: %v", err)
	}
	// LoadCAWith keeps the default organisation, so clear it to exercise the
	// fallback the way an externally supplied CA would.
	ca.Cert.Subject.Organization = nil

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	s := &Service{ca: ca, clock: time.Now}
	leaf, err := s.issueLeaf(key, "Alan Turing", "alan@example.test", time.Now())
	if err != nil {
		t.Fatalf("issueLeaf: %v", err)
	}
	if len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != "signsrv" {
		t.Errorf("leaf Organization = %v, want the fallback [signsrv]", leaf.Subject.Organization)
	}
}
