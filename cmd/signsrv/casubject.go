package main

import (
	"strings"

	"github.com/sunshine69/pdf-go/internal/signpdf"
)

// caSubjectFrom builds the CA subject from the ca_* configuration keys.
//
// Returns nil when none of them are set, which is the signal for the keystore
// to keep the built-in name. The values are whatever the operator writes; the
// CA certificate is self-signed, so they are self-asserted and are never a
// substitute for distributing and fingerprinting the certificate itself.
func caSubjectFrom(get func(key, def string) string) *signpdf.CASubject {
	s := &signpdf.CASubject{
		CommonName:         strings.TrimSpace(get("ca_common_name", "")),
		Organization:       strings.TrimSpace(get("ca_org", "")),
		OrganizationalUnit: strings.TrimSpace(get("ca_unit", "")),
		Locality:           strings.TrimSpace(get("ca_locality", "")),
		Province:           strings.TrimSpace(get("ca_province", "")),
		StreetAddress:      strings.TrimSpace(get("ca_street", "")),
		PostalCode:         strings.TrimSpace(get("ca_postal", "")),
		Country:            strings.TrimSpace(get("ca_country", "")),
		Email:              strings.TrimSpace(get("ca_email", "")),
	}
	if *s == (signpdf.CASubject{}) {
		return nil
	}
	return s
}

// describeCASubject renders the subject for checkconfig. An operator is told to
// read the printed configuration before the first start, so the identity that is
// about to become permanent has to appear there -- and an unset subject has to
// say which name will be used instead of printing nothing.
func (c *Config) describeCASubject() string {
	s := c.CASubject
	if s == nil {
		return "default (CN=signsrv CA); set the ca_* keys before the first start"
	}
	parts := make([]string, 0, 9)
	for _, p := range []struct{ label, value string }{
		{"CN", s.CommonName}, {"O", s.Organization}, {"OU", s.OrganizationalUnit},
		{"street", s.StreetAddress}, {"L", s.Locality}, {"ST", s.Province},
		{"PC", s.PostalCode}, {"C", s.Country}, {"email", s.Email},
	} {
		if p.value != "" {
			parts = append(parts, p.label+"="+p.value)
		}
	}
	return strings.Join(parts, ", ") + " (honoured on first start only)"
}
