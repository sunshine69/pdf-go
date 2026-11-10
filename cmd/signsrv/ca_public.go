package main

import (
	"net/http"
	"strings"
)

// The CA is the one file a recipient needs that is not inside the PDF. A
// signature travels with its chain, so a reader can prove the document is
// intact with the file alone; proving *who* signed needs the root as a trust
// anchor, and that is not in the file. Publishing the certificate is safe: it
// is the public half. A verifier that cannot fetch it has to be told the
// fingerprint over the phone, which is why the fingerprint is served too.
//
// These routes are open. No scope, no token: the answer is the same for every
// caller, and the CA is not a secret.

func (s *server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if s.signer == nil {
		writeProblem(w, http.StatusServiceUnavailable, "keystore_unavailable",
			"the signing service is not configured on this instance",
			"no CA certificate to publish; check the keystore path in the config")
		return
	}
	pem := s.signer.CA().CertPEM()
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	// A name on the request for a file makes a browser download it instead of
	// rendering the PEM in a tab.
	if strings.HasSuffix(r.URL.Path, ".crt") {
		w.Header().Set("Content-Disposition", `attachment; filename="ca.crt"`)
	}
	// The CA cannot change once signatures exist: replacing it invalidates every
	// chain a recipient has imported. So a cache is safe, and a stale copy is
	// worse than a cached one.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pem))
}

// handleCAFingerprint answers the question a recipient asks before importing the
// certificate: is this the CA I was told to trust? The digest is of the
// certificate's DER, the same value `openssl x509 -fingerprint -sha256` prints,
// so the two can be compared directly.
func (s *server) handleCAFingerprint(w http.ResponseWriter, r *http.Request) {
	if s.signer == nil {
		writeProblem(w, http.StatusServiceUnavailable, "keystore_unavailable",
			"the signing service is not configured on this instance", "")
		return
	}
	ca := s.signer.CA()
	// withDefaults puts no-store on every /api/ path, which is right for
	// anything that answers about a caller. This one answers about the CA, and
	// the CA is fixed, so caching is safe here and the override is deliberate.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":    ca.Cert.Subject.String(),
		"issuer":     ca.Cert.Issuer.String(),
		"not_before": ca.Cert.NotBefore,
		"not_after":  ca.Cert.NotAfter,
		"sha256":     hexSha(ca.Cert.Raw),
		"link":       "/ca.crt",
	})
}
