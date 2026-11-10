package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The CA is published so a recipient can verify a PDF they hold. The tests here
// are about two things: the certificate that comes out of the endpoint is the
// same one the keystore holds, and the endpoint answers for a caller with no
// token. A recipient verifying a document has no account.

func caGET(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	res, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	})
	return res
}

func TestCACertIsPublicAndMatchesKeystore(t *testing.T) {
	cfg := testConfig(t)
	s := newServer(cfg, logger(cfg), nil)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	if s.signer == nil {
		t.Fatal("signing service is missing, so there is no CA to publish")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)

	res := caGET(t, ts, "/ca.crt")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a caller with no token", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("Content-Type = %q, want the PEM certificate type", ct)
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "ca.crt") {
		t.Errorf("Content-Disposition = %q, want a filename so a browser saves the file", cd)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(body)
	if blk == nil {
		t.Fatalf("no PEM block in the response: %q", string(body))
	}
	if blk.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want CERTIFICATE", blk.Type)
	}
	if !bytesEqual(blk.Bytes, s.signer.CA().Cert.Raw) {
		t.Error("the certificate served is not the one in the keystore")
	}
}

// The fingerprint is what a recipient compares before importing the CA. It is
// the SHA-256 of the DER, so `openssl x509 -fingerprint -sha256` on the
// downloaded file must print the same value.
func TestCAFingerprintMatchesTheServedCertificate(t *testing.T) {
	cfg := testConfig(t)
	s := newServer(cfg, logger(cfg), nil)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)

	res := caGET(t, ts, "/api/v1/ca")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(s.signer.CA().Cert.Raw)
	want := hex.EncodeToString(h[:])
	if m["sha256"] != want {
		t.Errorf("sha256 = %v, want %s (the keystore CA)", m["sha256"], want)
	}
	if m["subject"] != s.signer.CA().Cert.Subject.String() {
		t.Errorf("subject = %v, want %q", m["subject"], s.signer.CA().Cert.Subject.String())
	}
	if m["link"] != "/ca.crt" {
		t.Errorf("link = %v, want the path a recipient can download from", m["link"])
	}
}

// An instance with no keystore cannot publish a CA. It has to say so, because a
// recipient following a link expects a certificate.
func TestCACertAnswers503WithoutAKeystore(t *testing.T) {
	cfg := testConfig(t)
	s := newServer(cfg, logger(cfg), nil)
	if s == nil {
		t.Fatal("newServer returned nil")
	}
	s.signer = nil
	ts := httptest.NewServer(s.withDefaults(s.mux))
	t.Cleanup(ts.Close)

	for _, p := range []string{"/ca.crt", "/api/v1/ca"} {
		res := caGET(t, ts, p)
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503 when the keystore is unavailable", p, res.StatusCode)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
