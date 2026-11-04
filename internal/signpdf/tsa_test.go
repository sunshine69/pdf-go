package signpdf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// A test TSA. Tests must not go to the network: a signature is accepted only
// when the timestamp token is bound to the request, so the tests need a TSA
// that behaves like one. The library checks the binding rules (algorithm,
// message imprint, nonce, embedded certificate) against this server's answers,
// which is the point of running it.
//
// The server is honest by default: it echoes the nonce and the imprint. Two
// switches make it dishonest so tests can prove that the binding is enforced:
// nonceMismatch (the response carries a different nonce) and reject (a
// rejection status, which is the "TSA is down" case).

type testTSA struct {
	URL           string
	Cert          *x509.Certificate
	srv           *httptest.Server
	key           *ecdsa.PrivateKey
	nonceMismatch bool
	reject        bool
	requests      int
}

func newTSA(t *testing.T) *testTSA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signsrv test TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{extKeyUTSTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	tsa := &testTSA{key: key, Cert: cert}
	mux := http.NewServeMux()
	mux.HandleFunc("/tsr", func(w http.ResponseWriter, r *http.Request) {
		tsa.requests++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		if tsa.reject {
			resp, _ := timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.SystemFailure)
			w.Header().Set("Content-Type", "application/timestamp-reply")
			w.Write(resp)
			return
		}
		nonce := req.Nonce
		if tsa.nonceMismatch && nonce != nil {
			nonce = new(big.Int).Add(nonce, big.NewInt(1))
		}
		ts := timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now().UTC(),
			Accuracy:          time.Second,
			SerialNumber:      big.NewInt(7),
			Policy:            testPolicyOID,
			Nonce:             nonce,
			Certificates:      []*x509.Certificate{cert},
			AddTSACertificate: true,
		}
		resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	tsa.srv = srv
	tsa.URL = srv.URL + "/tsr"
	return tsa
}

// The TSA certificate carries the standard timestamping EKU; crypto/x509
// refuses to create a certificate with an EKU value it does not know, so the
// library constant is the only usable one here.
var extKeyUTSTimeStamping = x509.ExtKeyUsageTimeStamping

// testPolicyOID is the RFC 3161 policy the server answers under. A request
// asks for a policy; an empty OID cannot be marshalled, so the server supplies
// one and the response carries it.
var testPolicyOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 1}
