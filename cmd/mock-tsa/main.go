// Command mock-tsa is a local RFC 3161 timestamping authority for development
// and acceptance runs.
//
// It exists so a signing run needs no network: point tsa_url at it and every
// signature gets a real, verifiable timestamp token. The token is genuine
// PKCS#7 over the message imprint the signer asked about — it is not a stub —
// and the certificate carrying it is a self-signed CA with the id-kp-timeStamping
// extended key usage, which is what a timestamp verifier walks.
//
// It is NOT a production timestamp authority. It mints a fresh self-signed
// certificate on every start, keeps no log, and answers anyone who asks. A
// production tsa_url points at a service whose certificate the verifier can
// trace to a root it trusts.
//
// Usage:
//
//	mock-tsa [-listen 127.0.0.1:5193] [-path /tsr] [-serial HEX]
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

// tsaPolicy is the RFC 3161 id-tsa-policy-sha1 OID, used when a request does
// not name one. It is the same default the signing code asks for.
var tsaPolicy = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 1}

func main() {
	listen := flag.String("listen", "127.0.0.1:5193", "address to serve on")
	path := flag.String("path", "/tsr", "path the timestamping requests are read from")
	serialHex := flag.String("serial", "", "hex serial for the TSA certificate; a random one when empty")
	flag.Parse()

	key, cert, err := newTSA(*serialHex)
	if err != nil {
		log.Fatalf("mock-tsa: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(*path, handle(key, cert))
	log.Printf("mock-tsa: listening on %s%s, certificate serial %s",
		*listen, *path, cert.SerialNumber.Text(16))
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("mock-tsa: %v", err)
	}
}

// handle answers one timestamping request: parse the TSR, echo its nonce and
// policy, stamp the imprint, sign it with the TSA key, embed the certificate.
func handle(key *ecdsa.PrivateKey, cert *x509.Certificate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "mock tsa: bad request: "+err.Error())
			return
		}
		policy := req.TSAPolicyOID
		if len(policy) == 0 {
			policy = tsaPolicy
		}
		ts := &timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now().UTC(),
			Accuracy:          time.Second,
			SerialNumber:      big.NewInt(time.Now().UnixNano()),
			Policy:            policy,
			Nonce:             req.Nonce,
			Certificates:      []*x509.Certificate{cert},
			AddTSACertificate: true,
		}
		resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "mock tsa: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(resp)
	}
}

// newTSA mints the signing key and a self-signed CA certificate carrying the
// timestamping EKU. The certificate has to be a CA certificate: the PKCS#7
// verifier walks the chain to the certificate that signed the token, and a
// plain leaf certificate cannot sign one.
func newTSA(serialHex string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial := big.NewInt(time.Now().UnixNano())
	if serialHex != "" {
		serial = new(big.Int)
		if _, ok := serial.SetString(serialHex, 16); !ok {
			return nil, nil, fmt.Errorf("serial %q is not hex", serialHex)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "signsrv mock TSA",
			Organization: []string{"signsrv development"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
