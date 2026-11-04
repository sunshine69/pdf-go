package signpdf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// documentSigningOID is the Document Signing extended key usage
// (1.3.6.1.5.5.7.3.36, RFC 9336). crypto/x509 has no constant for it, so the
// OID has to be written as a raw extension; a certificate that carries it is
// parsed back with the OID in UnknownExtKeyUsage.
var documentSigningOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

// The CA is the root of every signature the service produces. It is a
// self-signed ECDSA P-256 certificate valid for ten years, kept in the
// keystore directory as two files: ca.crt (public, PEM) and ca.key (private,
// encrypted at rest with a key derived from the keystore passphrase).
//
// The passphrase never appears in a log, in the config dump, or in the file:
// the file stores a random salt and a random nonce, and the key is derived
// per call. A wrong passphrase produces a GCM open failure, which is reported
// as "passphrase wrong" and never as a panic.

const (
	caYears = 10
	// keystoreHeader is the first field of the encrypted key file. Bumping it
	// means the format changed and an old file must not be read blindly.
	keystoreHeader = "signsrv-keystore"
	keystoreFormat = keystoreHeader + ".v1"
)

// The encrypted form of a private key is four fields separated by '|':
//
//	signsrv-keystore.v1|<salt>|<nonce>|<ciphertext>

// deriveKey turns the passphrase and the file's salt into a 32-byte AES key
// with argon2id. Parameters match the password hash (m=64MiB, t=3, p=2): the
// same "pay once, slowly" trade, and the same resistance to a GPU attack on a
// stolen keystore file.
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, 32)
}

// seal encrypts data under the passphrase, generating the salt and nonce.
func seal(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("signpdf: salt: %w", err)
	}
	key := deriveKey(passphrase, salt)
	block, err := aesGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("signpdf: nonce: %w", err)
	}
	ct := block.Seal(nil, nonce, data, nil)
	out := strings.Join([]string{
		keystoreFormat,
		b64(salt), b64(nonce), b64(ct),
	}, "|")
	return []byte(out), nil
}

// open decrypts a keystore file. It distinguishes a malformed file from a
// wrong passphrase, because the operator needs to know which one happened.
func open(data []byte, passphrase string) ([]byte, error) {
	fields := strings.Split(strings.TrimSpace(string(data)), "|")
	if len(fields) != 4 {
		return nil, errors.New("signpdf: keystore file is not a " + keystoreFormat + " envelope")
	}
	if fields[0] != keystoreFormat {
		return nil, fmt.Errorf("signpdf: keystore file has format %q, this build reads %q", fields[0], keystoreFormat)
	}
	salt, err := unb64(fields[1])
	if err != nil {
		return nil, fmt.Errorf("signpdf: keystore salt: %w", err)
	}
	nonce, err := unb64(fields[2])
	if err != nil {
		return nil, fmt.Errorf("signpdf: keystore nonce: %w", err)
	}
	ct, err := unb64(fields[3])
	if err != nil {
		return nil, fmt.Errorf("signpdf: keystore ciphertext: %w", err)
	}
	key := deriveKey(passphrase, salt)
	block, err := aesGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := block.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("signpdf: keystore passphrase is wrong (the key did not open)")
	}
	return pt, nil
}

// CA is the signing certificate authority of the service: its certificate,
// its private key, and the leaf issuance parameters derived from them.
type CA struct {
	Cert     *x509.Certificate
	Key      *ecdsa.PrivateKey
	Keystore string // directory the two files live in
	// crl is the revocation stub: an empty CRL, re-issued every 24h. Leaf
	// certificates have no CRLDP, so nothing reads it in v1; it exists so a
	// verifier configured to check revocation has an answer.
	crl   []byte
	crlAt time.Time
}

// Fingerprint is the hex SHA-256 of the CA's DER encoding, the value stored in
// revisions.cert_fingerprint.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.Cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// LoadCA reads ca.crt and ca.key from dir. When the files are absent it
// creates them (0600 on the key), which is the first-start path.
//
// A passphrase that does not open the existing key is a fatal error: the
// service must not sign with a key it cannot prove it owns.
func LoadCA(dir, passphrase string) (*CA, error) {
	if dir == "" {
		return nil, errors.New("signpdf: keystore directory is required")
	}
	if passphrase == "" {
		return nil, errors.New("signpdf: keystore passphrase is required")
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certData, certErr := os.ReadFile(certPath)
	keyData, keyErr := os.ReadFile(keyPath)

	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		return createCA(dir, passphrase)
	}
	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, fmt.Errorf("signpdf: read %s: %w", certPath, certErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("signpdf: read %s: %w", keyPath, keyErr)
	}
	// One file present, the other missing: refuse to guess which is right.
	if certErr != nil || keyErr != nil {
		return nil, fmt.Errorf("signpdf: keystore is incomplete: %s present, %s absent (refusing to recreate over an existing CA)", certPath, keyPath)
	}

	der, err := x509.ParseCertificate(unwrapPEM(certData, "CERTIFICATE"))
	if err != nil {
		return nil, fmt.Errorf("signpdf: parse %s: %w", certPath, err)
	}
	keyEnv, err := open(keyData, passphrase)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyEnv)
	if err != nil {
		return nil, fmt.Errorf("signpdf: parse %s: %w", keyPath, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signpdf: %s holds a %T, signpdf signs with ECDSA P-256", keyPath, key)
	}
	if !der.PublicKey.(*ecdsa.PublicKey).Equal(&ec.PublicKey) {
		return nil, errors.New("signpdf: ca.key does not match ca.crt")
	}
	if err := enforceMode(keyPath); err != nil {
		return nil, err
	}
	ca := &CA{Cert: der, Key: ec, Keystore: dir}
	if ca.Cert.NotAfter.Before(time.Now()) {
		return nil, fmt.Errorf("signpdf: CA expires at %s, regenerate the keystore", ca.Cert.NotAfter.Format("2006-01-02"))
	}
	return ca, nil
}

// createCA generates the CA key and certificate, writes ca.crt (PEM, 0644)
// and ca.key (encrypted envelope, 0600).
func createCA(dir, passphrase string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("signpdf: keystore dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signpdf: CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-1 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "signsrv CA", Organization: []string{"signsrv"}},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(365 * 24 * time.Hour * caYears),
		// The CA signs documents as well as certificates: the certification
		// signature is made with this key, so the certificate needs the
		// signing bits alongside the cert-signing bit.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// The Document Signing EKU (RFC 9336) has no Go constant, so it is
		// written as a raw extension. Parsing the certificate back puts the
		// OID in UnknownExtKeyUsage, which is exactly where the verifier
		// looks for it: a certificate with no EKU at all is refused by
		// RequireDigitalSignature(true).
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{documentSigningOID},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("signpdf: CA cert: %w", err)
	}
	cert := &CA{Cert: parseMust(der), Key: key, Keystore: dir}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	env, err := seal(keyDER, passphrase)
	if err != nil {
		return nil, err
	}
	if err := writeOwner(filepath.Join(dir, "ca.key"), env); err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("signpdf: write ca.crt: %w", err)
	}
	return cert, nil
}

// CertPEM is the CA certificate in PEM, the form stored in Out.CertPEM for a
// certification signature.
func (ca *CA) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
}

// CRL returns the empty revocation stub, issuing a new one when the stored
// copy is older than 24 hours. An empty CRL is a valid statement: "no
// certificate of this CA has been revoked", which is exactly the v1 promise.
func (ca *CA) CRL(now time.Time) ([]byte, error) {
	if len(ca.crl) > 0 && now.Sub(ca.crlAt) < 24*time.Hour {
		return ca.crl, nil
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	crl, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("signpdf: CRL: %w", err)
	}
	ca.crl, ca.crlAt = crl, now
	return crl, nil
}

func unwrapPEM(data []byte, wantType string) []byte {
	b, _ := pem.Decode(data)
	if b == nil {
		return data // tolerate a DER file
	}
	if b.Type != wantType {
		return nil
	}
	return b.Bytes
}

func parseMust(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic("signpdf: generated CA cert does not parse: " + err.Error())
	}
	return c
}

func randSerial() (*big.Int, error) {
	n := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("signpdf: serial: %w", err)
	}
	return s, nil
}
