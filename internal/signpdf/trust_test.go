package signpdf

import (
	"context"
	"testing"
	"time"
)

// A verification with no trust anchor accepts any signature whose chain holds
// together, including one rooted at a certificate the document brought with it.
// That answers "is this document intact" and nothing about who signed it, so the
// distinction has to be enforced somewhere, or a tool that prints a verdict is
// printing a weaker claim than the reader assumes. These tests pin down the
// boundary: the same code, one flag apart.

func TestAnchorAcceptsItsOwnDocuments(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	out, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}

	s.PinToCA()
	rep, err := s.Verify(context.Background(), out.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("a document this CA signed must verify under its own anchor: %v", rep.Errors)
	}
	for _, si := range rep.Signers {
		if !si.Trusted {
			t.Errorf("signer %s: Trusted=false under the issuing CA's anchor", si.Name)
		}
	}
}

// TestAnchorRefusesAnotherCA is the reason the anchor exists. Without it this
// same foreign document reports valid:true, because its chain is internally
// consistent and a verifier with no anchor has no opinion about who ran the CA.
func TestAnchorRefusesAnotherCA(t *testing.T) {
	tsa := newTSA(t)
	ours := newTestService(t, tsa)
	_, err := ours.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}

	foreign, err := NewService(Config{
		KeystoreDir: t.TempDir(),
		Passphrase:  "test-passphrase-1234",
		TSAURL:      tsa.URL,
		CASubject:   &CASubject{CommonName: "Competitor CA", Organization: "Competitor Ltd"},
		Clock:       time.Now,
	})
	if err != nil {
		t.Fatalf("NewService(foreign): %v", err)
	}
	foreignOut, err := foreign.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "competitor"))
	if err != nil {
		t.Fatalf("Certify(foreign): %v", err)
	}

	// Our verifier, our anchor: the foreign document is refused, and says why.
	ours.PinToCA()
	rep, err := ours.Verify(context.Background(), foreignOut.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Valid {
		t.Fatal("a document signed by another CA verified under our anchor")
	}
	if len(rep.Errors) == 0 {
		t.Fatal("refusal is not silent: the report has to say why")
	}

	// The same foreign document under the anchor that actually issued it is
	// fine: the anchor rejects the wrong issuer, not the notion of an issuer.
	ver, err := NewVerifier(Config{Anchor: foreign.CA().Cert, Clock: time.Now})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	rep, err = ver.Verify(context.Background(), foreignOut.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("foreign document under the foreign anchor: %v", rep.Errors)
	}
}

// TestVerifyWithoutAnchorIsIntegrityOnly records what the unpinned mode is and
// is not. It is kept deliberately: a future change that quietly made the
// unpinned path refuse foreign chains would break every recipient running a
// development binary, and a change that made it claim to have checked the
// issuer would be worse.
func TestVerifyWithoutAnchorIsIntegrityOnly(t *testing.T) {
	tsa := newTSA(t)
	s := newTestService(t, tsa)
	out, err := s.Certify(context.Background(), testPDF(t), certifyOpts(tsa, "signsrv"))
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}

	ver, err := NewVerifier(Config{Clock: time.Now})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if ver.Anchor() != nil {
		t.Fatal("a verifier built with no Anchor must report no anchor")
	}
	rep, err := ver.Verify(context.Background(), out.Data)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("the document is intact, so the integrity check should pass: %v", rep.Errors)
	}
	for _, si := range rep.Signers {
		if si.Trusted {
			t.Errorf("signer %s: Trusted=true with no anchor; nothing was checked about its issuer", si.Name)
		}
	}
}
