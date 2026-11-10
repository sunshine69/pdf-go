package signflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestStampDispatchRecordsTheSentBytes(t *testing.T) {
	doc := []byte("%PDF-1.4 signed bytes")
	sum := sha256.Sum256(doc)
	digest := hex.EncodeToString(sum[:])

	matching, err := json.Marshal(&Receipt{FinalSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}

	// A receipt attesting to a different digest than the bytes being sent is the
	// case that matters. It must be refused rather than re-stamped to agree:
	// re-stamping would make the pair look self-consistent and hide the very
	// disagreement the field exists to expose.
	other, _ := json.Marshal(&Receipt{FinalSHA256: "aa"})
	if _, err := (&Deps{}).stampDispatch(other, doc, "contract-signed.pdf"); err == nil {
		t.Fatal("dispatch of bytes the receipt does not attest to was accepted")
	}

	// Appending one byte changes what is sent, so the check must fail with it -
	// this is exactly the check a recipient runs with sha256sum.
	appended := append(append([]byte{}, doc...), []byte("X")...)
	if _, err := (&Deps{}).stampDispatch(matching, appended, "contract-signed.pdf"); err == nil {
		t.Fatal("appended byte accepted: dispatch hash does not track the bytes")
	}

	// Matching bytes: the fields are filled from what is actually leaving.
	out, err := (&Deps{}).stampDispatch(matching, doc, "contract-signed.pdf")
	if err != nil {
		t.Fatalf("matching bytes refused: %v", err)
	}
	var r Receipt
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("stamped receipt is not JSON: %v", err)
	}
	if r.DispatchSHA256 != r.FinalSHA256 {
		t.Fatalf("dispatch=%s final=%s, want equal", r.DispatchSHA256, r.FinalSHA256)
	}
	if r.DispatchBytes != len(doc) {
		t.Fatalf("dispatch_bytes=%d, want %d", r.DispatchBytes, len(doc))
	}
	if r.Filename != "contract-signed.pdf" {
		t.Fatalf("filename=%q, want contract-signed.pdf", r.Filename)
	}
}

func TestStampDispatchDoesNotInventAnAttestation(t *testing.T) {
	// A receipt with no final_sha256 attests to nothing. Stamping it records what
	// is being sent but does not conjure a value for what was verified.
	raw, _ := json.Marshal(&Receipt{})
	out, err := (&Deps{}).stampDispatch(raw, []byte("doc"), "f.pdf")
	if err != nil {
		t.Fatalf("empty attestation refused: %v", err)
	}
	var r Receipt
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if r.DispatchSHA256 == "" {
		t.Fatal("dispatch_sha256 left blank when bytes were available")
	}
	if r.FinalSHA256 != "" {
		t.Fatalf("final_sha256 invented as %q", r.FinalSHA256)
	}
}
