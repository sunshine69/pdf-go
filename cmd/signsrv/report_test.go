package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// TestAdminReportCertifiedButUnsigned is the case a status column cannot
// express. The document the envelope points at verifies cleanly — the
// certification signature the create step laid down is real and intact — yet
// not one party has signed it. A report that answers only "valid" would tell an
// operator the job is finished. The counts say it is not.
func TestAdminReportCertifiedButUnsigned(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	admin := accessOf(t, ts)

	se := newSignEnv(t, ts, admin)

	// Point the envelope at the certified revision, which is the document the
	// parties were shown. It carries one signature: the service's own.
	revs, err := store.ListRevisions(context.Background(), se.id)
	if err != nil {
		t.Fatal(err)
	}
	var certified signstore.Revision
	for _, r := range revs {
		if r.Kind == signstore.KindCertified {
			certified = r
		}
	}
	if certified.SHA256 == "" {
		t.Fatal("create did not produce a certified revision")
	}
	if err := store.SetEnvelopeCurrentSHA(context.Background(), se.id, certified.SHA256); err != nil {
		t.Fatal(err)
	}

	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/envelopes/"+se.id+"/report", admin, "")
	if code != http.StatusOK {
		t.Fatalf("report: code %d", code)
	}
	rep, _ := out["report"].(map[string]any)
	if rep == nil {
		t.Fatalf("report answer: %v", out)
	}
	// The document itself is intact: it carries the certification signature and
	// nothing has changed since. Intact is not the same as finished.
	if rep["valid"] != true {
		t.Fatalf("the certified document must verify: %v", rep)
	}
	if out["sha256"] != certified.SHA256 {
		t.Fatalf("the report states sha %v, the envelope holds %s", out["sha256"], certified.SHA256)
	}
	signers, _ := rep["signers"].([]any)
	if len(signers) != 1 {
		t.Fatalf("the certified document carries one signature: %v", rep)
	}
	if out["signed_parties"] == nil || out["signed_parties"].(float64) != 0 {
		t.Fatalf("the report must count the party signatures, not every signature: %v", out)
	}
	if out["required_parties"] == nil || out["required_parties"].(float64) != 2 {
		t.Fatalf("the report must name the parties the envelope asks for: %v", out)
	}
	if out["complete"] != false {
		t.Fatalf("a document with no party signature is not complete: %v", out)
	}
}

// TestAdminReportCompleteAfterBatch is the other side of the same answer: after
// the batch every party has signed, and the report says so.
func TestAdminReportCompleteAfterBatch(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := envelopeServer(t, cfg)
	admin := accessOf(t, ts)

	id := deliverOne(t, ts, admin)
	code, out := adminCode(t, ts, http.MethodGet, "/api/v1/envelopes/"+id+"/report", admin, "")
	if code != http.StatusOK {
		t.Fatalf("report: code %d", code)
	}
	if out["signed_parties"] == nil || out["signed_parties"].(float64) != 2 {
		t.Fatalf("party signatures after the batch: %v", out)
	}
	if out["required_parties"] == nil || out["required_parties"].(float64) != 2 {
		t.Fatalf("required parties: %v", out)
	}
	if out["complete"] != true {
		t.Fatalf("a document every party signed is complete: %v", out)
	}
}
