package signflow

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBatchReclaimDoesNotStackOntoAnExistingSignature covers the second half of
// the placement bug: the batch numbered its stack from the parties it was
// signing now, not from the signatures the document already carried.
//
// A batch that signs one party and then fails on the next leaves that signature
// committed; the retry signs the remaining party from the newest revision, as
// the batch is documented to do. The retry restarted its stack index at 0, so
// the second signature landed on the first one's box. Nothing downstream
// notices: the document verifies, the signer count is right, and the two
// signatures print on top of each other.
func TestBatchReclaimDoesNotStackOntoAnExistingSignature(t *testing.T) {
	f := newBatchFixtureWithTSA(t, 2, flakyTSA(t, 2))
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")

	// First run: party 1 signs, party 2's timestamp fails. The row is requeued
	// and party 1's signature stays where it was written.
	if _, err := f.runBatch(); err == nil {
		t.Fatal("first batch run succeeded; the fixture TSA was meant to fail the second signature")
	}
	if n := len(f.partyRevisions()); n != 1 {
		t.Fatalf("first run wrote %d signatures, want 1: the retry needs one to stack on", n)
	}

	// The failure pushed the row's next attempt into the future. Pull it back
	// rather than sleeping, so the test measures the retry's placement and not
	// the queue's backoff.
	f.releaseLeases()
	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("second batch run: %v", err)
	}
	if out == nil {
		t.Fatal("second batch run found no work; the retry never happened")
	}
	data, err := f.deps.Store.GetPDF(out.Final)
	if err != nil {
		t.Fatalf("read final document: %v", err)
	}

	boxes := sigBoxes(t, data)
	if len(boxes) < 2 {
		t.Fatalf("found %d signature boxes in the final document, want at least 2", len(boxes))
	}
	sortRects(boxes)
	for i := 0; i+1 < len(boxes); i++ {
		lower, upper := boxes[i], boxes[i+1]
		if overlap := lower.y1 - upper.y0; overlap > 0 {
			t.Errorf("signature box %d (y %.0f..%.0f) overlaps box %d (y %.0f..%.0f) by %.0f pt: "+
				"the retry placed its signature on top of the one already in the document",
				i, lower.y0, lower.y1, i+1, upper.y0, upper.y1, overlap)
		}
	}
}

// flakyTSA is a timestamp authority that answers every request except number
// failOn, which it refuses with a 500. Failing the second party signature is
// how a batch comes to be re-run with one signature already written.
func flakyTSA(t *testing.T, failOn int) string {
	t.Helper()
	upstream := newTestTSA(t)
	var n int
	mux := http.NewServeMux()
	mux.HandleFunc("/tsr", func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == failOn {
			http.Error(w, "timestamp authority is having a moment", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp, err := http.Post(upstream, "application/timestamp-query", bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(out)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/tsr"
}
