package signflow

import (
	"context"
	"testing"

	"github.com/sunshine69/pdf-go/internal/pdf"
)

// Where the signatures go.
//
// A create has always accepted a widget — a page, a field, a coordinate — and
// the batch has always ignored it, signing page 1 bottom-left for every
// envelope in the system. The drafter of a forty page contract who put the
// signature boxes on page 39 got signatures on page 1 and an API response that
// said everything was fine.
//
// The page number in the finished document's own field geometry is the ground
// truth here: it is what a reader, a verifier and a printout see.

func TestBatchSignsOnThePageTheEnvelopeAsksFor(t *testing.T) {
	f := newBatchFixture(t, 3)
	f.setWidgetPage(t, 2)
	f.consent(0, "Alice Adamson")
	f.consent(1, "Berta Brandt")
	f.consent(2, "Cesar Costa")

	out, err := f.runBatch()
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	data, err := f.deps.Store.GetPDF(out.Final)
	if err != nil {
		t.Fatalf("read final document: %v", err)
	}

	fields, err := pdf.FieldPages(data)
	if err != nil {
		t.Fatalf("read fields of the signed document: %v", err)
	}
	n, err := pdf.PageCount(data)
	if err != nil {
		t.Fatalf("count pages: %v", err)
	}
	if n < 2 {
		t.Skipf("the sample template has %d page(s); this test needs two", n)
	}

	var onWanted, sigs int
	for _, fld := range fields {
		if fld.Type != "signature" {
			continue
		}
		sigs++
		if fld.Page == 2 {
			onWanted++
		}
		t.Logf("signature field %q is on page %d (rect %v)", fld.Name, fld.Page, fld.Rect)
	}
	if sigs == 0 {
		t.Fatal("the signed document carries no signature fields; the assertion would prove nothing")
	}
	// Three parties signed. The certification signature may sit wherever
	// certification puts it — it is a separate stamp with its own options — but
	// every party signature belongs on the requested page.
	if onWanted < 3 {
		t.Errorf("%d of %d signature fields are on page 2, want at least the 3 parties; "+
			"the batch is signing where it always did, not where the envelope says",
			onWanted, sigs)
	}
}

// setWidgetPage writes the placement the way the API leaves it: on the row.
// Going through the row rather than CreateRequest is deliberate — the bug lived
// in the read back, where the batch ignored the stored widget and used its own
// default, so a test that only exercised the request object would not have
// caught it.
func (f *batchFixture) setWidgetPage(t *testing.T, page int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.deps.Store.DB().ExecContext(ctx,
		"update envelopes set widget_page = ? where id = ?", page, f.env.ID); err != nil {
		t.Fatalf("set widget page: %v", err)
	}
	env, err := f.deps.Store.GetEnvelope(ctx, f.env.ID)
	if err != nil {
		t.Fatalf("read envelope back: %v", err)
	}
	if env.WidgetPage != page {
		t.Fatalf("envelope read back page %d, want %d", env.WidgetPage, page)
	}
	f.env = env
}
