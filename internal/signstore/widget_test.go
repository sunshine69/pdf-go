package signstore

import (
	"context"
	"testing"
)

// Schema 7: the placement travels with the envelope.
//
// Four nullable columns, and the nullability is the whole design. The batch has
// to tell "the drafter asked for page 3" from "the drafter had no opinion", and
// the second answer has to survive an envelope created before the columns
// existed. Storing 0 for "no opinion" would give the batch two ways to say the
// same thing and force it to read both.

func TestWidgetRoundTripsThroughTheRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	e := &Envelope{
		ID:          idOf(700),
		Title:       "placed",
		Status:      StatusDraft,
		ExpiresAt:   "2030-01-01T00:00:00Z",
		WidgetField: "sig.page3.box",
		WidgetPage:  3,
		WidgetX:     72.5,
		WidgetY:     612,
	}
	if err := s.CreateEnvelope(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEnvelope(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WidgetField != e.WidgetField {
		t.Errorf("widget field = %q, want %q", got.WidgetField, e.WidgetField)
	}
	if got.WidgetPage != 3 {
		t.Errorf("widget page = %d, want 3", got.WidgetPage)
	}
	if got.WidgetX != 72.5 || got.WidgetY != 612 {
		t.Errorf("widget coordinates = (%v,%v), want (72.5,612)", got.WidgetX, got.WidgetY)
	}
}

func TestEmptyWidgetReadsBackAsNoOpinion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	e := &Envelope{ID: idOf(701), Title: "unplaced", Status: StatusDraft,
		ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := s.CreateEnvelope(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEnvelope(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WidgetField != "" || got.WidgetPage != 0 || got.WidgetX != 0 || got.WidgetY != 0 {
		t.Errorf("empty widget read back as field %q page %d (%v,%v), want all zero",
			got.WidgetField, got.WidgetPage, got.WidgetX, got.WidgetY)
	}

	// A row written by a release that had no widget columns at all: the columns
	// are NULL, and NULL must read as the same zero, not as a scan error. That
	// is the upgrade path every deployed database takes.
	if _, err := s.DB().ExecContext(ctx,
		`insert into envelopes(id, title, status, template_sha, filled_sha, current_sha,
		                      created_at, updated_at, expires_at)
		 values('`+idOf(702)+`', 'pre-widget', 'draft', '', '', '',
		         '2020-01-01T00:00:00Z','2020-01-01T00:00:00Z','2030-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	old, err := s.GetEnvelope(ctx, idOf(702))
	if err != nil {
		t.Fatalf("read a pre-widget row: %v", err)
	}
	if old.WidgetPage != 0 || old.WidgetField != "" {
		t.Errorf("pre-widget row read back as page %d field %q, want the zero values",
			old.WidgetPage, old.WidgetField)
	}

	// And the list query the API serves, not just the single-row read.
	out, _, err := s.ListEnvelopes(ctx, "draft", "", "", 100, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, env := range out {
		if env.ID == idOf(702) && (env.WidgetPage != 0 || env.WidgetField != "") {
			t.Errorf("pre-widget row through the list query has a widget: %+v", env)
		}
	}
}

// A page or coordinate of zero is not a placement anyone can act on, so it is
// stored as NULL. Writing 0 would make the batch guess whether the drafter
// meant page 0 (never legal) or nothing.
func TestZeroWidgetColumnsAreStoredAsNull(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	e := &Envelope{ID: idOf(703), Title: "field only", Status: StatusDraft,
		ExpiresAt: "2030-01-01T00:00:00Z", WidgetField: "Signature"}
	if err := s.CreateEnvelope(ctx, e); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB().QueryRowContext(ctx,
		"select count(*) from envelopes where id = ? and widget_page is null and widget_x is null",
		e.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("unset page/coordinate stored as %d non-NULL row(s), want NULL", n)
	}
}
