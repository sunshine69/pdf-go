package signstore

// created_by_subject is the row-level ownership marker a client's dashboard
// filters on, so an access-control decision rests on it. Two things about it
// were easy to get wrong and nothing checked them:
//
//   - the filter has to compose with the status and text-search filters rather
//     than replace them, because the dashboard sends all three at once;
//   - an envelope with no owner recorded must stay invisible to a client. Those
//     rows (every envelope written before v9) carry NULL, which reads back as
//     the empty string. A filter written as "owner = ? or owner is null" would
//     hand every legacy envelope to whichever client asked first.

import (
	"context"
	"testing"
)

func TestListEnvelopesOwnerFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rows := []struct {
		title, subject string
		status         EnvelopeStatus
	}{
		{"Alpha One", "client:7", StatusReady},
		{"Alpha Two", "client:7", StatusDraft},
		{"Beta One", "client:9", StatusReady},
		{"Orphan", "", StatusReady}, // written before v9: no owner recorded
	}
	for i, r := range rows {
		e := &Envelope{ID: idOf(i), Title: r.title, Status: r.status,
			CreatedBy: 1, ExpiresAt: "2030-01-01T00:00:00Z", CreatedBySubject: r.subject}
		if err := s.CreateEnvelope(ctx, e); err != nil {
			t.Fatalf("create %s: %v", r.title, err)
		}
	}

	count := func(status, search, owner string) int {
		t.Helper()
		list, total, err := s.ListEnvelopes(ctx, status, search, owner, 50, 0)
		if err != nil {
			t.Fatalf("list(%q,%q,%q): %v", status, search, owner, err)
		}
		if len(list) != total {
			t.Fatalf("list(%q,%q,%q) returned %d rows but total %d", status, search, owner, len(list), total)
		}
		for _, e := range list {
			if owner != "" && e.CreatedBySubject != owner {
				t.Fatalf("list(owner=%q) leaked envelope %q owned by %q", owner, e.Title, e.CreatedBySubject)
			}
		}
		return total
	}

	// No owner filter is the admin view: everything, including the orphan.
	if got := count("", "", ""); got != 4 {
		t.Errorf("unfiltered = %d, want 4", got)
	}
	// An owner sees its own rows and nobody else's, across both of its
	// statuses.
	if got := count("", "", "client:7"); got != 2 {
		t.Errorf("client:7 = %d, want 2", got)
	}
	if got := count("", "", "client:9"); got != 1 {
		t.Errorf("client:9 = %d, want 1", got)
	}
	// A subject that owns nothing owns not even the unowned rows. This is the
	// case that matters: NULL is not a wildcard.
	if got := count("", "", "client:11"); got != 0 {
		t.Errorf("client:11 = %d, want 0 (an unowned envelope is not a client's)", got)
	}

	// The filters compose. The dashboard sends status and search together with
	// the owner, so an owner filter that were ANDed only into one branch of the
	// search would leak rows here.
	if got := count("ready", "", "client:7"); got != 1 {
		t.Errorf("client:7 ready = %d, want 1", got)
	}
	if got := count("", "Alpha", "client:7"); got != 2 {
		t.Errorf("client:7 Alpha = %d, want 2", got)
	}
	// "Alpha" matches two envelopes but only one of them belongs to client:9.
	if got := count("", "Beta", "client:7"); got != 0 {
		t.Errorf("client:7 Beta = %d, want 0", got)
	}
	if got := count("", "Beta", "client:9"); got != 1 {
		t.Errorf("client:9 Beta = %d, want 1", got)
	}
	// The orphan is reachable by an unfiltered search and by nothing else.
	if got := count("", "Orphan", ""); got != 1 {
		t.Errorf("unfiltered Orphan = %d, want 1", got)
	}
	if got := count("", "Orphan", "client:7"); got != 0 {
		t.Errorf("client:7 Orphan = %d, want 0", got)
	}

	// The stored value survives a read, so the filter is matching what was
	// written and not a scan artifact.
	got, err := s.GetEnvelope(ctx, idOf(0))
	if err != nil {
		t.Fatal(err)
	}
	if got.CreatedBySubject != "client:7" {
		t.Errorf("CreatedBySubject read back as %q, want client:7", got.CreatedBySubject)
	}
	orphan, err := s.GetEnvelope(ctx, idOf(3))
	if err != nil {
		t.Fatal(err)
	}
	if orphan.CreatedBySubject != "" {
		t.Errorf("orphan CreatedBySubject read back as %q, want empty", orphan.CreatedBySubject)
	}
}
