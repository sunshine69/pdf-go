package signflow

import (
	"context"
	"github.com/sunshine69/pdf-go/internal/pdf"
	"strings"
	"testing"
	"time"
)

// The create accepts a widget and used to do nothing with it, which meant a
// bad placement could not be rejected: there was no code path that noticed.
// Now the placement is checked against the document that will actually carry
// the signatures, so a typo fails the create rather than surfacing as
// signatures in the wrong place after three parties have consented.

func createWithWidget(t *testing.T, w Widget) error {
	t.Helper()
	ctx := context.Background()
	d := newDeps(t)
	in := sampleBytes(t)
	_, err := d.Create(ctx, CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "Placement",
		ExpiresIn: 48 * time.Hour,
		Widget:    w,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	return err
}

func TestCreateRejectsAPageTheDocumentDoesNotHave(t *testing.T) {
	n, err := pdf.PageCount(sampleBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := createWithWidget(t, Widget{Page: n + 1}); err == nil {
		t.Fatalf("create accepted page %d of a %d page document", n+1, n)
	} else {
		var ve *ErrValidation
		if !AsValidation(err, &ve) {
			t.Fatalf("error = %v, want a field validation error", err)
		}
		if ve.Field != "widget.page" {
			t.Errorf("blamed %q, want widget.page", ve.Field)
		}
		if !strings.Contains(ve.Msg, "does not exist") {
			t.Errorf("message = %q, want it to name the missing page", ve.Msg)
		}
		if !strings.Contains(ve.Hint, "1 page") && !strings.Contains(ve.Hint, "pages") {
			t.Errorf("hint = %q, want it to say how many pages there are", ve.Hint)
		}
	}
}

func TestCreateRejectsANonZeroPageThatIsImpossible(t *testing.T) {
	for _, p := range []int{-1, -100} {
		if err := createWithWidget(t, Widget{Page: p}); err == nil {
			t.Errorf("create accepted page %d", p)
		}
	}
}

func TestCreateRejectsAnUnknownSignatureField(t *testing.T) {
	// The template has no signature field at all, so any name is a typo. The
	// old behaviour was to accept it and sign in the default corner.
	err := createWithWidget(t, Widget{Field: "Signature.On.The.Last.Page"})
	if err == nil {
		t.Fatal("create accepted a field name that is not in the document")
	}
	var ve *ErrValidation
	if !AsValidation(err, &ve) {
		t.Fatalf("error = %v, want a field validation error", err)
	}
	if ve.Field != "widget.field" {
		t.Errorf("blamed %q, want widget.field", ve.Field)
	}
}

func TestCreateRejectsNegativeCoordinates(t *testing.T) {
	if err := createWithWidget(t, Widget{Page: 1, X: -10}); err == nil {
		t.Error("create accepted a negative x")
	}
	if err := createWithWidget(t, Widget{Page: 1, Y: -10}); err == nil {
		t.Error("create accepted a negative y")
	}
}

// An empty widget is the ordinary case: the service chooses. It must not pay
// for a parse it has no use for, and must not be rejected.
func TestCreateAcceptsAnEmptyWidget(t *testing.T) {
	if err := createWithWidget(t, Widget{}); err != nil {
		t.Fatalf("create rejected the default placement: %v", err)
	}
}

func TestCreateStoresThePlacement(t *testing.T) {
	ctx := context.Background()
	d := newDeps(t)
	in := sampleBytes(t)
	created, err := d.Create(ctx, CreateRequest{
		Template:  in,
		Fill:      fillSpecFor(t, in),
		Parties:   parties(1),
		Title:     "Placement kept",
		ExpiresIn: 48 * time.Hour,
		Widget:    Widget{Page: 1, X: 120, Y: 400},
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	env, err := d.Store.GetEnvelope(ctx, created.Envelope.ID)
	if err != nil {
		t.Fatal(err)
	}
	if env.WidgetPage != 1 || env.WidgetX != 120 || env.WidgetY != 400 {
		t.Errorf("stored widget = page %d (%v,%v), want page 1 (120,400)",
			env.WidgetPage, env.WidgetX, env.WidgetY)
	}
}
