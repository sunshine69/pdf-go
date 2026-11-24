package pdf

import (
	"testing"

	"github.com/benoitkugler/pdf/formfill"
	"github.com/sunshine69/pdf-go/internal/schema"
)

// TestFieldValueCheckboxStates pins what a boolean or a word means for a check
// box. Both mistakes below shipped once: a false that left the box ticked, and
// a "true" written as the export state /true into a document whose only mark is
// /Yes, which viewers show as unticked.
func TestFieldValueCheckboxStates(t *testing.T) {
	// threeA is the shape Form 18a ships: /Opt present with the mark name.
	threeA := schema.Field{
		Name:    "Weekly",
		Type:    schema.TypeCheckbox,
		Options: []string{"Off", "Yes"},
	}
	// noOpt has no /Opt at all, so the mark name only exists in the widget's
	// appearance dictionary (surfaced as States).
	noOpt := schema.Field{
		Name:   "Monthly",
		Type:   schema.TypeCheckbox,
		States: []string{"Yes"},
	}
	ticked := schema.Field{
		Name:    "Vase",
		Type:    schema.TypeCheckbox,
		Options: []string{"Off", "Vase"},
	}

	for _, tt := range []struct {
		name string
		f    schema.Field
		raw  any
		want formfill.FDFName
	}{
		{"true uses the document's on-state", threeA, true, "Yes"},
		{"false clears the box", threeA, false, "Off"},
		{"on-state comes from States when Opt is absent", noOpt, true, "Yes"},
		{"false clears it too", noOpt, false, "Off"},
		{"a non-Yes mark is used, not the literal Yes", ticked, true, "Vase"},
		{`"true" is folded, not written as /true`, threeA, "true", "Yes"},
		{`"TRUE" folds the same way`, threeA, "TRUE", "Yes"},
		{`"yes" folds to the document's mark`, noOpt, "yes", "Yes"},
		{`"false" clears`, threeA, "false", "Off"},
		{`"Off" clears`, threeA, "Off", "Off"},
		{"an empty value clears", threeA, "", "Off"},
		{`an explicit mark passes through`, ticked, "Vase", "Vase"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FieldValue(tt.f, tt.raw)
			if err != nil {
				t.Fatalf("FieldValue(%v): %v", tt.raw, err)
			}
			name, ok := got.(formfill.FDFName)
			if !ok {
				t.Fatalf("got %T (%v), want a check box state name", got, got)
			}
			if name != tt.want {
				t.Errorf("value %v of %q: state = %q, want %q", tt.raw, tt.f.Name, name, tt.want)
			}
		})
	}
}

// TestFieldValueCheckboxFalseIsNotOn is the one-line regression: the boolean
// branch used to return the on-state whatever the value was, so false left a
// tick in the form and verify called it a mismatch.
func TestFieldValueCheckboxFalseIsNotOn(t *testing.T) {
	f := schema.Field{Name: "Weekly", Type: schema.TypeCheckbox, Options: []string{"Off", "Yes"}}
	for _, raw := range []any{false, "false", "no", "Off", ""} {
		got, err := FieldValue(f, raw)
		if err != nil {
			t.Fatal(err)
		}
		if got != formfill.FDFName("Off") {
			t.Errorf("%v left the box at %v", raw, got)
		}
	}
}

// TestCanonicalStateIsPerDocument is why verify has to fold against the field
// rather than the word: the same request ("true") is /Yes on the RTA's Form 18a
// and /Oui on a French form, and a word-level fold called the French fill a
// mismatch.
func TestCanonicalStateIsPerDocument(t *testing.T) {
	rta := schema.Field{Name: "Weekly", Type: schema.TypeCheckbox, Options: []string{"Off", "Yes"}}
	french := schema.Field{Name: "z10", Type: schema.TypeCheckbox, Options: []string{"Off", "Oui"}}

	if got := CanonicalState(rta, "true"); got != "Yes" {
		t.Errorf("RTA form: true -> %q, want Yes", got)
	}
	if got := CanonicalState(french, "true"); got != "Oui" {
		t.Errorf("French form: true -> %q, want Oui", got)
	}
	// What came back out of the document is already a mark name, and stays one.
	if got := CanonicalState(french, "Oui"); got != "Oui" {
		t.Errorf("Oui folded to %q", got)
	}
	if CanonicalState(french, "true") != CanonicalState(french, "Oui") {
		t.Error(`"true" and the document's own mark must compare equal`)
	}
	// An unrecognised mark is passed through so it stays visible in the report.
	if got := CanonicalState(rta, "Vase"); got != "Vase" {
		t.Errorf("unknown mark folded to %q, want it left alone", got)
	}
}
