package main

import (
	"os"
	"strings"
	"testing"
)

// The placement of a signature is the decision most likely to be made wrong and
// noticed last: nothing is auto-detected, so a create that says nothing about
// placement still succeeds and puts every signature in the bottom-left corner of
// page 1. These tests pin two things: that the CLI can actually express a
// placement, and that `pdf-go doc` says where the signature will go.

// 1. The flags map onto the service's widget object, and an unset flag is
// omitted rather than sent as a zero. A page of 0 would be read as page 0 and
// refused, so "not asked for" has to stay absent.
func TestWidgetSpecOmitsUnsetFlags(t *testing.T) {
	cases := []struct {
		name         string
		field        string
		page         int
		x, y         float64
		wantKeys     int
		wantField    string
		wantPage     any
		wantX, wantY float64
		wantNil      bool
	}{
		{name: "nothing asked for", wantNil: true},
		{name: "field anchor", field: "SigClient", wantKeys: 1, wantField: "SigClient"},
		{name: "page only", page: 3, wantKeys: 1, wantPage: 3},
		{name: "exact spot", page: 3, x: 72, y: 648, wantKeys: 3, wantPage: 3, wantX: 72, wantY: 648},
		{name: "field and page", field: "Sig", page: 2, wantKeys: 2, wantField: "Sig", wantPage: 2},
	}
	for _, tc := range cases {
		got := widgetSpec(tc.field, tc.page, tc.x, tc.y)
		if tc.wantNil {
			if got != nil {
				t.Fatalf("%s: got %v, want the key left out entirely", tc.name, got)
			}
			continue
		}
		if len(got) != tc.wantKeys {
			t.Fatalf("%s: %d keys %v, want %d", tc.name, len(got), got, tc.wantKeys)
		}
		if tc.wantField != "" && got["field"] != tc.wantField {
			t.Errorf("%s: field is %v, want %q", tc.name, got["field"], tc.wantField)
		}
		if tc.wantPage != nil && got["page"] != tc.wantPage {
			t.Errorf("%s: page is %v, want %v", tc.name, got["page"], tc.wantPage)
		}
		if tc.wantX != 0 && got["x"] != tc.wantX {
			t.Errorf("%s: x is %v, want %v", tc.name, got["x"], tc.wantX)
		}
		if tc.wantY != 0 && got["y"] != tc.wantY {
			t.Errorf("%s: y is %v, want %v", tc.name, got["y"], tc.wantY)
		}
	}
}

// 2. The guide states where a signature lands. A caller who reads only
// `pdf-go doc` must be able to answer that question without trying a create and
// opening the result, so the section names the default, the origin convention,
// the stacking, and the fact that nothing is auto-detected.
func TestGuideStatesSignaturePlacement(t *testing.T) {
	if !strings.Contains(guide, "SIGNATURE POSITION") {
		t.Fatal("the guide has no SIGNATURE POSITION section")
	}
	for _, want := range []string{
		"auto-detect",          // the thing callers assume that is not true
		"X=60 Y=60",            // the default, stated as a coordinate
		"LOWER-LEFT",           // the origin, the single most common mistake
		"--widget-page",        // a placement is reachable from the CLI
		"REFUSED create",       // a bad name is an error, not a silent fallback
		"220 x 80",             // the size of the box being placed
		"Only the FIRST party", // the field anchor's one asymmetry
		"FILLED document",      // the page is validated after the fill
	} {
		if !strings.Contains(guide, want) {
			t.Errorf("the placement section does not state %q", want)
		}
	}
}

// 3. The flags the section names exist, and their printed description says what
// they place. The description used to read "widget to lock the form to", which
// describes the form fields rather than the signature; a caller who believed it
// would omit the flag and get the default corner.
func TestCreateUsageDescribesPlacementFlags(t *testing.T) {
	code, out := runCLI(t, "envelope", "create", "--help")
	usage := string(out)
	if len(strings.TrimSpace(usage)) == 0 {
		t.Fatalf("envelope create --help printed nothing (code %d)", code)
	}
	for _, want := range []string{
		"-widget ",
		"-widget-page",
		"-widget-x",
		"-widget-y",
		"signature", // every one of them is about the signature
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("`envelope create --help` does not show %q:\n%s", want, usage)
		}
	}
	if strings.Contains(usage, "lock the form") {
		t.Error("--widget is described as locking the form; it places the signature")
	}
	// The guide's flag names and the parser's flag names are one list.
	for _, name := range []string{"widget", "widget-page", "widget-x", "widget-y"} {
		if !strings.Contains(guide, "--"+name) {
			t.Errorf("the guide does not mention --%s", name)
		}
	}
}

// 4. The skill document is what an agent follows step by step. It used to say
// only that `widget` is "an optional sibling of fill", which is true and
// useless: it does not say what happens when you leave it out.
func TestSkillDocExplainsPlacement(t *testing.T) {
	b, err := os.ReadFile("../../docs/skills/prepare-and-dispatch-signing.md")
	if err != nil {
		t.Skipf("skill document not readable: %v", err)
	}
	doc := string(b)
	for _, want := range []string{
		"auto-detection",
		"X=60, Y=60",
		"lower-left",
		`"field":"SigClient"`,
		"refuses the create",
		"--widget-x",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the skill document does not state %q", want)
		}
	}
}
