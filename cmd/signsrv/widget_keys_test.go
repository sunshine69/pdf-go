package main

// The widget object's JSON keys are pinned by the decoder, not by a struct tag:
// signflow.Widget has no tags, so the accepted spelling is the Go field name
// matched case-insensitively by encoding/json. That is a forgiving contract, and
// a forgiving contract is easy to break by accident — adding a tag to one field
// silently stops the documented lowercase key from binding, and the only
// symptom is a signature in the default corner on a create that answered 201.
//
// The skill document and `pdf-go doc` both tell callers to send
// {"field":…,"page":…,"x":…,"y":…}. This test sends exactly that.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signflow"
)

func TestCreateWidgetKeysOverHTTP(t *testing.T) {
	cfg := testConfig(t)
	ts, store := envelopeServer(t, cfg)
	access := accessOf(t, ts)

	// The spec is built by hand rather than with createFields, which already
	// carries a widget: what is under test is the exact key set the documents
	// publish, including x, which no existing test sends.
	name := firstTextField(t, sample1(t))
	spec := `{"fill":{"values":{"` + name + `":"filed"}},` +
		`"widget":{"field":"","page":1,"x":120,"y":600}}`

	code, out := createRequest(t, ts, access, sample1(t), map[string]string{
		"title":      "Placement is stored, not guessed",
		"expires_in": "48h",
		"parties":    `[{"email":"ann@example.test","name":"Ann","order":1}]`,
		"spec":       spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /api/v1/envelopes = %d, want 201: %v", code, out)
	}
	env, _ := out["envelope"].(map[string]any)
	id, _ := env["id"].(string)
	if id == "" {
		t.Fatalf("no envelope id: %v", out)
	}

	env2, err := store.GetEnvelope(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if env2.WidgetPage != 1 {
		t.Errorf("stored page = %d, want 1: the key \"page\" did not bind", env2.WidgetPage)
	}
	if env2.WidgetX != 120 {
		t.Errorf("stored x = %v, want 120: the key \"x\" did not bind", env2.WidgetX)
	}
	if env2.WidgetY != 600 {
		t.Errorf("stored y = %v, want 600: the key \"y\" did not bind", env2.WidgetY)
	}

	// A named field survives the same path, which is the case with the most
	// riding on it: an unrecognised name is refused outright, and a recognised
	// one has to reach the batch to be anchored on.
	code2, out2 := createRequest(t, ts, access, sample1(t), map[string]string{
		"title":      "Field anchored",
		"expires_in": "48h",
		"parties":    `[{"email":"bo@example.test","name":"Bo","order":1}]`,
		"spec": `{"fill":{"values":{"` + name +
			`":"anchored"}},"widget":{"field":"` + name + `"}}`,
	})
	if code2 != http.StatusCreated {
		t.Fatalf("create anchored on a real field = %d, want 201: %v", code2, out2)
	}
	envB, _ := out2["envelope"].(map[string]any)
	idB, _ := envB["id"].(string)
	envB2, err := store.GetEnvelope(context.Background(), idB)
	if err != nil {
		t.Fatal(err)
	}
	if envB2.WidgetField != name {
		t.Errorf("stored field = %q, want %q: the key \"field\" did not bind", envB2.WidgetField, name)
	}

	// A page the document does not have is a refusal, not a shrug. This is the
	// behaviour the guide advertises with the words "REFUSED create".
	code3, out3 := createRequest(t, ts, access, sample1(t), map[string]string{
		"title":      "Page out of range",
		"expires_in": "48h",
		"parties":    `[{"email":"cy@example.test","name":"Cy","order":1}]`,
		"spec":       `{"fill":{"values":{"` + name + `":"paged"}},"widget":{"page":9999}}`,
	})
	if code3 == http.StatusCreated {
		t.Fatalf("create accepted page 9999: %v", out3)
	}
	if body, err := json.Marshal(out3); err == nil && !strings.Contains(string(body), "widget.page") {
		t.Errorf("the refusal does not blame widget.page: %s", body)
	}

	// The decoder's tolerance is the reason the keys can be lowercase at all.
	// If a json tag is ever added to signflow.Widget this stops being true, and
	// the documents have to change with it — so it is asserted, not assumed.
	raw := []byte(`{"Field":"Upper","page":2,"X":10,"y":20}`)
	var w signflow.Widget
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Field != "Upper" || w.Page != 2 || w.X != 10 || w.Y != 20 {
		t.Errorf("mixed-case keys bound to %+v; signflow.Widget likely grew json tags,"+
			" and the documented lowercase keys must be re-checked", w)
	}
}
