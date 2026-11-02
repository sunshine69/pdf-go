// Package schema defines the JSON contract shared by the `extract` and
// `fill` sub-commands.
//
// `pdf-go extract` produces a FormSchema describing every form field of a
// document, keyed by its fully qualified PDF name. `pdf-go fill` consumes
// the very same shape, with values filled in, so the metadata can round-trip:
//
//	pdf-go extract in.pdf  > form.json   # inspect
//	<edit form.json with values>
//	pdf-go fill in.pdf form.json out.pdf
//
// The shape is deliberately flat and self-describing so it can be produced
// and consumed by an LLM without extra tooling: every field carries its type,
// its allowed values (for choices), and its geometry.
package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Field types reported by extract. They drive what `fill` accepts as a value.
const (
	TypeText       = "text"
	TypeCheckbox   = "checkbox"
	TypeRadio      = "radio"
	TypePushButton = "pushbutton"
	TypeChoice     = "choice" // scrollable list box
	TypeCombo      = "combo"  // drop-down combo box
	TypeSignature  = "signature"
	TypeUnknown    = "unknown"
)

// FormSchema is the document-level metadata emitted by `extract` and read by
// `fill`.
type FormSchema struct {
	// Source is the PDF the schema was extracted from (informational).
	Source string `json:"source,omitempty"`

	// NeedsAppearances is true when the original file asked viewers to
	// (re)build field appearances. `fill` always bakes appearances in, so
	// this is informational only.
	NeedsAppearances bool `json:"needsAppearances,omitempty"`

	// FieldCount is a convenience total, always == len(Fields).
	FieldCount int `json:"fieldCount"`

	// Pages carries page geometry, useful when positioning generated art.
	Pages []PageInfo `json:"pages"`

	// Fields lists every form field, in document order.
	Fields []Field `json:"fields"`

	// Warnings reports non fatal problems found while reading the form.
	Warnings []string `json:"warnings,omitempty"`
}

// PageInfo describes one page of the document in PDF user space units
// (1/72 inch, origin bottom-left).
type PageInfo struct {
	Index  int      `json:"index"`
	Width  float64  `json:"width"`
	Height float64  `json:"height"`
	Rotate float64  `json:"rotate,omitempty"`
	Fields []string `json:"fields,omitempty"` // fully qualified names drawn on this page
}

// Field is one form field.
//
// The "value to fill" depends on Type:
//
//   - text                              -> string
//   - checkbox, radio                   -> one of Options ("" or "Off" clears)
//   - choice, combo                     -> one of Options (string or []string)
//   - pushbutton, signature             -> not fillable, skipped
type Field struct {
	// Name is the fully qualified field name, e.g. "form[0].addr.city".
	// This is the key `fill` matches values on.
	Name string `json:"name"`

	// Type is one of the Type* constants above.
	Type string `json:"type"`

	// Value is the current value read from the PDF (empty when unset).
	// For choices this is a list of the current selections.
	Value string `json:"value,omitempty"`

	// Values is the current selection for multi-select choice fields.
	Values []string `json:"values,omitempty"`

	// Options lists the legal values for choice fields and the on-states of
	// checkbox/radio fields (the first entry of a checkbox is usually its
	// on-state, the second "Off").
	Options []string `json:"options,omitempty"`

	// Flags lists the PDF field flags (ReadOnly, Required, Multiline, ...).
	Flags []string `json:"flags,omitempty"`

	// MaxLen is the maximum number of characters (0 = unlimited).
	MaxLen int `json:"maxLen,omitempty"`

	// DefaultAppearance is the PDF /DA string, e.g. "/Helv 9 Tf 0 g".
	DefaultAppearance string `json:"defaultAppearance,omitempty"`

	// Page is the 1-based page index of the widget, 0 when unknown.
	Page int `json:"page,omitempty"`

	// Rect is the widget rectangle [x0 y0 x1 y1] in PDF units.
	Rect []float64 `json:"rect,omitempty"`

	// States lists the appearance keys defined by the widget, i.e. the
	// values that visibly toggle a checkbox/radio (e.g. ["Yes","Off"]).
	States []string `json:"states,omitempty"`

	// TextAlign is the PDF /Q entry: 0 left, 1 centered, 2 right.
	TextAlign int `json:"textAlign,omitempty"`

	// HasWidget is false when the field has no visible widget. `fill` will
	// create one in that case, sized from the value being written.
	HasWidget bool `json:"hasWidget"`

	// Note is a free-form hint carried through from a previous fill.
	Note string `json:"note,omitempty"`
}

// HasFlag reports whether a PDF field flag is set, e.g. "readOnly",
// "multiline", "combo", "radio".
func (f Field) HasFlag(name string) bool {
	name = strings.ToLower(name)
	for _, fl := range f.Flags {
		if strings.ToLower(fl) == name {
			return true
		}
	}
	return false
}

// SetValues stores field values keyed by field name.
//
// Accepted value shapes:
//
//	string            -> text, combo, single-select choice, checkbox/radio on-state
//	bool              -> checkbox/radio (true = first on-state, false = "Off")

// Paint is text drawn directly onto a page: headers, reference numbers,
// dates, captions, redactions labels. Unlike a form field it is page content,
// so it cannot be edited or cleared by a viewer.
type Paint struct {
	// ID is a caller-supplied label, echoed back in the report.
	ID string `json:"id,omitempty"`

	// Text is the content. "\n" starts a new line; a field with the
	// multiline flag wraps on its own.
	Text string `json:"text"`

	// Placement follows the same rules as Logo: Field, Rect, or
	// Page+Box+Position.
	Field    string    `json:"field,omitempty"`
	Rect     []float64 `json:"rect,omitempty"`
	Page     int       `json:"page,omitempty"`
	Box      string    `json:"box,omitempty"`
	Position string    `json:"position,omitempty"`
	Margin   float64   `json:"margin,omitempty"`
	Offset   []float64 `json:"offset,omitempty"`

	// Font is a standard font name: Helvetica, Helvetica-Bold,
	// Helvetica-Oblique, Times-Roman, Times-Bold, Times-Italic, Courier,
	// Courier-Bold, Symbol, ZapfDingbats (or their PDF short names).
	Font string `json:"font,omitempty"`

	// Size is in points; 0 means 12.
	Size float64 `json:"size,omitempty"`

	// Color is "#RRGGBB" or a name (black, white, red, ...). Default black.
	Color string `json:"color,omitempty"`

	// Align is "left" (default), "center" or "right" inside Rect/Box.
	Align string `json:"align,omitempty"`

	// Leading is the line distance; 0 means 1.2 * Size.
	Leading float64 `json:"leading,omitempty"`

	// Opacity in [0,1]. 1 is opaque.
	Opacity float64 `json:"opacity,omitempty"`

	// Rotate is degrees, counter-clockwise.
	Rotate float64 `json:"rotate,omitempty"`
}

// []string          -> multi-select choice
// map[string]any    -> nested, {"value": ...} and {"note": ...} are honoured
type SetValues map[string]any

// FillSpec is the JSON document consumed by `fill`.
type FillSpec struct {
	// Source overrides the input PDF path when given.
	Source string `json:"source,omitempty"`

	// Values maps fully qualified field names to their new value.
	Values SetValues `json:"values"`

	// Logos lists graphic elements to stamp onto pages: bar codes, QR
	// codes, logos, signatures, ...
	// Logos are drawn as plain page content and are NOT interactive: the
	// matching form field (if any) is only used to find the position.
	Logos []Logo `json:"logos,omitempty"`

	// Paints lists text drawn directly on pages: headers, reference
	// numbers, dates, captions. Like logos this is page content, not a
	// form field, so it is baked into the page.
	Paints []Paint `json:"paints,omitempty"`

	// LockForm marks every field ReadOnly in the output.
	LockForm bool `json:"lockForm,omitempty"`
}

// Logo is a raster or vector graphic stamped on a page.
type Logo struct {
	// ID is a caller-supplied label, echoed back in the report.
	ID string `json:"id,omitempty"`

	// Image is the artwork: a PNG/JPEG path (PNG strongly preferred) or
	// raw base64 in ImageData.
	Image     string `json:"image,omitempty"`
	ImageData string `json:"imageData,omitempty"`

	// Target selects where to draw. In priority order:
	//   Field  - place inside the rect of that form field (e.g. a
	//            signature field, or a "QR code" field)
	//   Rect   - explicit [x0 y0 x1 y1] in PDF units
	//   Page+Box+Position - anchor inside a page box
	// When Field refers to a field that has no widget, a widget is
	// created so the placement is visible in every viewer.
	Field string `json:"field,omitempty"`

	// Rect overrides the placement rectangle.
	Rect []float64 `json:"rect,omitempty"`

	// Page is 1-based; defaults to page 1 (or the page of Field).
	Page int `json:"page,omitempty"`

	// Box is the anchor box inside the page: "media" (default), "crop",
	// "trim", "bleed", "art", "content", "header", "footer".
	// Pages are typically built with a large media box and a smaller
	// crop box; stamping inside the crop box keeps art on the printed
	// area, inside the header/footer box places it in that band.
	Box string `json:"box,omitempty"`

	// Position anchors the logo inside Box, e.g. "bottom-right",
	// "bottom left", "center", "top", "header-left".
	Position string `json:"position,omitempty"`

	// Width and Height are in PDF units; 0 keeps the natural size and
	// preserves the image aspect ratio.
	Width  float64 `json:"width,omitempty"`
	Height float64 `json:"height,omitempty"`

	// Margin is padding between the logo and the Box edges.
	Margin float64 `json:"margin,omitempty"`

	// Offset shifts the logo from its anchor (x,y); positive x is right,
	// positive y is up.
	Offset []float64 `json:"offset,omitempty"`

	// Opacity in [0,1].
	Opacity float64 `json:"opacity,omitempty"`

	// Rotate is a clockwise rotation in degrees.
	Rotate float64 `json:"rotate,omitempty"`

	// Note is a free-form label, echoed back in the report.
	Note string `json:"note,omitempty"`
}

// ParseFillSpec decodes the JSON handed to `fill`. Two shapes are accepted so
// the metadata produced by `extract` round-trips without translation:
//
//	{"values":{"addr.city":"Paris"}}                  - a bare mapping
//	{"fields":[{"name":"addr.city","value":"Paris"}]} - the extract document
//
// In the second form every entry with a "value" (or "values") key becomes an
// assignment; entries marked "missing" are ignored. "logos" and "lockForm"
// are honoured by both forms.
func ParseFillSpec(b []byte) (FillSpec, error) {
	var spec FillSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		return spec, fmt.Errorf("parse spec: %w", err)
	}
	var doc struct {
		Fields []map[string]json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return spec, fmt.Errorf("parse spec: %w", err)
	}
	if spec.Values == nil {
		spec.Values = SetValues{}
	}
	for _, entry := range doc.Fields {
		var name string
		if err := json.Unmarshal(entry["name"], &name); err != nil || name == "" {
			continue
		}
		if skipped := entry["missing"]; skipped != nil {
			var flag bool
			if json.Unmarshal(skipped, &flag) == nil && flag {
				continue
			}
		}
		// A multi-select list keeps its full selection.
		if raw, ok := entry["values"]; ok {
			spec.Values[name] = decodeJSON(raw)
			continue
		}
		if raw, ok := entry["value"]; ok {
			spec.Values[name] = decodeJSON(raw)
		}
	}
	return spec, nil
}

// decodeJSON turns a JSON value into the Go shape the fillers accept:
// string, bool, float64 or []string.
func decodeJSON(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	switch typed := v.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, s)
			} else {
				out = append(out, fmt.Sprint(item))
			}
		}
		return out
	}
	return v
}

// PageGeometry is the geometry of one page: the boxes a graphic element can
// be positioned against. Produced by `pdf-go pages`.
type PageGeometry struct {
	Index  int                  `json:"index"`
	Width  float64              `json:"width"`
	Height float64              `json:"height"`
	Rotate float64              `json:"rotate,omitempty"`
	Boxes  map[string][]float64 `json:"boxes"`

	// Annotations is the number of annotations registered on the page,
	// i.e. how many widgets the page carries.
	Annotations int `json:"annotations,omitempty"`
}

// ReadFormSchema reads the JSON written by `pdf-go extract`. Passing that
// file back to `fill` needs no translation: the schema is the fill input.
func ReadFormSchema(path string) (FormSchema, error) {
	var s FormSchema
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("parse schema %s: %w", path, err)
	}
	return s, nil
}
