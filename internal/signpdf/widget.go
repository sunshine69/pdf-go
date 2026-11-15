package signpdf

import (
	"strings"

	pdflib "github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
)

// A signature can be anchored to a signature field the document already
// carries. This is how a 40-page contract gets its signatures on the signature
// page instead of on page 1: the drafter drops a signature field where it
// belongs, names it in the create request, and the service signs there.
//
// The lookup below reads the document the way a reader does — the page list in
// order, each page's annotations, each widget annotation pointing at its field
// dictionary — rather than walking AcroForm.Fields. Walking the fields gets you
// the field but not which page it lives on, and "which page" is the whole
// point. Walking from the page gives the page number for free and costs one
// pass over the pages a signature could plausibly need.

// fieldAnchor is where a signature field's widget sits.
type fieldAnchor struct {
	Page   int
	Rect   [4]float64
	HasAll bool // the annotation carried a usable /Rect
}

// findFieldWidget returns the page and rectangle of the widget annotation of the
// signature field called name, or ok=false when the document has no such field.
//
// The name is matched the way the fill layer matches it (internal/pdf):
// case-insensitively and ignoring spaces, against the field's fully qualified
// name — the /T partials of the field and its ancestors joined with periods —
// and also against its bare partial, so a template whose field is called
// "Signature" can be named as "Signature" even when it sits inside a
// "sig.1>-form" hierarchy.
//
// Signature fields normally have exactly one widget. Where a field has several,
// the first is used: a document that repeats one signature field across pages
// is asking to be signed on one of them, and the first is the least surprising
// reading.
func findFieldWidget(doc *pdfsign.Document, name string) (fieldAnchor, bool) {
	want := normaliseFieldName(name)
	if want == "" {
		return fieldAnchor{}, false
	}
	rdr := doc.Reader()
	if rdr == nil {
		return fieldAnchor{}, false
	}
	for page := 1; page <= rdr.NumPage(); page++ {
		annots := rdr.Page(page).V.Key("Annots")
		if annots.Kind() != pdflib.Array {
			continue
		}
		for i := 0; i < annots.Len(); i++ {
			ann := annots.Index(i)
			if ann.Kind() != pdflib.Dict {
				continue
			}
			if ann.Key("Subtype").Name() != "Widget" {
				continue
			}
			// The field dictionary may sit above the annotation, and the partial
			// name may sit above the field dictionary, so the name is assembled
			// up the chain rather than read off one dictionary.
			field := ann.Key("Parent")
			if field.Kind() != pdflib.Dict {
				continue
			}
			full, part := qualifiedName(field)
			if normaliseFieldName(full) != want && normaliseFieldName(part) != want {
				continue
			}
			a := fieldAnchor{Page: page}
			if r := annotRect(ann); r != [4]float64{} {
				a.Rect, a.HasAll = r, true
			}
			return a, true
		}
	}
	return fieldAnchor{}, false
}

// annotRect reads a widget annotation's /Rect. A widget with no usable rectangle
// still anchors a signature to its page — which is the fix for the common case
// — it just cannot say where on that page.
func annotRect(ann pdflib.Value) [4]float64 {
	v := ann.Key("Rect")
	if v.Kind() != pdflib.Array || v.Len() != 4 {
		return [4]float64{}
	}
	var r [4]float64
	for i := 0; i < 4; i++ {
		r[i] = v.Index(i).Float64()
	}
	if r[2] <= r[0] || r[3] <= r[1] {
		return [4]float64{}
	}
	return r
}

// qualifiedName returns a field's fully qualified name and its own partial
// name, walking up through parent field dictionaries. ISO 32000-1 12.7.3.2:
// the names are joined with periods. A parent may hold the name while its
// widget-bearing child carries none, and vice versa, so both are reported and
// the caller matches either.
func qualifiedName(field pdflib.Value) (full, partial string) {
	var parts []string
	seen := 0
	v := field
	for v.Kind() == pdflib.Dict && seen < 32 {
		t := v.Key("T")
		if t.Kind() == pdflib.String {
			if s := t.RawString(); s != "" {
				parts = append([]string{s}, parts...)
				if partial == "" {
					partial = s
				}
			}
		}
		parent := v.Key("Parent")
		// Only field dictionaries above this one contribute a name. The page is
		// a /Parent too, and its dictionary has no /T.
		if parent.Kind() != pdflib.Dict || parent.Key("Kids").Kind() != pdflib.Array {
			break
		}
		v = parent
		seen++
	}
	return strings.Join(parts, "."), partial
}

// normaliseFieldName is the forgiving comparison the fill layer uses for field
// names: case and spacing are decoration. Kept as a copy rather than an import
// because signpdf must not grow a dependency on the fill layer's document model.
func normaliseFieldName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}

// anchorWidget folds a field anchor into the widget the caller will sign with.
//
// The page is taken whenever the field has one. The coordinates are taken only
// when the caller did not name its own — an explicit X,Y is the more specific
// instruction — and only when the annotation actually declared a rectangle.
// Size stays the caller's: a signature is drawn 220x80 whatever the template
// asked for, and shrinking the box to a tall thin field would clip the printed
// name and date.
//
// A page is still clamped into the page's crop box by placement(), so an
// annotation drawn half off the printed area cannot put a signature off it.
func anchorWidget(w Widget, a fieldAnchor) Widget {
	if a.Page > 0 {
		w.Page = a.Page
	}
	if !a.HasAll || w.X != 0 || w.Y != 0 {
		return w
	}
	w.X, w.Y = a.Rect[0], a.Rect[1]
	return w
}
