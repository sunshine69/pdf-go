package pdf

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/benoitkugler/pdf/fonts"
	"github.com/benoitkugler/pdf/fonts/standardfonts"
	"github.com/benoitkugler/pdf/formfill"
	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/schema"
)

// FieldTarget is what a caller needs to know about a field before filling it.
type FieldTarget struct {
	Name      string
	Type      string
	HasWidget bool
	Rect      []float64 // current widget rectangle, empty when there is none
	Page      int
}

// IndexFields returns every field of the document, keyed by fully qualified
// name (sorted).
func IndexFields(doc *model.Document) map[string]model.FormFieldInherited {
	return doc.Catalog.AcroForm.Flatten()
}

// Targets lists fillable fields together with their geometry.
func Targets(doc *model.Document) map[string]FieldTarget {
	flat := IndexFields(doc)
	annotPage := fieldPage(doc)
	out := make(map[string]FieldTarget, len(flat))
	for name, fi := range flat {
		t := FieldTarget{Name: name}
		if fi.Field != nil {
			t.HasWidget = len(fi.Field.Widgets) > 0
			if len(fi.Field.Widgets) > 0 {
				if w := fi.Field.Widgets[0]; w.AnnotationDict != nil {
					t.Rect = RectSlice(w.AnnotationDict.Rect)
					t.Page = annotPage[w.AnnotationDict]
				}
			}
		}
		switch fi.Merged.FT.(type) {
		case model.FormFieldText:
			t.Type = schema.TypeText
		case model.FormFieldButton:
			switch {
			case fi.Merged.Ff&model.Pushbutton != 0:
				t.Type = schema.TypePushButton
			case fi.Merged.Ff&model.Radio != 0:
				t.Type = schema.TypeRadio
			default:
				t.Type = schema.TypeCheckbox
			}
		case model.FormFieldChoice:
			t.Type = schema.TypeChoice
			if fi.Merged.Ff&model.Combo != 0 {
				t.Type = schema.TypeCombo
			}
		case model.FormFieldSignature:
			t.Type = schema.TypeSignature
		default:
			t.Type = schema.TypeUnknown
		}
		out[name] = t
	}
	return out
}

// LookupTarget finds a field by exact name, tolerating whitespace and case so
// that a hand-written spec does not have to reproduce "form[0].addr.city"
// byte for byte.
func LookupTarget(targets map[string]FieldTarget, name string) (FieldTarget, string, bool) {
	if t, ok := targets[name]; ok {
		return t, name, true
	}
	want := NormaliseName(name)
	var candidates []string
	for k := range targets {
		if NormaliseName(k) == want {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 1 {
		return targets[candidates[0]], candidates[0], true
	}
	if len(candidates) > 1 {
		sort.Strings(candidates)
		return targets[candidates[0]], candidates[0], true
	}
	return FieldTarget{}, "", false
}

// FieldNames returns the sorted list of every field name.
func FieldNames(targets map[string]FieldTarget) []string {
	out := make([]string, 0, len(targets))
	for k := range targets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	stdFontMu    sync.Mutex
	stdFontCache = map[string]*model.FontDict{}
)

// stdFont returns a canonical font dictionary for one of the standard 14
// fonts. The returned pointer is shared, so a document that stamps many
// labels reuses a single font object.
func stdFont(name string) *model.FontDict {
	stdFontMu.Lock()
	defer stdFontMu.Unlock()
	if f, ok := stdFontCache[name]; ok {
		return f
	}
	var metrics standardfonts.Metrics
	switch strings.ToLower(name) {
	case "helvetica", "helv":
		metrics = standardfonts.Helvetica
	case "helvetica-bold", "hebo":
		metrics = standardfonts.Helvetica_Bold
	case "helvetica-oblique", "hello":
		metrics = standardfonts.Helvetica_Oblique
	case "helvetica-boldoblique", "heboit":
		metrics = standardfonts.Helvetica_BoldOblique
	case "times", "times-roman", "tiro":
		metrics = standardfonts.Times_Roman
	case "times-bold", "tib":
		metrics = standardfonts.Times_Bold
	case "courier", "cour":
		metrics = standardfonts.Courier
	case "courier-bold", "cob":
		metrics = standardfonts.Courier_Bold
	case "symbol", "symbo":
		metrics = standardfonts.Symbol
	case "zapfdingbats", "zadb":
		metrics = standardfonts.ZapfDingbats
	default:
		metrics = standardfonts.Helvetica
	}
	f := &model.FontDict{Subtype: metrics.WesternType1Font()}
	stdFontCache[name] = f
	return f
}

// ensureFontResources makes sure a page can host text drawn with one of the
// standard fonts. It only adds entries, keeping every inherited resource
// untouched.
func ensureFontResources(page *model.PageObject, names ...string) *model.ResourcesDict {
	if page.Resources == nil {
		res := model.NewResourcesDict()
		page.Resources = &res
	}
	res := page.Resources
	if res.Font == nil {
		res.Font = map[model.ObjName]*model.FontDict{}
	}
	for _, n := range names {
		res.Font[model.ObjName(n)] = stdFont(n)
	}
	return res
}

// FieldValue converts a schema value into the value type expected by the PDF
// field, using the field type.
func FieldValue(t schema.Field, raw any) (formfill.FDFValue, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case bool:
		if t.Type == schema.TypeCheckbox || t.Type == schema.TypeRadio {
			return formfill.FDFName(checkboxOnState(t)), nil
		}
		if v {
			return formfill.FDFText("true"), nil
		}
		return formfill.FDFText("false"), nil
	case string:
		return textValue(t, v)
	case float64:
		return textValue(t, FormatNumber(v))
	case int:
		return textValue(t, fmt.Sprintf("%d", v))
	case []any:
		return listValue(t, v)
	case []string:
		return listValue(t, anySlice(v))
	default:
		return textValue(t, fmt.Sprintf("%v", v))
	}
}

func textValue(t schema.Field, s string) (formfill.FDFValue, error) {
	switch t.Type {
	case schema.TypeText:
		// A /MaxLen field is a fixed-size box: more characters than it allows
		// is a data loss no viewer can display, so clip to the field width.
		if t.MaxLen > 0 {
			s = TruncateRunes(s, t.MaxLen)
		}
		return formfill.FDFText(s), nil
	case schema.TypeCheckbox, schema.TypeRadio:
		if s == "" || strings.EqualFold(s, "off") || strings.EqualFold(s, "false") || strings.EqualFold(s, "no") {
			return formfill.FDFName("Off"), nil
		}
		if len(t.Options) > 0 {
			for _, o := range t.Options {
				if strings.EqualFold(o, s) {
					return formfill.FDFName(o), nil
				}
			}
			return formfill.FDFName(s), nil
		}
		return formfill.FDFName(s), nil
	case schema.TypeChoice, schema.TypeCombo:
		return formfill.FDFText(s), nil
	case schema.TypeSignature, schema.TypePushButton:
		return nil, nil
	default:
		return formfill.FDFText(s), nil
	}
}

func listValue(t schema.Field, vs []any) (formfill.FDFValue, error) {
	switch t.Type {
	case schema.TypeChoice:
		out := make([]string, 0, len(vs))
		for _, v := range vs {
			out = append(out, fmt.Sprintf("%v", v))
		}
		return formfill.FDFChoices(out), nil
	case schema.TypeCheckbox, schema.TypeRadio:
		if len(vs) == 0 {
			return formfill.FDFName("Off"), nil
		}
		return formfill.FDFName(fmt.Sprintf("%v", vs[0])), nil
	default:
		parts := make([]string, 0, len(vs))
		for _, v := range vs {
			parts = append(parts, fmt.Sprintf("%v", v))
		}
		return formfill.FDFText(strings.Join(parts, ", ")), nil
	}
}

func anySlice(vs []string) []any {
	out := make([]any, len(vs))
	for i, v := range vs {
		out[i] = v
	}
	return out
}

func checkboxOnState(t schema.Field) string {
	for _, o := range t.Options {
		if o != "Off" && o != "No" && o != "" {
			return o
		}
	}
	return "Yes"
}

// FillDoc writes the requested values into the document and bakes in the
// appearance streams. Fields that have no widget (common in form templates
// produced by layout tools) get a widget sized and positioned from the value
// being written, so the result is visible in every viewer.
//
// Returns the list of names actually applied.
func FillDoc(doc *model.Document, schemaFields []schema.Field, values map[string]any, lockForm bool) ([]string, []report.Note, error) {
	byName := make(map[string]schema.Field, len(schemaFields))
	for _, f := range schemaFields {
		byName[f.Name] = f
	}
	targets := Targets(doc)

	var (
		fdf     formfill.FDFDict
		applied []string
		notes   []report.Note
	)
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, key := range names {
		raw := values[key]
		if m, ok := raw.(map[string]any); ok {
			if v, has := m["value"]; has {
				raw = v
			}
		}
		t, resolved, found := LookupTarget(targets, key)
		if !found {
			return applied, notes, fmt.Errorf("unknown field %q; run extract to list the available fields", key)
		}
		schemaField, ok := byName[resolved]
		if !ok {
			schemaField = schema.Field{Name: resolved, Type: t.Type}
		}
		if note := fitNote(schemaField, raw); note != "" {
			notes = append(notes, report.Note{Name: resolved, Note: note, Value: fmt.Sprint(raw)})
		}
		v, err := FieldValue(schemaField, raw)
		if err != nil {
			return applied, notes, fmt.Errorf("field %q: %w", resolved, err)
		}
		if v == nil {
			notes = append(notes, report.Note{
				Name: resolved,
				Note: fmt.Sprintf("%s fields cannot be filled with a value; use a logo to stamp artwork there", schemaField.Type),
			})
			continue
		}
		fdf.Fields = append(fdf.Fields, formfill.FDFField{
			Values: formfill.Values{V: v},
			T:      resolved,
		})
		applied = append(applied, resolved)
	}

	if err := formfill.FillForm(doc, fdf, lockForm); err != nil {
		return applied, notes, fmt.Errorf("fill: %w", err)
	}

	// The library resolves the DA font from AcroForm.DR, which most
	// producers leave empty, so it silently falls back to Helvetica and the
	// resulting appearance stream references a font name the viewer may not
	// be able to resolve. Repair the appearances with fonts that are
	// registered in the page resources.
	pages := doc.Catalog.Pages.Flatten()
	flat := IndexFields(doc)
	annotPage := fieldPage(doc)
	for _, name := range applied {
		fi, ok := flat[name]
		if !ok || fi.Field == nil {
			continue
		}
		schemaField := byName[name]
		value := renderValue(flat, name)
		EnsureFieldAppearances(pages, annotPage, fi, schemaField, value)
	}

	doc.Catalog.AcroForm.NeedAppearances = false
	return applied, notes, nil
}

func renderValue(flat map[string]model.FormFieldInherited, name string) string {
	fi, ok := flat[name]
	if !ok {
		return ""
	}
	switch ft := fi.Merged.FT.(type) {
	case model.FormFieldText:
		return ft.V
	case model.FormFieldButton:
		return string(ft.V)
	case model.FormFieldChoice:
		if len(ft.V) > 0 {
			return strings.Join(ft.V, ", ")
		}
	}
	return ""
}

// FormatNumber prints a float the way a human typed it (no trailing zeros).
func FormatNumber(v float64) string {
	s := fmt.Sprintf("%.6f", v)
	s = strings.TrimRight(s, "0")
	return strings.TrimRight(s, ".")
}

// keep the font import used (fonts.BuildFont is needed to measure text)
var _ = fonts.BuildFont

// AnnotPages maps every page annotation to its 1-based page index: the link
// between a field and the page it is drawn on.
func AnnotPages(doc *model.Document) map[*model.AnnotationDict]int { return fieldPage(doc) }

// fitNote reports a warning about a value that is accepted but may not render
// as the caller expects. It never fails the run: it exists so a program can
// see *why* a value came out differently.
func fitNote(f schema.Field, raw any) string {
	text, isText := raw.(string)
	switch f.Type {
	case schema.TypeText:
		if !isText {
			return ""
		}
		if f.MaxLen > 0 && len([]rune(text)) > f.MaxLen {
			return fmt.Sprintf("value is %d characters but the field allows %d; it will be clipped to %q",
				len([]rune(text)), f.MaxLen, TruncateRunes(text, f.MaxLen))
		}
		if !f.HasFlag("multiline") && (strings.Contains(text, "\n") || strings.Contains(text, "\r")) {
			return "value contains line breaks but the field is single-line; it is printed on one line"
		}
		if bad := unencodable(f, text); bad != "" {
			return fmt.Sprintf("the field font cannot draw %s; those characters are written as '.'", bad)
		}
		if f.Rect != nil {
			w := f.Rect[2] - f.Rect[0]
			if w > 0 && estWidth(f, text) > w+2 {
				return fmt.Sprintf("value is wider (%.0f pt) than the field (%.0f pt); it will be scaled down to fit",
					estWidth(f, text), w)
			}
		}
	case schema.TypeCheckbox, schema.TypeRadio:
		if !isText {
			return ""
		}
		if text == "" || isOffWord(text) {
			return ""
		}
		if len(f.States) > 0 && !containsFold(f.States, text) {
			return fmt.Sprintf("value %q is not one of the check marks defined by the document (%s); a generic tick is drawn instead",
				text, strings.Join(f.States, ", "))
		}
	case schema.TypeChoice, schema.TypeCombo:
		if !isText {
			return ""
		}
		if len(f.Options) > 0 && !containsFold(f.Options, text) {
			return fmt.Sprintf("value %q is not in the list of allowed values (%s)", text, strings.Join(f.Options, ", "))
		}
	}
	return ""
}

func isOffWord(s string) bool {
	return strings.EqualFold(s, "off") || strings.EqualFold(s, "false") || strings.EqualFold(s, "no")
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// estWidth measures a string in points using the font named by /DA.
func estWidth(f schema.Field, text string) float64 {
	da := ParseDA(f.DefaultAppearance)
	bf, err := builtFont(stdFont(da.font))
	if err != nil {
		return 0
	}
	size := da.size
	if size <= 0 {
		size = 12
	}
	var w Fl
	for _, r := range text {
		w += bf.GetWidth(r, size)
	}
	return float64(w)
}

// TruncateRunes clips s to at most n runes.
func TruncateRunes(s string, n int) string {
	if n <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// unencodable lists the distinct characters of text that the font named by the
// field /DA string cannot draw. The library maps them to '.' silently; we
// report them instead, because a name written as "J.D. SM.TH" is a data
// corruption the caller has to see.
func unencodable(f schema.Field, text string) string {
	da := ParseDA(f.DefaultAppearance)
	bf, err := builtFont(stdFont(da.font))
	if err != nil {
		return ""
	}
	var missing []string
	seen := map[rune]bool{}
	for _, r := range text {
		if r == '\n' || r == '\r' || r == '\t' || seen[r] {
			continue
		}
		seen[r] = true
		// A supported rune has a positive width; the standard fonts report 0
		// for anything outside their encoding.
		if bf.GetWidth(r, 10) == 0 {
			missing = append(missing, fmt.Sprintf("%q", r))
		}
	}
	if len(missing) == 0 {
		return ""
	}
	if len(missing) > 6 {
		missing = missing[:6]
	}
	return strings.Join(missing, ", ")
}
