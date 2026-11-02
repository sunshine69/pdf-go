package pdf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/benoitkugler/pdf/model"
	"github.com/benoitkugler/pdf/reader"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// Load parses a PDF into the library document model.
func Load(path string, password string) (*model.Document, *model.Encrypt, error) {
	doc, enc, err := reader.ParsePDFFile(path, reader.Options{UserPassword: password})
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Pages are addressed by index, so flatten the tree once.
	_ = doc.Catalog.Pages.Flatten()
	return &doc, enc, nil
}

// commonFlagNames are the flags shared by every field type.
var commonFlagNames = []struct {
	flag model.FormFlag
	name string
}{
	{model.ReadOnly, "readOnly"},
	{model.Required, "required"},
	{model.NoExport, "noExport"},
}

// textFlagNames / buttonFlagNames / choiceFlagNames are type specific.
var (
	textFlagNames = []struct {
		flag model.FormFlag
		name string
	}{
		{model.Multiline, "multiline"},
		{model.Password, "password"},
		{model.DoNotSpellCheck, "doNotSpellCheck"},
		{model.DoNotScroll, "doNotScroll"},
		{model.Comb, "comb"},
		{model.RichText, "richText"},
	}
	buttonFlagNames = []struct {
		flag model.FormFlag
		name string
	}{
		{model.NoToggleToOff, "noToggleToOff"},
		{model.Radio, "radio"},
		{model.Pushbutton, "pushButton"},
		{model.RadiosInUnison, "radiosInUnison"},
	}
	choiceFlagNames = []struct {
		flag model.FormFlag
		name string
	}{
		{model.Combo, "combo"},
		{model.Edit, "editable"},
		{model.Sort, "sorted"},
		{model.FileSelect, "fileSelect"},
		{model.MultiSelect, "multiSelect"},
		{model.CommitOnSelChange, "commitOnSelChange"},
	}
)

func flagNames(ff model.FormFlag, typ string) []string {
	out := []string{}
	for _, c := range commonFlagNames {
		if ff&c.flag != 0 {
			out = append(out, c.name)
		}
	}
	var specific []struct {
		flag model.FormFlag
		name string
	}
	switch typ {
	case schema.TypeText:
		specific = textFlagNames
	case schema.TypeCheckbox, schema.TypeRadio, schema.TypePushButton:
		specific = buttonFlagNames
	case schema.TypeChoice, schema.TypeCombo:
		specific = choiceFlagNames
	}
	for _, c := range specific {
		if ff&c.flag != 0 {
			out = append(out, c.name)
		}
	}
	return out
}

// fieldPage indexes fully qualified field names by page number (1-based),
// using the widget annotations registered in each page.
func fieldPage(doc *model.Document) map[*model.AnnotationDict]int {
	out := map[*model.AnnotationDict]int{}
	for i, page := range doc.Catalog.Pages.Flatten() {
		for _, annot := range page.Annots {
			if annot != nil {
				out[annot] = i + 1
			}
		}
	}
	return out
}

// Extract reads the AcroForm of a document and returns its metadata.
//
// Fields are sorted by name so the output is stable across runs, which
// matters when a schema is stored, diffed, and fed back to `fill`.
func Extract(path string, password string) (schema.FormSchema, error) {
	var out schema.FormSchema

	doc, _, err := Load(path, password)
	if err != nil {
		return out, err
	}
	out.Source = path
	out.NeedsAppearances = doc.Catalog.AcroForm.NeedAppearances

	acro := doc.Catalog.AcroForm
	if len(acro.Fields) == 0 {
		out.Warnings = append(out.Warnings,
			"document has no AcroForm fields")
	}

	annotPage := fieldPage(doc)
	pages := doc.Catalog.Pages.Flatten()

	byName := acro.Flatten()

	pageFields := make(map[int][]string, len(pages))
	out.Fields = make([]schema.Field, 0, len(byName))
	for name, fi := range byName {
		f := schema.Field{Name: name}
		if fi.Field != nil {
			f.HasWidget = len(fi.Field.Widgets) > 0
		}
		f.DefaultAppearance = fi.Merged.DA
		f.MaxLen = textMaxLen(fi.Merged.FT)

		switch ft := fi.Merged.FT.(type) {
		case model.FormFieldText:
			f.Type = schema.TypeText
			f.Value = ft.V
		case model.FormFieldButton:
			switch {
			case fi.Merged.Ff&model.Pushbutton != 0:
				f.Type = schema.TypePushButton
			case fi.Merged.Ff&model.Radio != 0:
				f.Type = schema.TypeRadio
			default:
				f.Type = schema.TypeCheckbox
			}
			f.Value = string(ft.V)
			f.Options = append(f.Options, ft.Opt...)
		case model.FormFieldChoice:
			f.Type = schema.TypeChoice
			if fi.Merged.Ff&model.Combo != 0 {
				f.Type = schema.TypeCombo
			}
			if len(ft.V) > 0 {
				f.Value = ft.V[0]
				f.Values = ft.V
			}
			for _, o := range ft.Opt {
				// The export value is what a viewer reports as the field
				// value, so it is the value callers must send back.
				if o.Export != "" {
					f.Options = append(f.Options, o.Export)
				} else {
					f.Options = append(f.Options, o.Name)
				}
			}
		case model.FormFieldSignature:
			f.Type = schema.TypeSignature
		default:
			f.Type = schema.TypeUnknown
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("field %q has an unresolved type; it is inherited from its parent", name))
		}
		f.Flags = flagNames(fi.Merged.Ff, f.Type)

		// Geometry: take the first widget of the field.
		if fi.Field != nil && len(fi.Field.Widgets) > 0 {
			w := fi.Field.Widgets[0]
			if w.AnnotationDict != nil {
				r := w.AnnotationDict.Rect
				f.Rect = []float64{f64(r.Llx), f64(r.Lly), f64(r.Urx), f64(r.Ury)}
				f.Page = annotPage[w.AnnotationDict]
			}
			f.States = appearanceKeys(fi.Field)
		}

		if f.Page > 0 {
			pageFields[f.Page] = append(pageFields[f.Page], name)
		}
		if f.Type == schema.TypePushButton {
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("field %q is a push button: it cannot be filled with a value", name))
		}
		out.Fields = append(out.Fields, f)
	}

	sort.Slice(out.Fields, func(i, j int) bool { return out.Fields[i].Name < out.Fields[j].Name })
	out.FieldCount = len(out.Fields)

	out.Pages = make([]schema.PageInfo, 0, len(pages))
	for i, page := range pages {
		media := page.MediaBox
		w, h := 0.0, 0.0
		if media != nil {
			w, h = f64(media.Urx-media.Llx), f64(media.Ury-media.Lly)
		}
		pi := schema.PageInfo{Index: i + 1, Width: w, Height: h, Rotate: rotationDeg(page.Rotate)}
		pi.Fields = pageFields[i+1]
		sort.Strings(pi.Fields)
		out.Pages = append(out.Pages, pi)
	}

	return out, nil
}

func textMaxLen(ft model.FormField) int {
	if txt, ok := ft.(model.FormFieldText); ok {
		if ml, ok := txt.MaxLen.(model.ObjInt); ok && ml > 0 {
			return int(ml)
		}
	}
	return 0
}

func appearanceKeys(f *model.FormFieldDict) []string {
	uniq := map[string]bool{}
	for _, w := range f.Widgets {
		if w.AnnotationDict == nil || w.AP == nil {
			continue
		}
		for k := range w.AP.N {
			if k == "" {
				continue
			}
			uniq[string(k)] = true
		}
	}
	if len(uniq) == 0 {
		return nil
	}
	out := make([]string, 0, len(uniq))
	for k := range uniq {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func f64(v model.Fl) float64 { return float64(v) }

// FullName builds the fully qualified name of a field, mirroring the rules
// used by AcroForm.Flatten.
func FullName(f *model.FormFieldDict, parent string, index int) string {
	name := f.T
	if name == "" {
		name = fmt.Sprintf("%d", index)
	}
	if parent != "" {
		return parent + "." + name
	}
	return name
}

// SplitName reports the fully qualified names of all root fields, useful for
// diagnostics.
func RootNames(a model.AcroForm) []string {
	out := make([]string, 0, len(a.Fields))
	for i, f := range a.Fields {
		out = append(out, FullName(f, "", i))
	}
	sort.Strings(out)
	return out
}

// IsFormFieldsEmpty reports whether a document has a usable AcroForm.
func HasForm(doc *model.Document) bool { return len(doc.Catalog.AcroForm.Fields) > 0 }

// NormaliseName lower-cases and strips spaces, used for tolerant lookups.
func NormaliseName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}
