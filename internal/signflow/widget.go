package signflow

import (
	"fmt"

	"github.com/sunshine69/pdf-go/internal/pdf"
)

// checkWidget validates the placement the drafter asked for against the
// document that will actually carry the signatures.
//
// The page is checked because the batch signs the certified bytes, and those
// bytes may have a different page count from the uploaded template once the
// fill has run. A page number that only makes sense on the template is a
// signature the batch will refuse to draw, hours later, after every party has
// clicked through the consent screen.
//
// The field name is checked because a name that is not in the document would
// otherwise fall back to the default corner without saying so: the drafter
// would get a signature in the wrong place and no error, which is the worst
// kind of mistake in a signing system.
func checkWidget(filled []byte, w Widget) error {
	if w.Page == 0 && w.Field == "" && w.X == 0 && w.Y == 0 {
		// Nothing was asked for. The batch uses the default column, which is
		// always valid, so there is nothing to check and no parse to pay for.
		return nil
	}
	n, err := pdf.PageCount(filled)
	if err != nil {
		return validation("widget", err.Error(), "the signed document could not be read to check the placement")
	}
	if w.Page < 0 {
		return validation("widget.page", fmt.Sprintf("%d is not a page", w.Page),
			fmt.Sprintf("pages are numbered from 1 to %d", n))
	}
	if w.Page > n {
		return validation("widget.page", fmt.Sprintf("page %d does not exist", w.Page),
			fmt.Sprintf("the document has %d pages", n))
	}
	if w.Field != "" {
		fields, err := pdf.FieldPages(filled)
		if err != nil {
			return validation("widget.field", err.Error(), "the signed document could not be read to check the field")
		}
		if _, _, ok := pdf.LookupTarget(fields, w.Field); !ok {
			return validation("widget.field", fmt.Sprintf("%q is not a field of this document", w.Field),
				"run extract on the template and use one of its field names, or leave the field empty")
		}
	}
	if w.X < 0 || w.Y < 0 {
		return validation("widget", fmt.Sprintf("x=%v y=%v", w.X, w.Y),
			"coordinates are distances from the bottom-left corner, in points, and cannot be negative")
	}
	return nil
}

// widgetEventField is what the audit event records about the placement. The
// event payload is the only place a create's intent survives outside the row,
// so an empty widget stays an empty object rather than becoming a zero page.
func widgetEventField(w Widget) map[string]any {
	out := map[string]any{}
	if w.Field != "" {
		out["field"] = w.Field
	}
	if w.Page > 0 {
		out["page"] = w.Page
	}
	if w.X != 0 {
		out["x"] = w.X
	}
	if w.Y != 0 {
		out["y"] = w.Y
	}
	return out
}
