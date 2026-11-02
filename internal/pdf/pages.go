package pdf

import (
	"fmt"

	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/schema"
)

// Pages describes the geometry of every page of a document: the boxes a
// stamp can be positioned against, and the fields drawn on the page.
//
// This is the companion of `extract`: extract answers *what* can be filled,
// pages answers *where* things can be drawn. Passing the list of pages as
// boxes limits the work to the pages of interest.
func Pages(path, password string, pageNumbers []int) ([]schema.PageGeometry, error) {
	doc, _, err := Load(path, password)
	if err != nil {
		return nil, err
	}
	pages := doc.Catalog.Pages.Flatten()

	want := map[int]bool{}
	for _, n := range pageNumbers {
		if n < 1 {
			return nil, fmt.Errorf("page numbers start at 1, got %d", n)
		}
		want[n] = true
	}

	out := make([]schema.PageGeometry, 0, len(pages))
	for i, page := range pages {
		if len(want) > 0 && !want[i+1] {
			continue
		}
		out = append(out, geometryOf(i+1, page))
	}
	if len(out) == 0 && len(want) > 0 {
		return nil, fmt.Errorf("no page in %s matches the requested page numbers", path)
	}
	return out, nil
}

// geometryOf reads the boxes of one page. A box that is not defined and not
// inherited is omitted, so the caller can tell "absent" from "equal to crop".
func geometryOf(index int, page *model.PageObject) schema.PageGeometry {
	g := schema.PageGeometry{
		Index:  index,
		Rotate: rotationDeg(page.Rotate),
		Boxes:  map[string][]float64{},
	}
	for _, name := range []string{BoxMedia, BoxCrop, BoxTrim, BoxBleed, BoxArt} {
		if r, err := ResolveBox(page, name); err == nil {
			g.Boxes[name] = RectSlice(r)
		}
	}
	if r, err := ResolveBox(page, BoxContent); err == nil {
		g.Boxes[BoxContent] = RectSlice(r)
	}
	if page.Annots != nil {
		g.Annotations = len(page.Annots)
	}
	if w, h := SizeOf(pageRect(page)); w > 0 {
		g.Width, g.Height = float64(w), float64(h)
	}
	return g
}

// pageRect is the rectangle the page is displayed in (crop, else media).
func pageRect(page *model.PageObject) model.Rectangle {
	if r, err := ResolveBox(page, BoxCrop); err == nil {
		return r
	}
	return model.Rectangle{}
}
