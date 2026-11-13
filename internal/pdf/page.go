package pdf

import (
	"fmt"
	"io"
	"log"
	"sync"

	cs "github.com/benoitkugler/pdf/contentstream"
	"github.com/benoitkugler/pdf/fonts"
	"github.com/benoitkugler/pdf/model"
)

// BlockKind selects the spacing and typeface defaults for a block.
type BlockKind int

const (
	KindParagraph BlockKind = iota
	KindHeading
	KindCode
	KindRule
	KindListItem
	KindQuote
)

// Run is a span of text drawn in one typeface. Inline emphasis in a source
// document becomes a sequence of runs inside one block.
type Run struct {
	Text   string
	Bold   bool
	Italic bool
	Mono   bool
}

// BlockStyle overrides the defaults for one block. Zero means "use the
// default for the block kind".
type BlockStyle struct {
	Font     string
	Size     float64
	Leading  float64
	Indent   float64 // extra left inset
	Right    float64 // extra right inset
	Before   float64 // vertical space above the block
	After    float64 // vertical space below the block
	Align    string  // left (default), center, right
	Color    string  // hex, as accepted by parseColor
	KeepNext bool    // do not break between this block and the next one
}

// Block is one unit of document flow: a paragraph, a heading, a list item, a
// code block or a horizontal rule.
type Block struct {
	Kind  BlockKind
	Level int // heading level 1..6, or list nesting depth
	Runs  []Run
	Style BlockStyle
}

// PageOptions controls the geometry and base typeface of generated pages.
type PageOptions struct {
	Margin    float64 // applied on all four sides
	FontSize  float64
	Leading   float64
	Font      string // base typeface family, default helvetica
	TextColor string // hex, default black
}

func (o PageOptions) withDefaults() PageOptions {
	if o.Margin <= 0 {
		o.Margin = 56 // 2 cm
	}
	if o.FontSize <= 0 {
		o.FontSize = 10.5
	}
	if o.Leading <= 0 {
		o.Leading = o.FontSize * 1.45
	}
	if o.Font == "" {
		o.Font = "helvetica"
	}
	return o
}

// headingSize maps a heading level onto a point size. Levels above 6 are
// treated as 6.
func headingSize(level int, base float64) float64 {
	switch level {
	case 1:
		return base * 1.75
	case 2:
		return base * 1.45
	case 3:
		return base * 1.25
	case 4:
		return base * 1.1
	case 5:
		return base
	default:
		// Markdown allows six levels. Returning base for both 5 and 6 makes a
		// level 6 heading indistinguishable from body text, which is how a
		// document ends up with an invisible outline.
		return base * 0.92
	}
}

// familyFor picks one of the standard-14 names for a run's styling.
func familyFor(base string, r Run) string {
	mono := r.Mono || base == "courier"
	bold, ital := r.Bold, r.Italic
	switch {
	case mono && bold && ital:
		return "courier-boldoblique"
	case mono && bold:
		return "courier-bold"
	case mono && ital:
		return "courier-oblique"
	case mono:
		return "courier"
	case bold && ital:
		return italFamily(base) + "-boldoblique"
	case bold:
		return italFamily(base) + "-bold"
	case ital:
		return italFamily(base) + "-oblique"
	default:
		return base
	}
}

// italFamily keeps a serif or sans base family when adding style.
func italFamily(base string) string {
	switch base {
	case "times", "times-new-roman", "timesnewroman":
		return "times"
	case "courier", "courier-new":
		return "courier"
	default:
		return "helvetica"
	}
}

// linePlan is one typeset line: the runs to draw and their x offsets.
type linePlan struct {
	parts    []partPlan
	width    float64
	baseline float64 // distance from the block top to this line's baseline
	size     float64 // largest size on the line, used for spacing
}

type partPlan struct {
	text string
	fam  string
	size float64
	x    float64

	// gap records that the source separated this word from the previous one
	// on the same line. Painting only needs x, but anything reading the text
	// back (tests, stamping, text extraction) needs to know where the spaces
	// were.
	gap bool
}

// blockIndent returns how far a block sits from the content left edge, in
// points. Level carries two different meanings across the kinds - rank in the
// heading outline, or nesting depth for everything else - so one formula for
// all kinds is wrong twice over: a top-level paragraph (Level 0) hangs 18pt
// into the left margin, and a heading is indented in proportion to a number
// that has nothing to do with layout.
func blockIndent(blk Block) float64 {
	if blk.Style.Indent != 0 {
		return blk.Style.Indent
	}
	depth := blk.Level
	if depth < 0 {
		depth = 0
	}
	switch blk.Kind {
	case KindHeading, KindRule:
		return 0
	case KindListItem:
		return 18 + float64(depth)*18
	case KindQuote:
		return 24
	case KindCode:
		return 12
	default:
		return float64(depth) * 18
	}
}

// layoutBlock wraps a block into lines within maxWidth. The returned lines
// carry absolute x offsets relative to the content left edge.
func layoutBlock(base PageOptions, blk Block, maxWidth float64) []linePlan {
	size := blk.Style.Size
	if size <= 0 {
		size = base.FontSize
	}
	leading := blk.Style.Leading
	if leading <= 0 {
		leading = base.Leading
	}
	if blk.Kind == KindHeading {
		size = headingSize(blk.Level, base.FontSize)
		if blk.Style.Size > 0 {
			size = blk.Style.Size
		}
		leading = size * 1.25
	}
	if blk.Kind == KindCode {
		if blk.Style.Size <= 0 {
			size = base.FontSize * 0.92
		}
		if blk.Style.Leading <= 0 {
			leading = size * 1.35
		}
	}

	// Headings are bold by default and step up to the serif family, which reads
	// as a document heading rather than as the same size of sans bold.
	runs := blk.Runs
	if blk.Kind == KindHeading && blk.Style.Font == "" {
		var forced []Run
		for _, r := range runs {
			r.Bold = true
			if r.Italic {
				r.Italic = false
			}
			forced = append(forced, r)
		}
		runs = forced
	}

	// Flatten runs into word tokens that keep their styling, so that inline
	// emphasis survives line wrapping. gap records whether the source had
	// whitespace before the word; without it a style change fakes a space, so
	// "*ital*." prints as "ital ." instead of "ital.".
	type token struct {
		word string
		gap  bool
		r    Run
		fam  string
		size float64
	}
	var toks []token
	// owed records that the source had whitespace before the next word. It is
	// carried across runs so the state survives a style change mid-sentence.
	owed := false
	for _, r := range runs {
		fam := familyFor(base.Font, r)
		if blk.Style.Font != "" {
			fam = blk.Style.Font
		}
		words, trailing := splitWordsMarked(r.Text, owed)
		for _, w := range words {
			toks = append(toks, token{word: w.word, gap: w.gap, r: r, fam: fam, size: size})
		}
		owed = trailing
	}

	measure := func(t token) float64 {
		return float64(textWidth(mustFont(t.fam), t.word, model.Fl(t.size)))
	}
	spaceW := func(t token) float64 {
		return float64(textWidth(mustFont(t.fam), " ", model.Fl(t.size)))
	}

	var lines []linePlan
	var cur []partPlan
	var curW float64
	flush := func() {
		if len(cur) == 0 {
			return
		}
		lp := linePlan{parts: cur, width: curW}
		var big float64
		for _, p := range cur {
			if p.size > big {
				big = p.size
			}
		}
		lp.size, lp.baseline = big, big*0.85
		lines = append(lines, lp)
		cur, curW = nil, 0
	}

	for _, t := range toks {
		if t.word == "\n" { // hard break, from a code block or a line break
			flush()
			continue
		}
		add := measure(t)
		gap := 0.0
		if len(cur) > 0 && t.gap {
			gap = spaceW(t)
		}
		if curW+gap+add > maxWidth && len(cur) > 0 {
			flush()
			gap = 0
		}
		cur = append(cur, partPlan{text: t.word, fam: t.fam, size: t.size,
			x: curW + gap, gap: t.gap && len(cur) > 0})
		curW += gap + add
	}
	flush()
	if len(lines) == 0 {
		lines = append(lines, linePlan{baseline: size * 0.85, size: size})
	}
	return lines
}

// splitWordsMarked splits on whitespace into words, marking each with whether
// the source separated it from what came before. `afterSpace` carries that
// state in across a run boundary and `trailing` carries it out, so a style
// change in the middle of a sentence neither adds nor loses a space: the text
// "and *ital*." arrives as two runs and must still print as "and ital.".
// Explicit newlines are returned as "\n" tokens with their own gap state.
func splitWordsMarked(s string, afterSpace bool) (words []wordMark, trailing bool) {
	var b []byte
	gap := afterSpace
	flushWord := func() {
		if len(b) > 0 {
			words = append(words, wordMark{word: string(b), gap: gap})
			b = b[:0]
			gap = false
		}
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			flushWord()
			words = append(words, wordMark{word: "\n", gap: gap})
			gap = false
		case ' ', '\t', '\r':
			flushWord()
			gap = true
		default:
			b = append(b, s[i])
		}
	}
	flushWord()
	if len(words) == 0 {
		return nil, gap
	}
	return words, gap
}

// wordMark is one word plus the information needed to re-join it.
type wordMark struct {
	word string
	gap  bool
}

// mustFont builds and caches a standard font. stdFont already caches.
func mustFont(fam string) fonts.BuiltFont {
	bf, err := builtFont(stdFont(fam))
	if err != nil {
		// stdFont only returns names the library knows; a failure here is a
		// bug, and falling back to Helvetica keeps the document readable.
		bf, _ = builtFont(stdFont("helvetica"))
	}
	return bf
}

// layoutLine is a typeset line with an absolute position on a page.
type layoutLine struct {
	parts []partPlan
	x, y  float64

	// size is the largest font size on the line. A caller continuing layout
	// below a generated page needs it, and it is how the tests check the
	// heading hierarchy without rendering pixels.
	size  float64
	color string
	align string
	width float64
}

type layoutRule struct {
	x, y, w float64
	thick   float64
	gray    float64
}

// builtPage collects what goes on one generated page.
type builtPage struct {
	lines []layoutLine
	rules []layoutRule
}

// PageResult is one generated page, ready to be spliced into a document.
type PageResult struct {
	Page     *model.PageObject
	MediaBox model.Rectangle
	Lines    int

	// Placed and Rules keep the layout geometry. A caller that stamps a page
	// number, a signature line or a logo onto a generated page needs to know
	// where the content actually ended; without them the only way is to
	// reverse-engineer it from the rendered bytes.
	Placed []PlacedLine
	Rules  []PlacedRule
}

// BuildPages typesets blocks onto pages of the given size and returns page
// objects. Content is placed top-to-bottom inside the margins.
func BuildPages(rect model.Rectangle, blocks []Block, o PageOptions) ([]PageResult, error) {
	o = o.withDefaults()
	if rect.Urx <= rect.Llx || rect.Ury <= rect.Lly {
		return nil, fmt.Errorf("pdf: page box is empty: %v", rect)
	}
	left := float64(rect.Llx) + o.Margin
	right := float64(rect.Urx) - o.Margin
	top := float64(rect.Ury) - o.Margin
	bottom := float64(rect.Lly) + o.Margin
	width := right - left
	height := top - bottom
	if width <= 10 || height <= 10 {
		return nil, fmt.Errorf("pdf: margins leave no room on a %.0fx%.0f pt page",
			float64(rect.Urx-rect.Llx), float64(rect.Ury-rect.Lly))
	}

	var pages []builtPage
	newPage := func() int {
		pages = append(pages, builtPage{})
		return len(pages) - 1
	}
	pi := newPage()
	y := top

	// advanceTo moves the cursor down by h, starting a new page when the
	// space is gone. ok is false when h is taller than a whole page.
	advanceTo := func(h float64) bool {
		if y-h < bottom {
			pi = newPage()
			y = top
			if y-h < bottom {
				return false
			}
		}
		return true
	}

	for _, blk := range blocks {
		indent := blockIndent(blk)
		blkW := width - indent - blk.Style.Right

		before := blk.Style.Before
		if before == 0 {
			before = defaultBefore(o, blk)
		}
		after := blk.Style.After
		if after == 0 {
			after = defaultAfter(o, blk)
		}

		if blk.Kind == KindRule {
			y -= before
			if !advanceTo(12) {
				return nil, fmt.Errorf("pdf: a rule does not fit on a page")
			}
			pages[pi].rules = append(pages[pi].rules, layoutRule{x: left, y: y, w: width, thick: 0.7, gray: 0.45})
			y -= 12 + after
			continue
		}

		lines := layoutBlock(o, blk, blkW)
		lead := lineLeading(o, blk)

		// Keep a heading with the line that follows it, and keep two lines of
		// a paragraph together, which is what stops lonely orphans.
		need := lead * float64(len(lines))
		if blk.Kind == KindHeading {
			need += lead // the heading plus at least one line of what it heads
		} else if len(lines) > 1 {
			need += lead // at least two lines together
		}
		if blk.Style.KeepNext {
			need += lead
		}
		if y-before-need < bottom && y < top {
			pi = newPage()
			y = top
		}

		y -= before
		for _, lp := range lines {
			if y-lead < bottom {
				pi = newPage()
				y = top
				y -= before
			}
			base := y - lp.baseline
			col := blk.Style.Color
			if col == "" {
				col = o.TextColor
			}
			xoff := left + indent
			switch blk.Style.Align {
			case "center", "centre":
				xoff += (blkW - lp.width) / 2
			case "right":
				xoff += blkW - lp.width
			}
			pages[pi].lines = append(pages[pi].lines, layoutLine{
				parts: lp.parts, x: xoff, y: base, size: lp.size, color: col,
				align: blk.Style.Align, width: lp.width,
			})
			y -= lead
		}
		y -= after
	}

	out := make([]PageResult, 0, len(pages))
	for _, p := range pages {
		po, n, err := renderPage(rect, p, o)
		if err != nil {
			return nil, err
		}
		out = append(out, PageResult{
			Page:     po,
			MediaBox: rect,
			Lines:    n,
			Placed:   exportLines(p.lines),
			Rules:    exportRules(p.rules),
		})
	}
	return out, nil
}

func lineLeading(o PageOptions, blk Block) float64 {
	if blk.Style.Leading > 0 {
		return blk.Style.Leading
	}
	size := o.FontSize
	if blk.Kind == KindHeading {
		size = headingSize(blk.Level, o.FontSize)
	}
	if blk.Kind == KindHeading {
		return size * 1.25
	}
	if blk.Kind == KindCode {
		return o.FontSize * 0.92 * 1.35
	}
	return o.Leading
}

func defaultBefore(o PageOptions, blk Block) float64 {
	switch blk.Kind {
	case KindHeading:
		if blk.Level <= 1 {
			return o.Leading * 1.4
		}
		return o.Leading * 1.0
	case KindCode, KindRule:
		return o.Leading * 0.8
	case KindQuote:
		return o.Leading * 0.5
	default:
		return 0
	}
}

func defaultAfter(o PageOptions, blk Block) float64 {
	switch blk.Kind {
	case KindHeading:
		return o.Leading * 0.4
	case KindCode, KindRule:
		return o.Leading * 0.8
	default:
		return o.Leading * 0.45
	}
}

// The standard-14 fonts carry a WinAnsi-style map. A rune outside it is
// written as "." by the library, which also logs "unsupported rune" to the
// standard logger. For a contract that is silent data loss: Japanese, Chinese
// and emoji turn into dots. Document authors need to be told, not surprised.
//
// Support is decided by asking the font to encode the rune and looking for
// the substitution, because the font's own map is the only authority. Encode
// logs on failure, so the probe runs with the logger redirected.
type fontSupport struct {
	bf fonts.BuiltFont
	m  map[rune]bool
}

var supportCache sync.Map // family name -> *fontSupport

func supportFor(fam string) *fontSupport {
	if v, ok := supportCache.Load(fam); ok {
		return v.(*fontSupport)
	}
	fs := &fontSupport{bf: mustFont(fam), m: map[rune]bool{}}
	supportCache.Store(fam, fs)
	return fs
}

// supported reports whether fam can draw r.
func supported(fam string, r rune) bool {
	fs := supportFor(fam)
	if v, ok := fs.m[r]; ok {
		return v
	}
	out := log.Writer()
	log.SetOutput(io.Discard)
	enc := fs.bf.Encode([]rune{r})
	log.SetOutput(out)
	// A "." result means the rune was substituted, unless "." itself is what
	// was asked for.
	ok := len(enc) == 1 && (enc[0] != '.' || r == '.')
	fs.m[r] = ok
	return ok
}

// withQuietFontLog suppresses the library's per-rune "unsupported rune" noise
// while fn runs. The library logs once per unsupported rune, which for a page
// of Japanese would bury the command's own output.
func withQuietFontLog(fn func() error) error {
	out := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(out)
	return fn()
}

// UnsupportedRunes returns the distinct runes in text that fam cannot draw, in
// order of first appearance.
func UnsupportedRunes(fam, text string) []rune {
	var out []rune
	seen := map[rune]bool{}
	for _, r := range text {
		if r == '\n' || r == '\t' || seen[r] || supported(fam, r) {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// TextSupported reports whether every rune in text is drawable by fam.
func TextSupported(fam, text string) bool {
	for _, r := range text {
		if r == '\n' || r == '\t' {
			continue
		}
		if !supported(fam, r) {
			return false
		}
	}
	return true
}

// cleanForFont maps control characters onto something printable. Runes the
// font cannot draw are left alone: the library substitutes them, and
// UnsupportedRunes is how the caller learns about them.
func cleanForFont(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '\t':
			out = append(out, ' ', ' ', ' ', ' ')
		case '\r', '\v', '\f':
			out = append(out, ' ')
		default:
			if r < 0x20 {
				out = append(out, ' ')
				continue
			}
			out = append(out, r)
		}
	}
	return string(out)
}

// renderPage turns placed content into a page object.
func renderPage(rect model.Rectangle, p builtPage, o PageOptions) (*model.PageObject, int, error) {
	gs := cs.NewGraphicStream(rect)
	gs.SaveState()

	for _, r := range p.rules {
		gs.Ops(
			cs.OpSetLineWidth{W: model.Fl(r.thick)},
			cs.OpSetStrokeGray{G: model.Fl(r.gray)},
		)
		if r.w > 0 {
			gs.Ops(
				cs.OpMoveTo{X: model.Fl(r.x), Y: model.Fl(r.y)},
				cs.OpLineTo{X: model.Fl(r.x + r.w), Y: model.Fl(r.y)},
				cs.OpStroke{},
			)
		}
	}

	for _, l := range p.lines {
		col, ok := parseColor(l.color)
		if ok {
			gs.SetColorFill(col)
		}
		for _, pt := range l.parts {
			bf := mustFont(pt.fam)
			gs.BeginText()
			gs.SetFontAndSize(bf, model.Fl(pt.size))
			gs.SetTextMatrix(1, 0, 0, 1, model.Fl(l.x+pt.x), model.Fl(l.y))
			if err := gs.ShowText(cleanForFont(pt.text)); err != nil {
				return nil, 0, fmt.Errorf("pdf: draw text %q: %w", pt.text, err)
			}
			gs.EndText()
		}
	}
	if err := gs.RestoreState(); err != nil {
		return nil, 0, err
	}

	fo := gs.ToXFormObject(true)
	res := fo.Resources
	return &model.PageObject{
		MediaBox:  &rect,
		CropBox:   &rect,
		Resources: &res,
		Contents:  []model.ContentStream{fo.ContentStream},
	}, len(p.lines), nil
}

// AppendPages adds generated pages to a document after (or before) an
// existing page index. index is 0-based and counts real pages, so it matches
// what the pages and extract commands report. index == -1 appends at the end.
//
// A page tree can nest (*PageTree nodes inside the root), so the insert point
// has to be resolved by walking to the leaf that owns it. Putting a page in
// the wrong node would silently reorder the document.
func AppendPages(doc *model.Document, index int, pages []*model.PageObject) error {
	if doc == nil {
		return fmt.Errorf("pdf: nil document")
	}
	// Pages is a value on the catalog, so take its address: appending has to
	// change the document, not a copy of its page tree.
	root := &doc.Catalog.Pages
	n := root.Count()
	if index == -1 {
		for _, p := range pages {
			root.Kids = append(root.Kids, p)
		}
		return nil
	}
	if index < 0 || index > n {
		return fmt.Errorf("pdf: page index %d is out of range, the document has %d pages", index, n)
	}
	for i, p := range pages {
		// Each insert shifts the following leaves, so the target moves with it.
		if !insertLeaf(root, index+1+i, p) {
			return fmt.Errorf("pdf: could not place a page after page %d", index)
		}
	}
	return nil
}

// insertLeaf puts page before the leaf at index within the subtree rooted at
// node. It descends into nested trees so the page lands as a sibling of the
// page it follows.
func insertLeaf(node *model.PageTree, index int, page *model.PageObject) bool {
	seen := 0
	for i, kid := range node.Kids {
		switch kid := kid.(type) {
		case *model.PageObject:
			if seen == index {
				node.Kids = insertKid(node.Kids, i, page)
				return true
			}
			seen++
		case *model.PageTree:
			sub := kid.Count()
			if index < seen+sub {
				return insertLeaf(kid, index-seen, page)
			}
			seen += sub
		}
	}
	if seen == index { // insert at the end of this subtree
		node.Kids = append(node.Kids, page)
		return true
	}
	return false
}

func insertKid(kids []model.PageNode, i int, page *model.PageObject) []model.PageNode {
	kids = append(kids, nil)
	copy(kids[i+1:], kids[i:])
	kids[i] = page
	return kids
}
