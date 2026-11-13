package pdf

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// BlocksFromHTML turns an HTML fragment into page blocks.
//
// This is a real walk, not Markdown-with-the-brackets-left-in. Feeding HTML to
// the Markdown parser keeps the tags as text, so <ul><li>a</li><li>b</li></ul>
// prints as the single line "ab" and every paragraph lands on one baseline.
// A contract annex written in HTML has to come out with its structure intact.
func BlocksFromHTML(src []byte, o MarkdownOptions) ([]Block, []string, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		return nil, nil, fmt.Errorf("pdf: html input is empty")
	}
	root, err := html.Parse(bytes.NewReader(src))
	if err != nil {
		return nil, nil, fmt.Errorf("pdf: parse html: %w", err)
	}

	var notes []string
	var blocks []Block

	// Bodyless fragments are parsed under <html><head>; walk from whichever
	// element actually holds the content.
	node := root
	if b := findAtom(root, atom.Body); b != nil {
		node = b
	}
	blocks = appendHTMLBlocks(blocks, node, 0, o, &notes)

	// Some documents put text directly in the fragment. If the structured
	// walk found nothing, fall back to whatever text the document carries so
	// the caller never silently produces a blank page.
	if len(blocks) == 0 {
		if txt := strings.TrimSpace(htmlText(root)); txt != "" {
			blocks = append(blocks, Block{Kind: KindParagraph, Runs: []Run{{Text: txt}}})
		}
	}
	if len(blocks) == 0 {
		return nil, notes, fmt.Errorf("pdf: html produced no printable text")
	}
	return blocks, notes, nil
}

// appendHTMLBlocks walks element children, emitting one Block per block-level
// element and inline runs for everything else.
func appendHTMLBlocks(out []Block, n *html.Node, depth int, o MarkdownOptions, notes *[]string) []Block {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		switch c.Type {
		case html.TextNode:
			// Loose text at block level still has to print.
			if strings.TrimSpace(c.Data) == "" {
				continue
			}
			runs := htmlRuns(c)
			if !anyText(runs) {
				continue
			}
			out = append(out, Block{Kind: KindParagraph, Level: depth, Runs: runs})
		case html.ElementNode:
			switch c.DataAtom {
			case atom.Script, atom.Style, atom.Head, atom.Nav, atom.Footer, atom.Svg:
				// CSS and JS carry no printable contract text.
				continue
			case atom.H1, atom.H2, atom.H3, atom.H4, atom.H5, atom.H6:
				runs := inlineHTMLRuns(c, notes)
				if !anyText(runs) {
					continue
				}
				out = append(out, Block{
					Kind:  KindHeading,
					Level: htmlHeadingLevel(c.DataAtom),
					Runs:  runs,
					Style: BlockStyle{KeepNext: true},
				})
			case atom.P, atom.Dd, atom.Dt:
				runs := inlineHTMLRuns(c, notes)
				if !anyText(runs) {
					continue
				}
				out = append(out, Block{Kind: KindParagraph, Level: depth, Runs: runs})
			case atom.Br:
				out = append(out, Block{Kind: KindParagraph, Level: depth,
					Runs: []Run{{Text: "\n"}}})
			case atom.Hr:
				out = append(out, Block{Kind: KindRule, Level: depth,
					Runs: []Run{{Text: " "}}})
			case atom.Pre:
				txt := htmlText(c)
				if strings.TrimSpace(txt) == "" {
					continue
				}
				out = append(out, Block{Kind: KindCode, Level: depth,
					Runs: []Run{{Text: strings.TrimRight(txt, "\n"), Mono: true}}})
			case atom.Blockquote:
				inner := appendHTMLBlocks(nil, c, depth+1, o, notes)
				for i := range inner {
					inner[i].Kind = KindQuote
				}
				out = append(out, inner...)
			case atom.Ul, atom.Ol, atom.Dl:
				out = appendHTMLList(out, c, depth, o, notes)
			case atom.Table:
				out = appendHHTMLTable(out, c, depth, notes)
			case atom.Div, atom.Section, atom.Article, atom.Main, atom.Body, atom.Html, atom.Span, atom.Li:
				// Containers: keep walking. A <div> with inline text only is
				// handled by the recursive call below finding text nodes.
				out = appendHTMLBlocks(out, c, depth, o, notes)
			default:
				// Unknown block-ish element: walk into it rather than drop it.
				out = appendHTMLBlocks(out, c, depth, o, notes)
			}
		}
	}
	return out
}

// appendHTMLList emits one item per <li>, with the marker for ordered lists.
func appendHTMLList(out []Block, n *html.Node, depth int, o MarkdownOptions, notes *[]string) []Block {
	ordered := n.DataAtom == atom.Ol
	marker := "•"
	if n.DataAtom == atom.Dl {
		marker = ""
	}
	i := 1
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		if c.DataAtom != atom.Li && c.DataAtom != atom.Dt && c.DataAtom != atom.Dd {
			// Nested <ul> directly inside <ul>, or stray whitespace.
			out = appendHTMLBlocks(out, c, depth+1, o, notes)
			continue
		}
		// The item's own inline text first, then any nested lists.
		runs := inlineHTMLRunsDirect(c, notes)
		if ordered {
			runs = append([]Run{{Text: fmt.Sprintf("%d. ", i)}}, runs...)
			i++
		} else if marker != "" {
			runs = append([]Run{{Text: marker + " "}}, runs...)
		}
		if anyText(runs) {
			out = append(out, Block{Kind: KindListItem, Level: depth, Runs: runs})
		}
		for sub := c.FirstChild; sub != nil; sub = sub.NextSibling {
			if sub.Type == html.ElementNode &&
				(sub.DataAtom == atom.Ul || sub.DataAtom == atom.Ol || sub.DataAtom == atom.Dl) {
				out = appendHTMLList(out, sub, depth+1, o, notes)
			}
		}
	}
	return out
}

// inlineHTMLRuns collects the inline content of an element into runs,
// applying bold/italic/mono from the tags the contract author used.
func inlineHTMLRuns(n *html.Node, notes *[]string) []Run {
	return htmlInline(n, false, false, false, notes)
}

// inlineHTMLRunsDirect is inlineHTMLRuns over direct children only, so nested
// lists are not swallowed into the parent item's text.
func inlineHTMLRunsDirect(n *html.Node, notes *[]string) []Run {
	var out []Run
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		switch {
		case c.Type == html.ElementNode &&
			(c.DataAtom == atom.Ul || c.DataAtom == atom.Ol || c.DataAtom == atom.Dl):
			continue // handled separately as a nested list
		case c.Type == html.ElementNode && isBlockTag(c):
			continue // continuation paragraphs are emitted as their own blocks
		}
		out = append(out, htmlInline(c, false, false, false, notes)...)
	}
	return out
}

// isBlockTag reports whether an element starts its own block.
func isBlockTag(n *html.Node) bool {
	switch n.DataAtom {
	case atom.P, atom.Div, atom.Ul, atom.Ol, atom.Dl, atom.Pre, atom.Blockquote,
		atom.Table, atom.Hr, atom.H1, atom.H2, atom.H3, atom.H4, atom.H5, atom.H6:
		return true
	}
	return false
}

// htmlInline walks inline content, carrying the bold/italic/mono state down.
func htmlInline(n *html.Node, bold, ital, mono bool, notes *[]string) []Run {
	switch n.Type {
	case html.TextNode:
		txt := collapseSpaces(n.Data)
		if txt == "" {
			return nil
		}
		return []Run{{Text: txt, Bold: bold, Italic: ital, Mono: mono}}
	case html.ElementNode:
		switch n.DataAtom {
		case atom.Script, atom.Style:
			return nil
		case atom.Br:
			return []Run{{Text: "\n", Bold: bold, Italic: ital, Mono: mono}}
		case atom.Strong, atom.B:
			bold = true
		case atom.Em, atom.I:
			ital = true
		case atom.Code, atom.Pre, atom.Tt, atom.Kbd, atom.Samp:
			mono = true
		case atom.Img:
			*notes = append(*notes, "an <img> in the HTML was not rendered; images need the add-logo path")
			return nil
		}
		var out []Run
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			out = append(out, htmlInline(c, bold, ital, mono, notes)...)
		}
		return out
	}
	return nil
}

// appendHHTMLTable turns a <table> into a block per row. A real grid is out of
// scope; a row per line keeps the content readable and greppable.
func appendHHTMLTable(out []Block, n *html.Node, depth int, notes *[]string) []Block {
	rows := 0
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			if c.Type != html.ElementNode {
				continue
			}
			switch c.DataAtom {
			case atom.Tr:
				var cells []string
				for d := c.FirstChild; d != nil; d = d.NextSibling {
					if d.Type == html.ElementNode && (d.DataAtom == atom.Td || d.DataAtom == atom.Th) {
						cells = append(cells, strings.TrimSpace(htmlText(d)))
					}
				}
				if len(cells) == 0 {
					continue
				}
				rows++
				out = append(out, Block{
					Kind:  KindParagraph,
					Level: depth,
					Runs:  []Run{{Text: strings.Join(cells, "  |  ")}},
				})
			case atom.Tbody, atom.Thead, atom.Tfoot:
				walk(c)
			}
		}
	}
	walk(n)
	if rows > 0 {
		*notes = append(*notes, fmt.Sprintf(
			"a %d-row HTML table was rendered as one line per row, not as a grid", rows))
	}
	return out
}

// htmlRuns builds runs from a bare text node.
func htmlRuns(n *html.Node) []Run {
	txt := collapseSpaces(n.Data)
	if txt == "" {
		return nil
	}
	return []Run{{Text: txt}}
}

// htmlText returns every text node under n, with markup removed. Whitespace is
// preserved for <pre> and collapsed elsewhere by the caller.
func htmlText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		if x.Type == html.ElementNode && x.DataAtom == atom.Br {
			b.WriteString("\n")
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// findAtom returns the first element with the given tag, or nil.
func findAtom(n *html.Node, a atom.Atom) *html.Node {
	if n.Type == html.ElementNode && n.DataAtom == a {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findAtom(c, a); found != nil {
			return found
		}
	}
	return nil
}

// collapseSpaces folds runs of whitespace into single spaces, and trims only
// leading/trailing runs that touch a tag boundary. Text is kept whole so word
// wrapping stays the layout layer's job.
func collapseSpaces(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == ' ':
			if !prevSpace {
				b.WriteByte(' ')
			}
			prevSpace = true
		default:
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return b.String()
}

// htmlHeadingLevel maps an h1..h6 tag to the 1..6 level the layout layer
// expects. The atom values happen to be consecutive, but relying on that
// silently breaks when the tag table changes, so it is written out.
func htmlHeadingLevel(a atom.Atom) int {
	switch a {
	case atom.H1:
		return 1
	case atom.H2:
		return 2
	case atom.H3:
		return 3
	case atom.H4:
		return 4
	case atom.H5:
		return 5
	default:
		return 6
	}
}
