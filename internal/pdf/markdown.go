package pdf

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/parser"
)

// MarkdownOptions controls how Markdown text becomes page blocks.
type MarkdownOptions struct {
	// Bullet is the glyph drawn before a list item. A rune the font cannot
	// draw is reported rather than silently turned into a dot.
	Bullet string
}

// BlocksFromMarkdown parses Markdown and returns page blocks. Tables and
// images are reported as notes rather than dropped in silence: a contract
// that quietly loses a signature table is worse than one that fails.
func BlocksFromMarkdown(src []byte, o MarkdownOptions) ([]Block, []string, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		return nil, nil, fmt.Errorf("pdf: markdown input is empty")
	}
	p := parser.NewWithExtensions(parser.CommonExtensions)
	doc := p.Parse(src)

	var notes []string
	var blocks []Block
	blocks = appendBlocks(blocks, doc, 0, o, &notes)
	if len(blocks) == 0 {
		return nil, notes, fmt.Errorf("pdf: markdown produced no printable text")
	}
	return blocks, notes, nil
}

// appendBlocks walks the AST and emits blocks. depth is the nesting level for
// lists and quotes.
func appendBlocks(out []Block, n ast.Node, depth int, o MarkdownOptions, notes *[]string) []Block {
	for _, kid := range n.GetChildren() {
		switch node := kid.(type) {
		case *ast.Heading:
			runs := inlineRuns(node.GetChildren(), notes)
			if !anyText(runs) {
				continue
			}
			lvl := node.Level
			if lvl < 1 {
				lvl = 1
			}
			if lvl > 6 {
				lvl = 6
			}
			out = append(out, Block{
				Kind:  KindHeading,
				Level: lvl,
				Runs:  runs,
				Style: BlockStyle{KeepNext: true},
			})
		case *ast.Paragraph:
			runs := inlineRuns(node.GetChildren(), notes)
			if !anyText(runs) {
				continue
			}
			out = append(out, Block{Kind: KindParagraph, Level: depth, Runs: runs})
		case *ast.Text:
			// A text block appears inside list items and table cells.
			runs := inlineRuns(node.GetChildren(), notes)
			if !anyText(runs) {
				continue
			}
			out = append(out, Block{Kind: KindParagraph, Level: depth, Runs: runs})
		case *ast.List:
			out = appendList(out, node, depth, o, notes)
		case *ast.BlockQuote:
			inner := appendBlocks(nil, node, depth+1, o, notes)
			for i := range inner {
				inner[i].Kind = KindQuote
				if inner[i].Style.Indent == 0 {
					inner[i].Style.Indent = 24 + float64(depth)*12
				}
			}
			out = append(out, inner...)
		case *ast.CodeBlock:
			code := string(node.Literal)
			if code == "" {
				code = strings.TrimRight(string(node.Content), "\n")
			}
			if code == "" {
				continue
			}
			out = append(out, Block{
				Kind: KindCode,
				Runs: []Run{{Text: strings.TrimRight(code, "\n"), Mono: true}},
			})
		case *ast.HorizontalRule:
			out = append(out, Block{Kind: KindRule})
		case *ast.Table:
			*notes = append(*notes, "a table was found; tables are not typeset yet, its cells are written one per line")
			out = append(out, tableBlocks(node, notes)...)
		case *ast.HTMLBlock:
			// The parser hands us raw markup. Stripping tags keeps the words,
			// which is the honest minimum; silently dropping the whole block
			// would lose contract text.
			txt := stripTags(string(node.Literal))
			if strings.TrimSpace(txt) == "" {
				continue
			}
			*notes = append(*notes, "raw HTML was converted to plain text; tags and styling are dropped")
			out = append(out, Block{Kind: KindParagraph, Runs: []Run{{Text: txt}}})
		case *ast.Aside, *ast.MathBlock:
			runs := inlineRuns(node.GetChildren(), notes)
			if anyText(runs) {
				out = append(out, Block{Kind: KindParagraph, Level: depth, Runs: runs})
			}
		default:
			// Anything unhandled is still walked, so text is not lost just
			// because its container is a node type we do not model.
			out = appendBlocks(out, node, depth, o, notes)
		}
	}
	return out
}

func appendList(out []Block, l *ast.List, depth int, o MarkdownOptions, notes *[]string) []Block {
	ordered := l.ListFlags&ast.ListTypeOrdered != 0
	marker := o.Bullet
	if marker == "" {
		marker = "\u2022" // bullet, which the standard fonts do support
	}
	i := l.Start
	if i <= 0 {
		i = 1
	}
	for _, item := range l.GetChildren() {
		li, ok := item.(*ast.ListItem)
		if !ok {
			continue
		}
		// A list item holds blocks; the leading inline text of the item is
		// what we turn into the first line, and nested lists follow.
		head, tail := splitListItem(li)
		runs := inlineRuns(head, notes)
		if ordered {
			runs = append([]Run{{Text: fmt.Sprintf("%d. ", i)}}, runs...)
			i++
		} else {
			runs = append([]Run{{Text: marker + " "}}, runs...)
		}
		if anyText(runs) {
			out = append(out, Block{Kind: KindListItem, Level: depth, Runs: runs})
		}
		// Only the continuation blocks may be walked again. Re-walking the item
		// itself prints its text a second time, which is exactly what an
		// agent-written annex must not do.
		out = appendBlocks(out, &ast.Container{Children: tail}, depth+1, o, notes)
	}
	return out
}

// splitListItem separates the item's own inline content from nested blocks.
// The library puts leading text directly in the ListItem's children.
func splitListItem(li *ast.ListItem) (inline, blocks []ast.Node) {
	for _, c := range li.GetChildren() {
		switch c.(type) {
		case *ast.List, *ast.CodeBlock, *ast.Paragraph, *ast.Text:
			// Paragraph/TextBlock after the first position is a continuation
			// paragraph; treat the first one as the item text.
			if len(inline) == 0 && len(blocks) == 0 {
				inline = c.GetChildren()
				continue
			}
			blocks = append(blocks, c)
		default:
			if len(blocks) == 0 {
				inline = append(inline, c)
				continue
			}
			blocks = append(blocks, c)
		}
	}
	return inline, blocks
}

func tableBlocks(t *ast.Table, notes *[]string) []Block {
	var out []Block
	for _, row := range t.GetChildren() {
		cells := rowCells(row)
		if len(cells) == 0 {
			continue
		}
		var runs []Run
		for _, c := range cells {
			runs = append(runs, Run{Text: c})
		}
		out = append(out, Block{Kind: KindParagraph, Runs: runs, Style: BlockStyle{
			Before: 0, After: 0,
		}})
	}
	return out
}

func rowCells(row ast.Node) []string {
	var out []string
	for _, c := range row.GetChildren() {
		runs := inlineRuns(c.GetChildren(), nil)
		txt := runsText(runs)
		if txt != "" {
			out = append(out, txt)
		}
	}
	return out
}

// inlineRuns flattens inline nodes into styled runs.
func inlineRuns(nodes []ast.Node, notes *[]string) []Run {
	var runs []Run
	var walk func(ns []ast.Node, bold, ital, mono bool)
	walk = func(ns []ast.Node, bold, ital, mono bool) {
		for _, n := range ns {
			switch node := n.(type) {
			case *ast.Text:
				txt := string(node.Literal)
				if txt == "" {
					txt = string(node.Content)
				}
				if txt != "" {
					runs = append(runs, Run{Text: txt, Bold: bold, Italic: ital, Mono: mono})
				}
			case *ast.Code:
				txt := string(node.Literal)
				if txt != "" {
					runs = append(runs, Run{Text: txt, Bold: bold, Italic: ital, Mono: true})
				}
			case *ast.Strong:
				walk(node.GetChildren(), true, ital, mono)
			case *ast.Emph:
				walk(node.GetChildren(), bold, true, mono)
			case *ast.Del:
				walk(node.GetChildren(), bold, ital, mono)
			case *ast.Link:
				// The target is kept in brackets only when it is meaningful;
				// for a contract the visible text is what matters.
				walk(node.GetChildren(), bold, ital, mono)
			case *ast.Image:
				if notes != nil {
					*notes = append(*notes, "an image was dropped: images in source documents are not embedded yet")
				}
				if t := string(node.Title); t != "" {
					runs = append(runs, Run{Text: "[" + t + "]", Bold: bold, Italic: ital})
				}
			case *ast.Softbreak:
				runs = append(runs, Run{Text: " ", Bold: bold, Italic: ital, Mono: mono})
			case *ast.Hardbreak:
				runs = append(runs, Run{Text: "\n", Bold: bold, Italic: ital, Mono: mono})
			case *ast.NonBlockingSpace:
				runs = append(runs, Run{Text: string(node.Literal), Bold: bold, Italic: ital})
			case *ast.HTMLSpan:
				txt := stripTags(string(node.Literal))
				if txt != "" {
					runs = append(runs, Run{Text: txt, Bold: bold, Italic: ital})
				}
			default:
				walk(node.GetChildren(), bold, ital, mono)
			}
		}
	}
	walk(nodes, false, false, false)
	return mergeRuns(runs)
}

// mergeRuns joins adjacent runs that share styling, so a paragraph written as
// one node is not split into fragments.
func mergeRuns(in []Run) []Run {
	var out []Run
	for _, r := range in {
		if r.Text == "" {
			continue
		}
		if n := len(out); n > 0 {
			last := &out[n-1]
			if last.Bold == r.Bold && last.Italic == r.Italic && last.Mono == r.Mono {
				last.Text += r.Text
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func joinSpace(runs []Run) []Run {
	if len(runs) == 0 {
		return nil
	}
	out := make([]Run, 0, len(runs)*2-1)
	for i, r := range runs {
		if i > 0 {
			out = append(out, Run{Text: " "})
		}
		out = append(out, r)
	}
	return out
}

func runsText(runs []Run) string {
	var b strings.Builder
	for _, r := range runs {
		b.WriteString(r.Text)
	}
	return strings.TrimSpace(b.String())
}

func anyText(runs []Run) bool {
	return runsText(runs) != ""
}

// stripTags removes HTML markup, keeping the text between tags. Entities that
// appear in contract documents most often are decoded.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
			if depth == 0 {
				b.WriteByte(' ')
			}
		case depth == 0:
			if r == '\n' {
				r = ' '
			}
			b.WriteRune(r)
		}
	}
	out := b.String()
	for _, rep := range [][2]string{
		{"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""},
		{"&nbsp;", " "}, {"&#39;", "'"}, {"&apos;", "'"},
	} {
		out = strings.ReplaceAll(out, rep[0], rep[1])
	}
	out = strings.Join(strings.Fields(out), " ")
	return out
}
