package signfill

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/benoitkugler/pdf/model"

	"github.com/sunshine69/pdf-go/internal/pdf"
	"github.com/sunshine69/pdf-go/internal/report"
)

// MaxPageRunes caps how much text one append may typeset. Without a ceiling a
// pasted megabyte of notes produces a megabyte-long document and an unusable
// number of pages.
const MaxPageRunes = 200_000

// AppendOptions configures one page-insertion run.
type AppendOptions struct {
	Path     string // original path, used for temp staging and in the report
	Password string
	Format   string // "markdown" (default), "html", or "text"
	At       int    // 0-based page index to insert after; -1 appends at the end
	Margin   float64
	FontSize float64
	Leading  float64
	Font     string
	Title    string // optional heading printed at the top of the first page
	Strict   bool   // turn unsupported characters into an error

	// Input names the file the text was read from, for the report only. It is
	// deliberately not used to read anything: the text arrives as an argument so
	// the HTTP API can pass a request body through the same code.
	Input string
}

// Append typesets text and splices the resulting pages into an existing PDF.
//
// It is bytes-in / bytes-out for the same reason Fill is: the CLI and the HTTP
// API must not grow different semantics. Nothing is signed here; a signed
// document is a change of version, so the caller is expected to append before
// the envelope is sent.
func Append(in []byte, text string, o AppendOptions) (report.AppendReport, []byte, error) {
	if len(in) == 0 {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: empty document")
	}
	if !bytes.HasPrefix(in, []byte("%PDF-")) {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: input is not a PDF")
	}
	if n := utf8.RuneCountInString(text); n > MaxPageRunes {
		return report.AppendReport{}, nil, fmt.Errorf(
			"signfill: %d characters of text exceeds the %d character limit", n, MaxPageRunes)
	}
	if o.At < -1 {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: page index %d is invalid, use -1 to append", o.At)
	}

	format := strings.ToLower(strings.TrimSpace(o.Format))
	if format == "" {
		format = "markdown"
	}

	tmp, err := os.MkdirTemp("", "signappend")
	if err != nil {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	inPath := filepath.Join(tmp, "in.pdf")
	if err := os.WriteFile(inPath, in, 0o600); err != nil {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: stage document: %w", err)
	}

	doc, _, err := pdf.Load(inPath, o.Password)
	if err != nil {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: parse: %w", err)
	}

	existing := doc.Catalog.Pages.Count()
	if o.At >= existing {
		return report.AppendReport{}, nil, fmt.Errorf(
			"signfill: page index %d is out of range, the document has %d pages", o.At, existing)
	}

	blocks, notes, err := blocksFor(text, format)
	if err != nil {
		return report.AppendReport{}, nil, err
	}
	if o.Title != "" {
		blocks = append([]pdf.Block{{
			Kind:  pdf.KindHeading,
			Level: 1,
			Runs:  []pdf.Run{{Text: o.Title}},
		}}, blocks...)
	}

	// The new pages copy the geometry of the last existing page, so an added
	// annex matches the document it joins instead of assuming A4.
	leaves := doc.Catalog.Pages.FlattenInherit()
	if len(leaves) == 0 {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: the document has no pages to copy geometry from")
	}
	src := leaves[len(leaves)-1]
	rect := model.Rectangle{Llx: 0, Lly: 0, Urx: 595, Ury: 842}
	if src.MediaBox != nil {
		rect = *src.MediaBox
	}

	opts := pdf.PageOptions{
		Margin:   o.Margin,
		FontSize: o.FontSize,
		Leading:  o.Leading,
		Font:     o.Font,
	}
	results, err := pdf.BuildPages(rect, blocks, opts)
	if err != nil {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: typeset: %w", err)
	}

	pages := make([]*model.PageObject, 0, len(results))
	lines := 0
	for _, r := range results {
		pages = append(pages, r.Page)
		lines += r.Lines
	}
	if err := pdf.AppendPages(doc, o.At, pages); err != nil {
		return report.AppendReport{}, nil, fmt.Errorf("signfill: splice: %w", err)
	}

	// The caller asked for -1 to mean "at the end". Reporting -1 back would
	// leave them to redo the arithmetic, and it would not tell them which page
	// the annex actually starts on.
	at := o.At
	if at < 0 {
		at = existing - 1
	}

	rep := report.AppendReport{
		Source:    o.Path,
		Input:     o.Input,
		Format:    format,
		At:        at,
		PageCount: existing + len(pages),
		Added:     len(pages),
		Lines:     lines,
		Warnings:  notes,
	}

	charsetWarnings := unsupportedWarning(blocks, o.Font)
	if charsetWarnings != "" {
		if o.Strict {
			return rep, nil, fmt.Errorf("signfill: %s", charsetWarnings)
		}
		rep.Warnings = append(rep.Warnings, charsetWarnings)
	}

	var out bytes.Buffer
	if err := doc.Write(&out, nil); err != nil {
		return rep, nil, fmt.Errorf("signfill: write: %w", err)
	}
	return rep, out.Bytes(), nil
}

// blocksFor dispatches on format. Plain text is routed through the Markdown
// path because a paragraph of text is valid Markdown, with one exception:
// hard line breaks are preserved, which Markdown would otherwise fold away.
func blocksFor(text, format string) ([]pdf.Block, []string, error) {
	switch format {
	case "markdown", "md":
		return pdf.BlocksFromMarkdown([]byte(text), pdf.MarkdownOptions{})
	case "html", "htm":
		return pdf.BlocksFromHTML([]byte(text), pdf.MarkdownOptions{})
	case "text", "txt":
		return textBlocks(text), nil, nil
	default:
		return nil, nil, fmt.Errorf(
			"signfill: unknown format %q; use markdown, html or text", format)
	}
}

// textBlocks keeps the author's line breaks, which is what a term sheet or a
// clause list pasted from another tool needs.
func textBlocks(text string) []pdf.Block {
	var out []pdf.Block
	var para []string
	flush := func() {
		if len(para) == 0 {
			return
		}
		txt := strings.Join(para, "\n")
		if strings.TrimSpace(txt) != "" {
			out = append(out, pdf.Block{Kind: pdf.KindParagraph, Runs: []pdf.Run{{Text: txt}}})
		}
		para = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		para = append(para, strings.TrimRight(line, " \t"))
	}
	flush()
	if len(out) == 0 {
		return []pdf.Block{{Kind: pdf.KindParagraph, Runs: []pdf.Run{{Text: " "}}}}
	}
	return out
}

// unsupportedWarning names the characters the base font cannot draw. The
// library substitutes them with a dot and logs once per rune, so without this
// a document can quietly lose every non-Latin word in it.
func unsupportedWarning(blocks []pdf.Block, font string) string {
	fam := font
	if fam == "" {
		fam = "helvetica"
	}
	var missing []rune
	seen := map[rune]bool{}
	for _, b := range blocks {
		for _, r := range b.Runs {
			f := fam
			switch {
			case r.Mono:
				f = "courier"
			case r.Bold && r.Italic:
				f = "helvetica-boldoblique"
			case r.Bold:
				f = "helvetica-bold"
			case r.Italic:
				f = "helvetica-oblique"
			}
			for _, c := range pdf.UnsupportedRunes(f, r.Text) {
				if seen[c] {
					continue
				}
				seen[c] = true
				missing = append(missing, c)
				if len(missing) >= 12 {
					break
				}
			}
			if len(missing) >= 12 {
				break
			}
		}
		if len(missing) >= 12 {
			break
		}
	}
	if len(missing) == 0 {
		return ""
	}
	shown := make([]string, 0, len(missing))
	for _, c := range missing {
		shown = append(shown, fmt.Sprintf("%q(U+%04X)", string(c), c))
	}
	return fmt.Sprintf(
		"the built-in fonts cannot draw %s; they are written as \".\" in the output. "+
			"The standard 14 fonts cover Latin-1 only, so CJK, Arabic, Hebrew, Cyrillic, "+
			"Greek and emoji need an embedded font instead",
		strings.Join(shown, ", "))
}
