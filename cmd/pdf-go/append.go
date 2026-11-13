package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/signfill"
)

// runAppend backs both `append` and `insert`. They are one operation; the
// difference is that `insert` insists on a position, because guessing one is
// the worst way to fail at this. `append` defaults to the last page.
func runAppend(args []string, insert bool) int {
	name := "append"
	if insert {
		name = "insert"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	from := fs.String("from", "", "file with the Markdown/HTML/text to typeset ('-' for stdin)")
	text := fs.String("text", "", "text to typeset, instead of --from")
	format := fs.String("format", "", "markdown (default), html or text; inferred from the file name")
	title := fs.String("title", "", "heading printed at the top of the added pages")
	at := fs.Int("at", -1, "0-based page index to add the new pages after; -1 is the end")
	margin := fs.Float64("margin", 56, "page margin in points")
	fontSize := fs.Float64("font-size", 10.5, "body font size in points")
	leading := fs.Float64("leading", 0, "line spacing in points (0 means 1.45x the font size)")
	font := fs.String("font", "helvetica", "body font: helvetica, times or courier")
	strict := fs.Bool("strict", false, "fail if a character cannot be rendered")
	password := fs.String("password", "", "password of an encrypted input PDF")
	outPath := fs.String("o", "", "output file (default <input>-appended.pdf)")
	quiet := fs.Bool("q", false, "do not print the JSON report")

	pos, err := parseAroundPositional(fs, args)
	if err != nil {
		return fail(err, name)
	}
	if fs.NFlag() == 0 && len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.PrintDefaults()
		return report.OK
	}
	if len(pos) == 0 {
		fmt.Fprintf(os.Stderr, "usage: pdf-go %s <in.pdf> [--from notes.md | --text \"...\"] [--at N] [-o out.pdf]\n", name)
		return report.Usage
	}
	if insert && !flagGiven(fs, "at") {
		return fail(fmt.Errorf(
			"insert needs --at N, the 0-based page index to add the page after (use `append` to add at the end)"), name)
	}

	in := pos[0]
	if fi, serr := os.Stat(in); serr == nil && fi.IsDir() {
		return fail(fmt.Errorf("%s is a directory, not a PDF", in), name)
	}

	src := *text
	// inputName records where the text came from, for the report. Stdin and
	// --text have no file to name, so they leave it empty.
	inputName := ""
	if strings.TrimSpace(src) == "" {
		path := *from
		if path == "" {
			path = "-"
		}
		if path != "-" {
			inputName = path
		}
		b, rerr := readOrStdin(path)
		if rerr != nil {
			return fail(rerr, name)
		}
		src = string(b)
		if *format == "" {
			*format = formatFromName(path)
		}
	}
	if *format == "" {
		*format = "markdown"
	}

	doc, rerr := os.ReadFile(in)
	if rerr != nil {
		return fail(fmt.Errorf("read %s: %w", in, rerr), name)
	}

	out := *outPath
	if out == "" {
		out = strings.TrimSuffix(in, filepath.Ext(in)) + "-appended.pdf"
	}

	rep, updated, aerr := signfill.Append(doc, src, signfill.AppendOptions{
		Path:     in,
		Password: *password,
		Format:   *format,
		At:       *at,
		Margin:   *margin,
		FontSize: *fontSize,
		Leading:  *leading,
		Font:     *font,
		Title:    *title,
		Strict:   *strict,
		Input:    inputName,
	})
	if aerr != nil {
		return fail(aerr, in)
	}
	if werr := os.WriteFile(out, updated, 0o644); werr != nil {
		return fail(fmt.Errorf("write %s: %w", out, werr), name)
	}
	rep.Output = out

	if *quiet {
		return report.OK
	}
	if werr := writeJSON(os.Stdout, rep); werr != nil {
		return fail(werr, "")
	}
	return report.OK
}

// flagGiven reports whether a flag was actually passed, as opposed to left at
// its default. `insert` needs this: a missing --at must be an error, not a
// silent guess about where the page should go.
func flagGiven(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// readOrStdin reads a file, or stdin when the path is "-".
func readOrStdin(path string) ([]byte, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}

// formatFromName picks a format from a file extension. Stdin and unknown
// extensions fall back to Markdown, which is what people draft clauses in.
func formatFromName(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm", ".xhtml":
		return "html"
	case ".txt", ".text", ".asc":
		return "text"
	case "-":
		return ""
	default:
		return "markdown"
	}
}

// parseAroundPositional lets flags appear after the input file, as they do for
// every other command in this CLI. The flag package stops at the first
// non-flag argument, so without this "append in.pdf --from notes.md" would
// parse in.pdf, stop, and quietly ignore --from.
func parseAroundPositional(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-" || !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		name, inline, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			return nil, fmt.Errorf("unknown flag --%s", name)
		}
		flagArgs = append(flagArgs, a)
		if inline != "" || boolFlag(f) {
			continue // --name=value, or a flag that takes no value
		}
		if i+1 < len(args) && takesValue(args[i+1]) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	return pos, fs.Parse(flagArgs)
}

// boolFlag reports whether a flag may be given without a value.
func boolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// takesValue reports whether an argument is a flag's value rather than the next
// flag. A negative number counts as a value so that "--at -1" works.
func takesValue(s string) bool {
	if s == "-" || !strings.HasPrefix(s, "-") {
		return true
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
