// Package report defines the JSON envelopes the CLI prints, so an automated
// caller can read the outcome of a run without parsing prose.
package report

// Status codes returned by the CLI.
const (
	OK       = 0
	Usage    = 1
	InputErr = 2
	Partial  = 3
)

// ExtractReport is printed by `extract` when a schema is written to a file,
// summarising what was found.
type ExtractReport struct {
	Source           string         `json:"source"`
	Schema           string         `json:"schema,omitempty"`
	FieldCount       int            `json:"fieldCount"`
	ByType           map[string]int `json:"byType"`
	NeedsAppearances bool           `json:"needsAppearances,omitempty"`
	Warnings         []string       `json:"warnings,omitempty"`
}

// FillReport is printed by `fill`.
type FillReport struct {
	Source string `json:"source"`
	Output string `json:"output"`
	Spec   string `json:"spec,omitempty"`

	// Applied lists the fields whose value was written.
	Applied []string `json:"applied"`
	// Skipped lists the requested fields that were not written, with the
	// reason: a useful signal for an agent filling a form in turns.
	Skipped []SkippedField `json:"skipped,omitempty"`

	// Logos lists where each graphic was stamped.
	Logos []LogoReport `json:"logos,omitempty"`

	// Paints lists where each text block was drawn.
	Paints []PaintReport `json:"paints,omitempty"`

	Missing  []string `json:"missingFields,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Locked   bool     `json:"lockedForm,omitempty"`

	// Notes are per-field remarks that do not fail the run: a value clipped
	// to the width of its field, a signature field that cannot be signed, ...
	Notes []Note `json:"notes,omitempty"`
}

// SkippedField explains why one value was not applied.
type SkippedField struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Note is a remark about one field that did not stop the run.
type Note struct {
	Name  string `json:"name"`
	Note  string `json:"note"`
	Value string `json:"value,omitempty"`
}

// LogoReport is where one graphic ended up.
type LogoReport struct {
	ID       string    `json:"id,omitempty"`
	Page     int       `json:"page"`
	Box      string    `json:"box"`
	Position string    `json:"position,omitempty"`
	Field    string    `json:"field,omitempty"`
	Rect     []float64 `json:"rect"`
	Size     []float64 `json:"size"`
	Rotate   float64   `json:"rotate,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// PaintReport is where one text block was drawn.
type PaintReport struct {
	ID       string    `json:"id,omitempty"`
	Page     int       `json:"page"`
	Box      string    `json:"box,omitempty"`
	Position string    `json:"position,omitempty"`
	Field    string    `json:"field,omitempty"`
	Rect     []float64 `json:"rect"`
	Lines    int       `json:"lines"`
	Size     float64   `json:"size"`
	Font     string    `json:"font,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// PagesReport is printed by `pages` when the geometry is written to a file.
type PagesReport struct {
	Source    string `json:"source"`
	Output    string `json:"output"`
	PageCount int    `json:"pageCount"`
}

// VerifyReport is printed by `verify`.
type VerifyReport struct {
	Source  string `json:"source"`
	Checked int    `json:"checked"`

	Matches    []ValueReport `json:"matches,omitempty"`
	Mismatches []ValueReport `json:"mismatches,omitempty"`
	Missing    []string      `json:"missingFields,omitempty"`
}

// ValueReport is one field compared against what was requested.
type ValueReport struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Want  string `json:"want,omitempty"`
	Got   string `json:"got"`
	Value string `json:"value,omitempty"`
	Match bool   `json:"match"`
}

// Error is the envelope printed for a failure.
type Error struct {
	Error  string `json:"error"`
	Source string `json:"source,omitempty"`
	Hint   string `json:"hint,omitempty"`
}
