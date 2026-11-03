// Package signfill is the adapter between the signing service and the PDF
// form code already used by the pdf-go CLI (internal/pdf + internal/schema).
//
// It takes a template document and a fill specification in the exact JSON
// format documented by `pdf-go doc`, applies the values, logos and paints,
// and reports what was applied, skipped and warned about. The fill
// specification is the same format the CLI accepts, so the AI filling tool
// and the signing API share one schema and one implementation.
//
// Nothing in this package signs a document. Signing belongs to signpdf.
package signfill
