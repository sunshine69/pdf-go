package signmail

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"regexp"
	"strings"
	texttmpl "text/template"
)

// Rendering of the four messages. Templates live in web/templates and are
// embedded in the binary, so a deployment needs no template files on disk.
// The text body is rendered with text/template (no escaping, so the link is
// printed in full); the HTML body with html/template, which escapes the link
// in the href context and will not accept a script.

// Data is what a template is given. Every field is plain, so a template cannot
// reach into the store.
type Data struct {
	Kind      string // invite, reminder, cancelled, signed
	Subject   string
	Title     string
	Sender    string
	Signer    string
	Link      string
	ExpiresAt string
	DaysLeft  int
	Reason    string
	SignedAt  string
	SHA256    string
	Bytes     int
	Order     int // the party's place in the signing order
	N         int // the number of parties
	Email     string
	Limit     int
	From      string
	MailFrom  string
	Legal     string

	// The signed message names the attachments it carries, and always names the
	// URL the signed copy lives at: the attachment for a normal document, a
	// time-limited download for one too large to attach. RetainedDays is the
	// life of that link in hours, so the message can state it.
	Attachment   string
	ReceiptName  string
	DownloadURL  string
	RetainedDays int

	// Recipient is the address the message is going to. Every party-facing
	// message can print it as the reader's own address; the drafter's notices
	// are the first messages whose reader is not the party named in the body,
	// so those templates name the recipient and say why they are writing to
	// them. It is printed as plain, since it reaches the body from user input.
	Recipient string
}

// DefaultLegal is the footer line every message carries.
const DefaultLegal = "This message was sent by signsrv, an electronic signature service."

// Renderer holds the parsed templates. Parsing happens at startup: a template
// that does not parse is a startup error, not a failure at send time.
type Renderer struct {
	text map[string]*texttmpl.Template
	html *template.Template
}

// NewRenderer parses the templates read from the embedded filesystem.
func NewRenderer(fsys fs.FS) (*Renderer, error) {
	// The two drafter kinds are here for the same reason as the others: a
	// template that does not parse is a startup error, not a failure at the
	// moment a party declines and nobody is watching the queue.
	kinds := []string{"invite.txt.tmpl", "reminder.tmpl", "signed.tmpl", "cancelled.tmpl",
		"declined.tmpl", "undeliverable.tmpl"}
	r := &Renderer{text: map[string]*texttmpl.Template{}}
	for _, name := range kinds {
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("signmail: template %s: %w", name, err)
		}
		t, err := texttmpl.New(name).Funcs(texttmpl.FuncMap{
			// plain strips markup from user-supplied text so the plaintext
			// body stays free of HTML tags, entities, and icons. html/template
			// escapes the same values in the HTML body, so the two views of a
			// title differ only by the escaping each medium needs.
			"plain": Plain,
		}).Parse(string(body))
		if err != nil {
			return nil, fmt.Errorf("signmail: template %s: %w", name, err)
		}
		r.text[kindOf(name)] = t
	}
	body, err := fs.ReadFile(fsys, "invite.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("signmail: template invite.html.tmpl: %w", err)
	}
	t, err := template.New("invite.html.tmpl").Parse(string(body))
	if err != nil {
		return nil, fmt.Errorf("signmail: template invite.html.tmpl: %w", err)
	}
	r.html = t
	return r, nil
}

// kindOf maps a template file name to the message kind. invite.txt.tmpl and
// invite.html.tmpl are two views of one kind, so the text suffix is dropped.
func kindOf(name string) string {
	name = strings.TrimSuffix(name, ".tmpl")
	name = strings.TrimSuffix(name, ".txt")
	return name
}

// Render produces the text and HTML bodies of one message. A reminder, a
// cancellation, and the signed copy have a text body only; their HTML body is
// empty, and Build writes a single text/plain part in that case.
func (r *Renderer) Render(d Data) (string, string, error) {
	t := r.text[d.Kind]
	if t == nil {
		return "", "", fmt.Errorf("signmail: no template for kind %q", d.Kind)
	}
	// The subject, the footer, and the sender line are filled here, so a
	// caller that builds a Data value with the document facts gets a complete
	// message without remembering which fields a template needs.
	if d.Subject == "" {
		d.Subject = SubjectFor(d)
	}
	// The subject is built from the document title, so it carries the same
	// user data as the body. The plaintext templates print it as plain.
	d.Subject = Plain(d.Subject)
	if d.Legal == "" {
		d.Legal = DefaultLegal
	}
	if d.From == "" {
		d.From = d.MailFrom
	}
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		return "", "", fmt.Errorf("signmail: %s: %w", d.Kind, err)
	}
	text := strings.TrimRight(b.String(), "\n")
	if len(text) > MaxBodyBytes {
		return "", "", fmt.Errorf("signmail: %s body is %d bytes, limit %d",
			d.Kind, len(text), MaxBodyBytes)
	}
	html := ""
	if d.Kind == "invite" {
		var h bytes.Buffer
		if err := r.html.Execute(&h, d); err != nil {
			return "", "", fmt.Errorf("signmail: invite html: %w", err)
		}
		html = strings.TrimRight(h.String(), "\n")
		if len(html) > MaxBodyBytes {
			return "", "", fmt.Errorf("signmail: invite html is %d bytes, limit %d",
				len(html), MaxBodyBytes)
		}
	}
	if err := checkText(d, text); err != nil {
		return "", "", err
	}
	return text, html, nil
}

// checkText enforces the plaintext rules the specification states: the link
// appears in full, and no HTML tag, entity, emoji, or icon appears in it.
// checkText enforces the plaintext rules: the link appears in full, and no
// HTML tag, entity, emoji, or icon appears in the body. User fields are run
// through plain at render time, so the check applies to the whole body,
// including a title a user typed with tags in it.
func checkText(d Data, text string) error {
	// The link must be in full in the messages that hand one out. Three kinds
	// are exempt, each because it has no link to carry: a cancelled notice's
	// whole point is that the link a party held is dead, and the drafter's two
	// notices go to someone who was never a party to the link at all — a
	// declined request closed every link in it, and an undeliverable one never
	// reached anyone who could use it. Each template prints no link
	// deliberately, so the rule could not be satisfied here even if it applied.
	if d.Link != "" && !noLinkKinds[d.Kind] && !strings.Contains(text, d.Link) {
		return fmt.Errorf("signmail: %s text body does not contain the link in full", d.Kind)
	}
	if htmlTagRe.MatchString(text) {
		return fmt.Errorf("signmail: %s text body contains an HTML tag", d.Kind)
	}
	if entityRe.MatchString(text) {
		return fmt.Errorf("signmail: %s text body contains an HTML entity", d.Kind)
	}
	if iconRe.MatchString(text) {
		return fmt.Errorf("signmail: %s text body contains a non-ASCII icon", d.Kind)
	}
	return nil
}

// noLinkKinds are the messages that never carry a link: cancelled because the
// link it describes is dead, and the drafter's two notices because the reader
// was never given one. Adding a kind here means its template must print no URL,
// and drafter_test asserts that for the drafter's kinds.
var noLinkKinds = map[string]bool{
	"cancelled": true, "declined": true, "undeliverable": true,
}

var (
	htmlTagRe = regexp.MustCompile(`<[A-Za-z/]`)
	entityRe  = regexp.MustCompile(`&(#|amp|lt|gt|quot|nbsp)`)
	iconRe    = regexp.MustCompile("[\u2600-\u27BF\U0001F300-\U0001FAFF]")
)

// SubjectFor is the subject line of each kind, built here so a template change
// cannot move the subject of a reminder away from the subject of an invite.
func SubjectFor(d Data) string {
	switch d.Kind {
	case "invite":
		return "Signature requested: " + d.Title
	case "reminder":
		return "Signature reminder: " + d.Title
	case "cancelled":
		return "Signing cancelled: " + d.Title
	case "signed":
		return "Signed copy: " + d.Title
	case "declined":
		// The subject leads with the party, not the document: the drafter has
		// many documents out at once, and the fact they need is which one came
		// back.
		return "Signature declined by " + d.Signer + ": " + d.Title
	case "undeliverable":
		return "Invitation could not be delivered: " + d.Title
	}
	return d.Title
}

// Prepare fills in the derived fields of a Data value: subject, legal line,
// days left, so a caller builds one value and renders.
func Prepare(d Data, nowStr string) Data {
	if d.Subject == "" {
		d.Subject = SubjectFor(d)
	}
	if d.Legal == "" {
		d.Legal = DefaultLegal
	}
	if d.From == "" {
		d.From = d.MailFrom
	}
	if d.ExpiresAt == "" {
		d.ExpiresAt = nowStr
	}
	return d
}

// StripProtocol removes http:// and https://, for a body that prints the host
// as text rather than as a link.
func StripProtocol(u string) string {
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(u, p) {
			return u[len(p):]
		}
	}
	return u
}

// Plain makes user-supplied text safe for a plaintext body: HTML tags and
// entities are removed, and characters outside the plain-text range (emoji,
// icons) are dropped. The rule the service states is that a plaintext body
// carries no markup, so a document title that a user typed with tags in it
// cannot inject markup into a message.
func Plain(s string) string {
	s = tagRe.ReplaceAllString(s, "")
	s = entityRe.ReplaceAllString(s, "")
	s = iconRe.ReplaceAllString(s, "")
	return s
}

var tagRe = regexp.MustCompile(`</?[A-Za-z][^>]*>`)
