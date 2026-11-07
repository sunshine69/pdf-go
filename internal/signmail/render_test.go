package signmail

import (
	"bytes"
	"context"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/web"
)

// The acceptance list of docs/steps/06-tokens-email.md for rendering. Every
// signoff item is asserted, and the dev outbox file is parsed with the real
// mail parser rather than grepped.

func newRenderer(t *testing.T) *Renderer {
	t.Helper()
	r, err := NewRenderer(web.Templates())
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	return r
}

func inviteData() Data {
	return Data{
		Kind:      "invite",
		Title:     "Lease 2026",
		Sender:    "Ann",
		Signer:    "Patrick",
		Link:      "http://127.0.0.1:8090/s/mvt3qxgv2nq5kv3yt3dfwhdjuivn57dr35d6zdrbcyt6r3dftc7q",
		ExpiresAt: "2026-11-06T00:00:00Z",
		DaysLeft:  2,
		MailFrom:  "signsrv@example.test",
		From:      "signsrv@example.test",
	}
}

// Signoff: a link of 52 lowercase base32 characters in the plaintext body.
func TestInviteTextHasLinkInFull(t *testing.T) {
	r := newRenderer(t)
	d := inviteData()
	text, html, err := r.Render(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(text, d.Link) {
		t.Fatalf("text body has no link in full:\n%s", text)
	}
	if !regexp.MustCompile(`^/s/[a-z2-7]{52}$`).MatchString(strings.TrimPrefix(d.Link, "http://127.0.0.1:8090")) {
		t.Fatalf("link is not 52 lowercase base32 characters")
	}
	// The same words in the HTML version.
	if !strings.Contains(html, "Lease 2026") || !strings.Contains(html, d.Link) {
		t.Fatalf("html body missing the title or the link:\n%s", html)
	}
	if !strings.Contains(html, `href="`) {
		t.Fatal("html body has no href")
	}
}

// Signoff: no HTML tags, entities, emoji, icons, or HTML escapes in the text
// body.
func TestInviteTextHasNoMarkup(t *testing.T) {
	r := newRenderer(t)
	d := inviteData()
	d.Title = "Lease & <b>2026</b> &copy; caf\xc3\xa9"
	text, _, err := r.Render(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(text, "<") {
		t.Fatalf("text body has an HTML tag:\n%s", text)
	}
	if regexp.MustCompile(`&(amp|lt|gt|quot|nbsp|#)`).MatchString(text) {
		t.Fatalf("text body has an HTML entity:\n%s", text)
	}
	if regexp.MustCompile("[\u2600-\u27BF\U0001F300-\U0001FAFF]").MatchString(text) {
		t.Fatalf("text body has an emoji:\n%s", text)
	}
}

// The link is URL-safe and needs no escaping, so it is printed in full and is
// the same value in the text and the HTML body.
func TestLinkNeedsNoEscaping(t *testing.T) {
	r := newRenderer(t)
	d := inviteData()
	text, html, err := r.Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, d.Link) {
		t.Fatalf("html body escaped the link:\n%s", html)
	}
	if strings.Contains(text, "&#") {
		t.Fatal("text body escaped the link")
	}
}

// Signoff: the RFC 1123 date.
func TestDateIsRFC1123(t *testing.T) {
	now := time.Date(2026, 11, 4, 11, 30, 0, 0, time.UTC)
	got := HeaderDate(now)
	// 2026-11-04 is a Wednesday; the format prints the seconds the clock has.
	want := "Wed, 04 Nov 2026 11:30:00 -0000"
	if got != want {
		t.Fatalf("date %q, want %q", got, want)
	}
	m := &Message{Kind: "invite", EnvelopeID: "e1", PartyID: "p1",
		To: "a@x.test", From: "b@x.test", Subject: "s", Text: "body", HTML: "<p>b</p>"}
	raw := m.Build(now)
	if !bytes.Contains(raw, []byte("Date: "+want+"\r\n")) {
		t.Fatalf("message has no RFC 1123 Date header:\n%s", raw)
	}
}

// Signoff: Message-Id.
func TestMessageIDShape(t *testing.T) {
	id := MessageID("1234567890abcdef1234567890abcdef", "signsrv@example.test")
	if !regexp.MustCompile(`^<[0-9a-f]{16}-1234567890abcdef1234567890abcdef@example\.test>$`).MatchString(id) {
		t.Fatalf("Message-Id %q", id)
	}
}

// Signoff: the body is one part, 8bit, with the link unbroken. The rule this
// replaces (quoted-printable, lines under 76 characters) is the one that put a
// soft break inside a signing link, so the assertion is the opposite: a long
// line is required to exist, and no "=" may appear inside the link.
func TestBodyIsOnePart8bitWithUnbrokenLink(t *testing.T) {
	r := newRenderer(t)
	d := inviteData()
	d.Link = "https://pdfsign.kaykraft.org/s/" + strings.Repeat("a", 64)
	d.Title = "Patrick Müller café"
	text, html, err := r.Render(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	m := &Message{Kind: "invite", EnvelopeID: "e1", PartyID: "p1",
		To: "patrick@example.test", From: "b@x.test", Subject: SubjectFor(d),
		Text: text, HTML: html}
	raw := string(m.Build(time.Now().UTC()))
	if !strings.Contains(raw, "Content-Type: text/html; charset=utf-8\r\n") {
		t.Fatalf("body is not declared text/html:\n%s", raw)
	}
	if !strings.Contains(raw, "Content-Transfer-Encoding: 8bit\r\n") {
		t.Fatalf("body is not 8bit:\n%s", raw)
	}
	if strings.Contains(raw, "multipart/alternative") {
		t.Fatal("message is multipart/alternative; the HTML part can be ignored")
	}
	if !strings.Contains(raw, d.Link) {
		t.Fatalf("link is not in the message in full:\n%s", raw)
	}
	bodyOnly := raw[strings.Index(raw, "\r\n\r\n")+4:]
	if strings.Contains(bodyOnly, "=\r\n") {
		t.Fatal("a quoted-printable soft break is in the body")
	}
	// The href attribute is one string: the anchor line has the link between
	// the quotes with nothing in it.
	href := `href="` + d.Link + `"`
	if !strings.Contains(raw, href) {
		t.Fatalf("href is not the link in full:\n%s", raw)
	}
	// A long line is expected, not wrapped. A wrapped body is the failure.
	long := false
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.Contains(line, d.Link) && len(line) > 76 {
			long = true
		}
	}
	if !long {
		t.Fatal("the link line was wrapped")
	}
}

// Signoff: a subject with a non-ASCII character is sent in the encoded word
// form, so no header carries a byte a relay can drop, and it reads back as it
// was written.
func TestSubjectHeaderEncoding(t *testing.T) {
	if got := EncodeSubject("Signature requested: Lease 2026"); got != "Signature requested: Lease 2026" {
		t.Fatalf("plain subject changed: %q", got)
	}
	enc := EncodeSubject("Signature requested: Patrick Müller café")
	if !strings.HasPrefix(enc, "=?UTF-8?B?") || !strings.HasSuffix(enc, "?=") {
		t.Fatalf("non-ASCII subject not encoded: %q", enc)
	}
	if DecodeSubject(enc) != "Signature requested: Patrick Müller café" {
		t.Fatalf("round trip: %q", DecodeSubject(enc))
	}
	// A subject with a line break cannot be a header field at all.
	if strings.Contains(EncodeSubject("a\r\nBcc: x@y.test"), "\r\n") {
		t.Fatal("a subject can inject a header line")
	}
	m := &Message{Kind: "invite", EnvelopeID: "e1", To: "a@x.test", From: "b@x.test",
		Subject: "Lease Müller", Text: "body"}
	if !strings.Contains(string(m.Build(time.Now().UTC())), "Subject: =?UTF-8?B?") {
		t.Fatal("message header does not encode the subject")
	}

}

// The invite has to tell the signer what to do when the signing page cannot
// show the document on their device, because on some phone browsers the frame
// is empty and the page still has to be signed. The instruction is in both the
// text and the HTML body.
func TestInviteCarriesTheDownloadFallbackLine(t *testing.T) {
	r := newRenderer(t)
	d := inviteData()
	text, html, err := r.Render(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, body := range []struct{ what, s string }{{"text", text}, {"html", html}} {
		if !strings.Contains(strings.ToLower(body.s), "download") {
			t.Fatalf("%s body does not mention the Download fallback:\n%s", body.what, body.s)
		}
	}
	if strings.Contains(text, "<") {
		t.Fatalf("the fallback line put markup in the text body:\n%s", text)
	}
}

// Signoff: a dev outbox message parses as a valid RFC 2822 message with the
// 52-character link inside.
func TestDevOutboxFileParses(t *testing.T) {
	dir := t.TempDir()
	s := &FileSender{Dir: dir}
	d := inviteData()
	r := newRenderer(t)
	text, html, err := r.Render(d)
	if err != nil {
		t.Fatal(err)
	}
	m := &Message{Kind: "invite", EnvelopeID: "abc", PartyID: "p1",
		To: "patrick@example.test", From: d.MailFrom,
		Subject: SubjectFor(d), Text: text, HTML: html}
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatalf("send: %v", err)
	}
	msg, headers, err := Parse(readEml(t, dir, "invite-abc-p1.eml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if headers["Content-Type"] != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type %q", headers["Content-Type"])
	}
	if msg.HTML == "" || !strings.Contains(msg.HTML, d.Link) {
		t.Fatalf("parsed html body has no link:\n%s", msg.HTML)
	}
	if !strings.Contains(msg.HTML, d.Link) {
		t.Fatal("parsed html body has no link")
	}
	// Parse with the standard library too: the file is a real message.
	parsed, err := mail.ReadMessage(bytes.NewReader(readEml(t, dir, "invite-abc-p1.eml")))
	if err != nil {
		t.Fatalf("net/mail rejects the file: %v", err)
	}
	if parsed.Header.Get("Message-Id") == "" {
		t.Fatal("no Message-Id")
	}
	if !regexp.MustCompile(`^<[0-9a-f]{16}-abc@`).MatchString(parsed.Header.Get("Message-Id")) {
		t.Fatalf("Message-Id %q", parsed.Header.Get("Message-Id"))
	}
	if !strings.Contains(parsed.Header.Get("Date"), "2026") {
		t.Fatalf("Date %q", parsed.Header.Get("Date"))
	}
}

func readEml(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(dir + "/" + name)
	if err != nil {
		t.Fatalf("outbox file %s: %v", name, err)
	}
	return b
}
