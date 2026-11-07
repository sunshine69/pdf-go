package signmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Message is one email the service sends. It is plain data, so the worker can
// build it from the queue row and hand it to any sender.
type Message struct {
	Kind       string // invite, reminder, cancelled, signed
	EnvelopeID string
	PartyID    string
	To         string
	From       string
	Subject    string
	Text       string // the plaintext view, kept as the fallback body
	HTML       string

	// Files are attachments. A delivery message carries the signed document
	// and its receipt; a message with no Files is a one-part message.
	Files []File
}

// File is one attachment. The bytes are the bytes Gate 2 verified: what was
// verified is what is sent, from the same read.
type File struct {
	Name string
	Type string // media type, e.g. application/pdf
	Data []byte
}

// Sender delivers one message. Two implementations: SMTP for production,
// and a file sender for development, which is also the proof used in tests.
type Sender interface {
	Send(ctx context.Context, m *Message) error
}

// MessageID builds the header value: 16 random hex characters, the envelope
// id, and the sender host. The envelope id inside makes the message traceable
// to the envelope when a signer replies.
func MessageID(envID, from string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "<" + envID + "@" + HostOf(from) + ">"
	}
	return "<" + hex.EncodeToString(b[:]) + "-" + envID + "@" + HostOf(from) + ">"
}

// HostOf is the domain part of an address, used as the Message-Id host.
func HostOf(addr string) string {
	if i := strings.Index(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return "localhost"
}

// RFC1123 formats the Date header the way the standard requires: UTC,
// no padding, two-digit day.
func RFC1123(t time.Time) string {
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000")
}

// HeaderDate is the Date header value. The clock is passed in so a test can
// assert the exact string.
func HeaderDate(t time.Time) string { return RFC1123(t) }

// Build returns the full RFC 822 message: the headers, a blank line, then the
// body. The body is one text/html part written as itself, with
// Content-Transfer-Encoding: 8bit.
//
// The body carries no transfer encoding on purpose. A quoted-printable body
// must keep its lines under 76 characters and ends a long line with a soft
// break, an "=" at the end of the line. A signing link is 95 characters of
// unbroken text inside an href, so a soft break lands inside the value, and a
// client that does not undo it shows the signer a link with an "=" in it — the
// exact failure this mail exists to avoid, because the link is the only thing
// in the message a signer has to get right. 8bit is in the MIME standard, is
// accepted by every relay, and adds no characters to the body.
//
// A message with attachments is a multipart/mixed: the text/html part, then one
// base64 part per file. Base64 is what attachments require — a PDF is not
// printable ASCII — and the encoded lines stay under 76 characters so no relay
// rejects them.
func (m *Message) Build(date time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + m.From + "\r\n")
	b.WriteString("To: " + m.To + "\r\n")
	b.WriteString("Subject: " + EncodeSubject(m.Subject) + "\r\n")
	b.WriteString("Date: " + HeaderDate(date) + "\r\n")
	b.WriteString("Message-Id: " + MessageID(m.EnvelopeID, m.From) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	if len(m.Files) == 0 {
		b.WriteString("Content-Type: " + bodyContentType(m) + "\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
		b.WriteString("\r\n")
		b.WriteString(bodyText(m))
		b.WriteString("\r\n")
		return b.Bytes()
	}
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + mixedBoundary + "\"\r\n\r\n")
	b.WriteString("--" + mixedBoundary + "\r\n")
	b.WriteString("Content-Type: " + bodyContentType(m) + "\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(bodyText(m))
	b.WriteString("\r\n")
	for _, f := range m.Files {
		name := sanitizeFilename(f.Name)
		ct := f.Type
		if ct == "" {
			ct = "application/octet-stream"
		}
		b.WriteString("--" + mixedBoundary + "\r\n")
		b.WriteString("Content-Type: " + ct + "; name=\"" + name + "\"\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-Disposition: attachment; filename=\"" + name + "\"\r\n\r\n")
		b.WriteString(wrapBase64(f.Data))
		b.WriteString("\r\n")
	}
	b.WriteString("--" + mixedBoundary + "--\r\n")
	return b.Bytes()
}

// bodyContentType is the Content-Type of the single body part: an HTML body is
// sent as text/html, because that is the part a mail client renders as a link
// the signer can tap. A message with no HTML body (a reminder, a cancellation,
// the signed copy) is sent as the text, as text/plain.
func bodyContentType(m *Message) string {
	if m.HTML != "" {
		return htmlContentType
	}
	return textContentType
}

// bodyText is the body itself, written as itself with no transfer encoding.
func bodyText(m *Message) string {
	if m.HTML != "" {
		return m.HTML
	}
	return m.Text
}

const (
	htmlContentType = "text/html; charset=utf-8"
	textContentType = "text/plain; charset=utf-8"
	mixedBoundary   = "signsrv2"
)

// wrapBase64 writes base64 in lines of 76 characters, as MIME asks.
func wrapBase64(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		out.WriteString(enc[i:end])
		out.WriteString("\r\n")
	}
	return out.String()
}

// sanitizeFilename keeps a file name to characters that cannot carry a header
// break or a path: the name comes from a document title, which is user data,
// and a header is not a place user data gets to run.
func sanitizeFilename(name string) string {
	if name == "" {
		return "attachment"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == ' ':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "attachment"
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

// EncodeSubject returns a Subject header field that a mail client reads back
// whole. A subject that is printable ASCII with no embedded newline is already
// a valid field and is written as itself. Anything else — a non-ASCII character
// from a name like Patrick or Müller, a character a caller did not sanitize —
// becomes the base64 form the standard defines, =?UTF-8?B?...?=, so no
// character in a header can end the field. A header field is not a place user
// data gets to run.
func EncodeSubject(s string) string {
	if isSafeHeader(s) {
		return s
	}
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
}

// isSafeHeader reports whether a string can be a header value as it is:
// printable ASCII, and no line break in any form.
func isSafeHeader(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

// FileSender writes the message to a file, for dev mode and for tests.
type FileSender struct {
	Dir string
}

// Send writes {kind}-{envelope}-{party}.eml. The name carries the three
// identifiers so a test can find the invite for one party without parsing.
func (f *FileSender) Send(ctx context.Context, m *Message) error {
	if f.Dir == "" {
		return errors.New("signmail: file sender has no directory")
	}
	if err := os.MkdirAll(f.Dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s-%s.eml", m.Kind, m.EnvelopeID, m.PartyID)
	return os.WriteFile(filepath.Join(f.Dir, name), m.Build(time.Now()), 0o640)
}

// SMTPSender sends over a real SMTP server, with STARTTLS when the server
// supports it. Port 25 is the one case where STARTTLS is skipped: a mail relay
// on the loopback interface is the standard development setup, and it has no
// TLS.
// The SMTP time budgets, from the design: 15s to connect, 30s to write. A
// relay that is down or slow is a failure to record in the queue, not a
// stalled worker.
const (
	dialTimeout  = 15 * time.Second
	writeTimeout = 30 * time.Second
)

type SMTPSender struct {
	Host     string
	Port     int
	StartTLS bool
	User     string
	Password string
}

// Send connects, upgrades, authenticates when credentials are given, and
// writes the message.
func (s *SMTPSender) Send(ctx context.Context, m *Message) error {
	if s.Host == "" {
		return errors.New("signmail: smtp host is empty")
	}
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	// The dial gets its own deadline: a host that does not answer must not
	// hold the worker. 15s is enough for a relay on the local network and
	// short enough that one dead host cannot stall the queue.
	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	defer cancelDial()
	uc, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("signmail: dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(uc, s.Host)
	if err != nil {
		uc.Close()
		return fmt.Errorf("signmail: handshake with %s: %w", addr, err)
	}
	defer c.Close()

	// A dial that already landed in TLS (port 465) needs no upgrade; port 25
	// on a loopback relay is the one case where STARTTLS is skipped.
	_, isTLS := c.TLSConnectionState()
	tlsNeeded := s.StartTLS && s.Port != 25 && !isTLS
	if tlsNeeded {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
			return fmt.Errorf("signmail: starttls: %w", err)
		}
	}
	if s.User != "" {
		// PLAIN sends the credentials in one base64 line, and net/smtp will
		// only do it over TLS. LOGIN is the challenge-response form most
		// relays advertise, so it is used when the connection is not
		// encrypted; PLAIN is used when it is.
		var auth smtp.Auth
		_, tlsOn := c.TLSConnectionState()
		if tlsOn {
			auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
		} else {
			auth = LoginAuth(s.User, s.Password)
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("signmail: auth: %w", err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("signmail: envelope-from: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return fmt.Errorf("signmail: rcpt %s: %w", m.To, err)
	}
	// The write gets its own deadline, so a relay that accepts the envelope
	// and then stops reading cannot hold the connection.
	if err := uc.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("signmail: write deadline: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("signmail: data: %w", err)
	}
	if _, err := w.Write(m.Build(time.Now())); err != nil {
		return err
	}
	return w.Close()
}

// Parse reads a complete message back. A test uses it to check that a sent file
// is a valid message with the link inside it, rather than grepping a string
// that could appear in any part of the file.
func Parse(raw []byte) (*Message, map[string]string, error) {
	headers, _, ok := parseHeaders(raw)
	if !ok {
		return nil, nil, errors.New("signmail: message has no header/body separator")
	}
	text, html, files, ok := splitMIME(raw)
	if !ok {
		return nil, nil, errors.New("signmail: message body is not text")
	}
	return &Message{
		To:      headers["To"],
		From:    headers["From"],
		Subject: DecodeSubject(headers["Subject"]),
		HTML:    strings.TrimSpace(html),
		Text:    strings.TrimSpace(text),
		Files:   files,
	}, headers, nil
}

// DecodeSubject is the inverse of EncodeSubject: the base64 form is decoded,
// anything else is returned as it is.
func DecodeSubject(v string) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "=?UTF-8?B?") || !strings.HasSuffix(v, "?=") {
		return v
	}
	enc := v[len("=?UTF-8?B?") : len(v)-len("?=")]
	if raw, err := base64.StdEncoding.DecodeString(enc); err == nil {
		return string(raw)
	}
	return v
}

// splitHead separates a MIME part into its headers and its RAW body: no
// transfer decoding. parseHeaders decodes a transfer encoding, which is right
// for a text body and wrong for a base64 one, so the walker needs the bytes as
// they were written.
func splitHead(raw []byte) (map[string]string, []byte, bool) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, nil, false
	}
	h := map[string]string{}
	for _, line := range strings.Split(string(raw[:i]), "\r\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, " ") {
			if len(h) > 0 {
				last := lastIndex(h)
				h[last] += strings.TrimSpace(line)
			}
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		h[textproto.CanonicalMIMEHeaderKey(k)] = strings.TrimSpace(v)
	}
	return h, raw[i+4:], true
}

// splitMIME returns the text/html body, the plain text when the message carries
// one, and any attachments. A single-part message has no boundary, so
// parseHeaders of the whole message finds the body and ok is true.
func splitMIME(raw []byte) (text, html string, files []File, ok bool) {
	// Walk the boundaries rather than splitting on one of them: an attached
	// document nests the body part inside a multipart/mixed, and a single
	// boundary split would see the outer part and miss the body.
	var walk func(part []byte)
	walk = func(part []byte) {
		h, body, found := splitHead(part)
		if !found {
			return
		}
		ct := strings.ToLower(h["Content-Type"])
		switch {
		case strings.HasPrefix(ct, "multipart/"):
			boundary := boundaryOf(h["Content-Type"])
			if boundary == "" {
				return
			}
			for _, sub := range strings.Split(string(body), "--"+boundary) {
				walk([]byte(sub))
			}
		case strings.HasPrefix(ct, "text/html"):
			html = string(body)
			ok = true
		case strings.HasPrefix(ct, "text/plain"):
			text = string(body)
			ok = true
		default:
			// An attachment: base64 bytes, named by the Content-Disposition the
			// builder writes. The body is taken raw — decoding a transfer
			// encoding would eat the "=" padding and any "=XX" sequence inside
			// the base64.
			name := filenameOf(h["Content-Disposition"])
			if name == "" || !strings.EqualFold(strings.TrimSpace(h["Content-Transfer-Encoding"]), "base64") {
				return
			}
			// The builder wraps base64 at 76 characters, as MIME asks; the line
			// breaks are not part of the payload.
			payload := strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, string(body))
			data, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return
			}
			files = append(files, File{Name: name, Type: mediaTypeOf(h["Content-Type"]), Data: data})
		}
	}
	walk(raw)
	return text, html, files, ok
}

// boundaryOf is the boundary parameter of a multipart Content-Type.
func boundaryOf(ct string) string {
	for _, p := range strings.Split(ct, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || k != "boundary" {
			continue
		}
		return strings.Trim(strings.TrimSpace(v), `"`)
	}
	return ""
}

// filenameOf is the filename parameter of a Content-Disposition.
func filenameOf(cd string) string {
	for _, p := range strings.Split(cd, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || (k != "filename" && k != "name") {
			continue
		}
		return strings.Trim(strings.TrimSpace(v), `"`)
	}
	return ""
}

// mediaTypeOf is the type of a Content-Type, without its parameters.
func mediaTypeOf(ct string) string {
	k, _, _ := strings.Cut(strings.TrimSpace(ct), ";")
	return strings.TrimSpace(k)
}

func parseHeaders(raw []byte) (map[string]string, string, bool) {
	h, body, ok := splitHead(raw)
	if !ok {
		return nil, "", false
	}
	text := string(body)
	if strings.EqualFold(strings.TrimSpace(h["Content-Transfer-Encoding"]), "base64") {
		payload := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, text)
		if raw, err := base64.StdEncoding.DecodeString(payload); err == nil {
			text = string(raw)
		}
	}
	return h, text, true
}

func lastIndex(m map[string]string) string {
	var last string
	for k := range m {
		last = k
	}
	return last
}

// MaxBodyBytes is the cap on a rendered body, so a long document title cannot
// make the service build a message of any size.
const MaxBodyBytes = 16000

var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// ValidAddress is the address check the queue and the API share.
func ValidAddress(a string) bool { return emailRe.MatchString(a) }

// BackoffFor is the delay before the next attempt for one message: 1, 5, 30,
// 120 minutes. The table is short because a relay that is down for two hours is
// an outage, not a queue to keep working through.
func BackoffFor(attempt int) time.Duration {
	switch attempt {
	case 0:
		return time.Minute
	case 1:
		return 5 * time.Minute
	case 2:
		return 30 * time.Minute
	default:
		return 120 * time.Minute
	}
}

// MaxAttempts is the number of deliveries tried for one message before the row
// is recorded as failed.
const MaxAttempts = 5
