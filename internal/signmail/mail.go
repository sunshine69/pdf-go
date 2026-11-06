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
	Text       string
	HTML       string

	// Files are attachments. A delivery message carries the signed document
	// and its receipt; a message with no Files is a plain text/html message.
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

// Build returns the full RFC 822 message: headers, then a multipart/alternative
// body with the text part first and the HTML part second. Every part is
// quoted-printable, so a body with non-ASCII names (Patrick, Müller) survives
// a 7-bit transport.
func (m *Message) Build(date time.Time) []byte {
	// An attachment changes the message's shape: the text/html pair becomes one
	// part of an outer multipart/mixed whose remaining parts are the files. A
	// client that reads the alternative pair must still find it, and a client
	// that reads attachments must find them, and neither may have to guess.
	if len(m.Files) > 0 {
		return m.buildMixed(date)
	}
	if m.HTML == "" {
		return m.buildSinglePart(date)
	}
	id := MessageID(m.EnvelopeID, m.From)
	var b bytes.Buffer
	b.WriteString("From: " + m.From + "\r\n")
	b.WriteString("To: " + m.To + "\r\n")
	b.WriteString("Subject: " + m.Subject + "\r\n")
	b.WriteString("Date: " + HeaderDate(date) + "\r\n")
	b.WriteString("Message-Id: " + id + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"signsrv1\"\r\n")
	b.WriteString("\r\n")
	b.WriteString("--signsrv1\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	b.WriteString(EncodeQP(m.Text))
	b.WriteString("\r\n--signsrv1\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	b.WriteString(EncodeQP(m.HTML))
	b.WriteString("\r\n--signsrv1--\r\n")
	return b.Bytes()
}

// The two boundaries a message with attachments needs.
const (
	altBoundary   = "signsrv1"
	mixedBoundary = "signsrv2"
)

// buildMixed writes a message with attachments: an outer multipart/mixed
// holding the alternative text/html pair, then one base64 part per file.
// Base64 is what attachments require (a PDF is not 7-bit safe) and the encoded
// lines stay under 76 characters so no relay rejects them.
func (m *Message) buildMixed(date time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + m.From + "\r\n")
	b.WriteString("To: " + m.To + "\r\n")
	b.WriteString("Subject: " + m.Subject + "\r\n")
	b.WriteString("Date: " + HeaderDate(date) + "\r\n")
	b.WriteString("Message-Id: " + MessageID(m.EnvelopeID, m.From) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + mixedBoundary + "\"\r\n\r\n")

	// Part 1: the message body, as an alternative pair when there is HTML.
	b.WriteString("--" + mixedBoundary + "\r\n")
	if m.HTML != "" {
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + altBoundary + "\"\r\n\r\n")
		b.WriteString("--" + altBoundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		b.WriteString(EncodeQP(m.Text))
		b.WriteString("\r\n--" + altBoundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		b.WriteString(EncodeQP(m.HTML))
		b.WriteString("\r\n--" + altBoundary + "--\r\n")
	} else {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		b.WriteString(EncodeQP(m.Text))
		b.WriteString("\r\n")
	}

	// The remaining parts: one per attachment.
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

// wrapBase64 encodes bytes as base64 in lines of at most 76 characters, which
// is what MIME asks for and what relays expect to see.
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

func (m *Message) buildSinglePart(date time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + m.From + "\r\n")
	b.WriteString("To: " + m.To + "\r\n")
	b.WriteString("Subject: " + m.Subject + "\r\n")
	b.WriteString("Date: " + HeaderDate(date) + "\r\n")
	b.WriteString("Message-Id: " + MessageID(m.EnvelopeID, m.From) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	b.WriteString(EncodeQP(m.Text))
	b.WriteString("\r\n")
	return b.Bytes()
}

// EncodeQP writes printable ASCII as itself, CR and LF as the line breaks,
// and every other byte as =XX. Lines are kept under 76 characters.
func EncodeQP(s string) string {
	var out strings.Builder
	line := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n':
			out.WriteString("\r\n")
			line = 0
		case c == '\r':
			continue
		case c >= 32 && c <= 126:
			// Printable ASCII is written as itself. A space that ends a line
			// is encoded, because a mail client may strip it.
			if c == ' ' && i+1 < len(s) && s[i+1] == '\n' {
				out.WriteString("=20")
				line += 3
				continue
			}
			out.WriteByte(c)
			line++
		default:
			out.WriteString(fmt.Sprintf("=%02X", c))
			line += 3
		}
		// The soft break goes at a word boundary, so a URL, a SHA-256, and a
		// quoted-printable escape are never split. QP recommends lines under
		// 76 characters; breaking inside a word would corrupt the link, which
		// is the value the message exists to carry.
		if line > 75 && c == ' ' {
			out.WriteString("=\r\n")
			line = 0
		}
	}
	return out.String()
}

// DecodeQP is the inverse, used by the parser and by tests that read a
// quoted-printable body back.
func DecodeQP(s string) string {
	s = strings.ReplaceAll(s, "=\r\n", "")
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '=' && i+2 < len(s) {
			var v int
			if n, _ := fmt.Sscanf(s[i:i+3], "=%02X", &v); n == 1 {
				out.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// FileSender writes each message as an .eml file in a directory. This is the
// dev sender (SIGNSRV_DEV=1), and the test sender. The file is a complete RFC
// 822 message, so any client can open it, which is what makes it usable as
// proof in acceptance.
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

// Parse reads a complete message back. A test uses it to check that a sent
// file is a valid message with the link inside it, rather than grepping a
// string that could appear in any part of the file.
func Parse(raw []byte) (*Message, map[string]string, error) {
	text, html, files, ok := splitMIME(raw)
	if !ok {
		return nil, nil, errors.New("signmail: message has no text body")
	}
	headers, _, _ := parseHeaders(raw)
	if headers["To"] == "" {
		return nil, nil, errors.New("signmail: message has no To header")
	}
	return &Message{
		To:      headers["To"],
		From:    headers["From"],
		Subject: headers["Subject"],
		Text:    strings.TrimSpace(text),
		HTML:    strings.TrimSpace(html),
		Files:   files,
	}, headers, nil
}

// splitHead separates a MIME part into its headers and its RAW body: no
// transfer decoding. parseHeaders decodes quoted-printable, which is right for
// a text body and wrong for a base64 one, so the walker needs the bytes as
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

// splitMIME returns the text/plain and text/html bodies. A single-part
// message has no boundary, so parseHeaders of the whole message finds the
// text body and ok is true.
func splitMIME(raw []byte) (text, html string, files []File, ok bool) {
	// Walk the boundaries rather than splitting on one of them: an attached
	// document nests the alternative pair inside a multipart/mixed, and a single
	// boundary split would see the outer part and miss the bodies.
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
		case strings.HasPrefix(ct, "text/plain"):
			text = DecodeQP(string(body))
			ok = true
		case strings.HasPrefix(ct, "text/html"):
			html = DecodeQP(string(body))
		default:
			// An attachment: base64 bytes, named by the Content-Disposition the
			// builder writes. The body is taken raw — quoted-printable decoding
			// would eat the "=" padding and any "=XX" sequence inside the base64.
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
			files = append(files, File{Name: name, Type: mediaTypeOf(ct), Data: data})
		}
	}
	walk(raw)
	return text, html, files, ok
}

// boundaryOf reads the boundary parameter out of a Content-Type value.
func boundaryOf(ct string) string {
	i := strings.Index(strings.ToLower(ct), "boundary=")
	if i < 0 {
		return ""
	}
	v := strings.Trim(strings.TrimSpace(ct[i+len("boundary="):]), `";`)
	if j := strings.IndexAny(v, "; "); j >= 0 {
		v = v[:j]
	}
	return v
}

// filenameOf reads the filename parameter of a Content-Disposition header.
func filenameOf(cd string) string {
	i := strings.Index(strings.ToLower(cd), "filename=")
	if i < 0 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(cd[i+len("filename="):]), `";`)
}

// mediaTypeOf drops the parameters from a Content-Type value.
func mediaTypeOf(ct string) string {
	if i := strings.IndexAny(ct, ";"); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return strings.TrimSpace(ct)
}

// parseHeaders reads the header block of a message or a MIME part.
func parseHeaders(raw []byte) (map[string]string, string, bool) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, "", false
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
	return h, DecodeQP(string(raw[i+4:])), true
}

func lastIndex(m map[string]string) string {
	var s string
	for k := range m {
		s = k
	}
	return s
}

// MaxBodyBytes is the cap on a rendered body, so a long document title cannot
// make a message the size of a PDF.
const MaxBodyBytes = 16000

var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// ValidAddress is the check applied before sending.
func ValidAddress(a string) bool { return emailRe.MatchString(a) }

// BackoffFor is the delay after an attempt: 1 minute, 5, 15, 1 hour. The
// fifth attempt is the last, so its backoff is never used.
func BackoffFor(attempt int) time.Duration {
	switch attempt {
	case 0:
		return time.Minute
	case 1:
		return 5 * time.Minute
	case 2:
		return 15 * time.Minute
	default:
		return time.Hour
	}
}

// MaxAttempts is the number of sends per message. After the fifth failure the
// row is given up, not retried.
const MaxAttempts = 5
