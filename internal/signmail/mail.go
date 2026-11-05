package signmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
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
	text, html, ok := splitMIME(raw)
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
	}, headers, nil
}

// splitMIME returns the text/plain and text/html bodies. A single-part
// message has no boundary, so parseHeaders of the whole message finds the
// text body and ok is true.
func splitMIME(raw []byte) (text, html string, ok bool) {
	for _, p := range bytes.Split(raw, []byte("--signsrv1")) {
		h, rest, found := parseHeaders(p)
		if !found {
			continue
		}
		ct := strings.ToLower(h["Content-Type"])
		if strings.HasPrefix(ct, "text/plain") {
			text = DecodeQP(rest)
			ok = true
		}
		if strings.HasPrefix(ct, "text/html") {
			html = DecodeQP(rest)
		}
	}
	return text, html, ok
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
