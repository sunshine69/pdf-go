package signstore

import "time"

// Time format used in every timestamp column: RFC 3339 with seconds, in UTC.
// Lexical order of these strings is chronological, which is what the sweeps
// and the ORDER BY clauses rely on.
const timeFormat = "2006-01-02T15:04:05Z"

func timeNow() string { return time.Now().UTC().Format(timeFormat) }

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

// parseTime is used by the store to accept both the stored format and any
// RFC 3339 value, so a hand-edited row never crashes a read.
func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

// EnvelopeStatus is the lifecycle of a document. The transitions between them
// are owned by internal/signflow; signstore only refuses values outside the
// vocabulary.
type EnvelopeStatus string

const (
	StatusDraft      EnvelopeStatus = "draft"
	StatusReady      EnvelopeStatus = "ready"
	StatusSent       EnvelopeStatus = "sent"
	StatusCollecting EnvelopeStatus = "collecting"
	StatusSigned     EnvelopeStatus = "signed"
	StatusCompleted  EnvelopeStatus = "completed"
	StatusDelivered  EnvelopeStatus = "delivered"
	StatusExpired    EnvelopeStatus = "expired"
	StatusCancelled  EnvelopeStatus = "cancelled"
	StatusFailed     EnvelopeStatus = "failed"
)

// ValidStatus reports whether a string is one of the envelope statuses. The
// API uses it to answer 400 on a filter value that is not in the vocabulary,
// so a typo in a query string is a named error, not an empty result.
func ValidStatus(s string) bool { return EnvelopeStatus(s).valid() }

func (s EnvelopeStatus) valid() bool {
	switch s {
	case StatusDraft, StatusReady, StatusSent, StatusCollecting, StatusSigned,
		StatusCompleted, StatusDelivered, StatusExpired, StatusCancelled, StatusFailed:
		return true
	}
	return false
}

// Terminal reports whether no transition is possible from this status.
func (s EnvelopeStatus) Terminal() bool {
	switch s {
	case StatusDelivered, StatusExpired, StatusCancelled, StatusFailed:
		return true
	}
	return false
}

// PartyStatus is the lifecycle of one signing party.
type PartyStatus string

const (
	PartyInvited   PartyStatus = "invited"
	PartyClaimed   PartyStatus = "claimed"
	PartyConsented PartyStatus = "consented"
	PartyDeclined  PartyStatus = "declined"
	PartyExpired   PartyStatus = "expired"
)

func (s PartyStatus) valid() bool {
	switch s {
	case PartyInvited, PartyClaimed, PartyConsented, PartyDeclined, PartyExpired:
		return true
	}
	return false
}

// Revision kinds. A template is the uploaded original; filled is the
// template with the form written; certified is the filled document carrying
// the certification signature; signed-N is the document after party N's
// signature was added by the signing batch.
const (
	KindTemplate   = "template"
	KindFilled     = "filled"
	KindCertified  = "certified"
	KindSignedPref = "signed-"
)

// Mail kinds.
const (
	MailInvite   = "invite"
	MailReminder = "reminder"
	MailCancel   = "cancel"
	MailDelivery = "delivery"
)

// Envelope is a row of the envelopes table.
type Envelope struct {
	ID          string
	Title       string
	Status      EnvelopeStatus
	TemplateSHA string
	FilledSHA   string
	CurrentSHA  string
	Serial      string // certification certificate serial
	CreatedBy   int64
	CreatedAt   string
	UpdatedAt   string
	ExpiresAt   string
	SentAt      string
	DeliveredAt string
	CancelledAt string

	// NotifyEmail is the drafter's address: who to tell when a party declines or
	// when an invitation can never be delivered. Empty means nobody asked to be
	// told, and every envelope created before schema 6 is empty.
	NotifyEmail string

	// Widget is where the party signatures go. Every zero value means "the
	// service chooses", which is what every envelope created before schema 7
	// means: page 1, bottom-left column. The batch reads these and passes them
	// to the signing service; before this they were recorded in the created
	// event and then thrown away.
	WidgetField string
	WidgetPage  int64
	WidgetX     float64
	WidgetY     float64
}

// Party is a row of the parties table.
type Party struct {
	ID           string
	EnvelopeID   string
	OrderIdx     int
	Email        string
	Name         string
	Status       PartyStatus
	TokenHash    string
	TokenExpires string
	ClaimAt      string
	ConsentAt    string
	DeliveredAt  string
	SessionHash  string
	Reason       string
}

// Revision is a row of the revisions table. SHA-256 of the bytes, and the
// content-addressed file name in storage, are the same string.
type Revision struct {
	ID              string
	EnvelopeID      string
	SHA256          string
	PrevID          string
	Kind            string
	SigField        string
	PartyID         string
	CertSerial      string
	CertFingerprint string
	ProducedBy      string
	Size            int64
	CreatedAt       string
}

// Consent is a row of the consents table: what the party agreed to, and the
// evidence that they did.
type Consent struct {
	ID            string
	PartyID       string
	EnvelopeID    string
	SignatureText string
	DocumentSHA   string
	ImageSHA      string
	Appearance    string // JSON of the appearance options
	ConsentAt     string
	IP            string
	UserAgent     string
}

// Admin is a row of the admins table. pw_hash is an argon2id encoding.
type Admin struct {
	ID        int64
	Email     string
	PWHash    string
	Role      string
	CreatedAt string
	LastLogin string
}

// Client is a machine API client. KeyHash is a SHA-256 of the issued key.
type Client struct {
	ID        int64
	Name      string
	KeyHash   string
	Scopes    string
	CreatedAt string
	RevokedAt string
}

// Event is one entry of the audit trail.
type Event struct {
	ID         int64
	EnvelopeID string
	Actor      string
	Kind       string
	Payload    string
	CreatedAt  string
}

// MailItem is one entry of the mail queue.
type MailItem struct {
	ID         int64
	EnvelopeID string
	PartyID    string
	Kind       string
	SHA256     string
	Attempts   int
	NextAt     string
	LeaseUntil string
	SentAt     string
	LastError  string

	// Recipient is the address this row goes to, when that is not the party
	// named by PartyID: the drafter's notices. Empty means the party row.
	Recipient string
	// Detail is the text the message explains — the SMTP rejection an
	// invitation got. It is separate from LastError because LastError belongs
	// to this row's own delivery attempts.
	Detail string
}

// BatchItem is the pending signing batch of an envelope.
type BatchItem struct {
	EnvelopeID string
	Attempts   int
	NextAt     string
	LeaseUntil string
	EnqueuedAt string
}
