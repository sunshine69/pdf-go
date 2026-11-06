package signstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// The states of one party's delivery. accepted means the transport took a
// message whose bytes passed Gate 2; refused means Gate 2 stopped it; pending
// means it is queued but has not been attempted.
const (
	DeliveryPending  = "pending"
	DeliveryAccepted = "accepted"
	DeliveryRefused  = "refused"
)

// Delivery is one party's copy of the finished document. One row per
// (envelope, party): a re-run of a delivery updates the row it already has,
// so the table describes the current state of delivery rather than a history
// of attempts, and "is this envelope delivered?" is one query.
type Delivery struct {
	EnvelopeID  string
	PartyID     string
	SHA256      string
	Bytes       int64
	VerifiedAt  string
	Verified    bool
	Method      string // "attach" or "link"
	DownloadID  string // the random token, when Method is link
	UntilAt     string // link expiry
	DeliveredAt string
	Status      string
	LastError   string
}

// Download is one large-document link: a random token, stored only as its
// hash, pointing at one document for one party, with an expiry.
type Download struct {
	TokenHash  string
	EnvelopeID string
	PartyID    string
	SHA256     string
	ExpiresAt  string
	CreatedAt  string
}

// deliveryInsertCols are the columns UpsertDelivery writes, in the order the
// placeholders are bound. These are column names, so no expression may appear
// here: an insert statement cannot name coalesce(x, ”) as a column.
const deliveryInsertCols = "envelope_id, party_id, sha256, bytes, verified_at, verified," +
	" delivery_method, download_token, download_until, delivered_at, delivery_status, last_error"

// deliverySelectCols is the same list read back. The four optional text columns
// collapse to "" so the scan does not need a null wrapper per column.
const deliverySelectCols = "envelope_id, party_id, sha256, bytes, verified_at, verified," +
	" delivery_method, coalesce(download_token, ''), coalesce(download_until, '')," +
	" coalesce(delivered_at, ''), delivery_status, coalesce(last_error, '')"

// deliverySelectColsD is deliverySelectCols qualified with the alias d, which
// ListDeliveries needs because it joins parties for the ordering.
const deliverySelectColsD = "d.envelope_id, d.party_id, d.sha256, d.bytes, d.verified_at, d.verified," +
	" d.delivery_method, coalesce(d.download_token, ''), coalesce(d.download_until, '')," +
	" coalesce(d.delivered_at, ''), d.delivery_status, coalesce(d.last_error, '')"

// UpsertDelivery writes (or rewrites) one party's delivery record. The
// envelope column is checked against the parties table by the foreign key, so
// a delivery row cannot be written for a party that does not exist.
func (s *Store) UpsertDelivery(ctx context.Context, d *Delivery) error {
	if d == nil || d.EnvelopeID == "" || d.PartyID == "" {
		return errors.New("signstore: delivery needs an envelope and a party")
	}
	if !strings.HasPrefix(d.Status, "pending") && !strings.HasPrefix(d.Status, "accepted") &&
		!strings.HasPrefix(d.Status, "refused") {
		return errors.New("signstore: unknown delivery status")
	}
	_, err := s.db.ExecContext(ctx,
		`insert into deliveries(`+deliveryInsertCols+`)
		 values(?,?,?,?,?,?,?,?,?,?,?,?)
		 on conflict(envelope_id, party_id) do update set
		   sha256 = excluded.sha256,
		   bytes = excluded.bytes,
		   verified_at = excluded.verified_at,
		   verified = excluded.verified,
		   delivery_method = excluded.delivery_method,
		   download_token = excluded.download_token,
		   download_until = excluded.download_until,
		   delivered_at = excluded.delivered_at,
		   delivery_status = excluded.delivery_status,
		   last_error = excluded.last_error`,
		d.EnvelopeID, d.PartyID, d.SHA256, d.Bytes, d.VerifiedAt, boolInt(d.Verified),
		d.Method, emptyToNull(d.DownloadID), emptyToNull(d.UntilAt), emptyToNull(d.DeliveredAt),
		d.Status, truncate(d.LastError, 400))
	return err
}

func scanDelivery(row interface{ Scan(...any) error }) (*Delivery, error) {
	var d Delivery
	err := row.Scan(&d.EnvelopeID, &d.PartyID, &d.SHA256, &d.Bytes, &d.VerifiedAt,
		&d.Verified, &d.Method, &d.DownloadID, &d.UntilAt, &d.DeliveredAt, &d.Status, &d.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// GetDelivery reads one party's delivery record.
func (s *Store) GetDelivery(ctx context.Context, envelopeID, partyID string) (*Delivery, error) {
	row := s.db.QueryRowContext(ctx, "select "+deliverySelectCols+" from deliveries"+
		" where envelope_id = ? and party_id = ?", envelopeID, partyID)
	return scanDelivery(row)
}

// ListDeliveries returns every party's delivery record for one envelope, in
// party order, so a report reads the same order the signatures were applied in.
func (s *Store) ListDeliveries(ctx context.Context, envelopeID string) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx,
		`select `+deliverySelectColsD+` from deliveries d
		 join parties p on p.id = d.party_id
		 where d.envelope_id = ? order by p.order_idx`, envelopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// CountDeliveries reports how many parties of an envelope have an accepted
// delivery and how many parties the envelope has. The envelope reaches
// delivered when the two numbers are equal and non-zero.
func (s *Store) CountDeliveries(ctx context.Context, envelopeID string) (accepted, parties int, err error) {
	err = s.db.QueryRowContext(ctx,
		`select
		   (select count(*) from deliveries where envelope_id = ? and delivery_status = 'accepted'),
		   (select count(*) from parties where envelope_id = ?)`,
		envelopeID, envelopeID).Scan(&accepted, &parties)
	return accepted, parties, err
}

// CreateDownload stores one large-document link. The token itself is not
// stored; only its hash is, so a database dump cannot hand out live links.
func (s *Store) CreateDownload(ctx context.Context, d *Download) error {
	if d == nil || d.TokenHash == "" || d.SHA256 == "" {
		return errors.New("signstore: a download needs a token hash and a document hash")
	}
	_, err := s.db.ExecContext(ctx,
		`insert into downloads(token_hash, envelope_id, party_id, sha256, expires_at, created_at)
		 values(?,?,?,?,?,?)
		 on conflict(token_hash) do update set
		   envelope_id = excluded.envelope_id, party_id = excluded.party_id,
		   sha256 = excluded.sha256, expires_at = excluded.expires_at`,
		d.TokenHash, d.EnvelopeID, d.PartyID, d.SHA256, d.ExpiresAt, d.CreatedAt)
	return err
}

// GetDownload resolves a token hash to its document. An expired row is not
// returned: the caller answers 410, and the row is removed by Sweep.
func (s *Store) GetDownload(ctx context.Context, tokenHash string) (*Download, error) {
	var d Download
	err := s.db.QueryRowContext(ctx,
		`select token_hash, envelope_id, party_id, sha256, expires_at, created_at
		 from downloads where token_hash = ?`, tokenHash).
		Scan(&d.TokenHash, &d.EnvelopeID, &d.PartyID, &d.SHA256, &d.ExpiresAt, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// DeleteExpiredDownloads drops every link whose expiry has passed, and reports
// how many. It is the sweep's job, not a request handler's: a handler that
// deletes on read lets a probe decide what the storage keeps.
func (s *Store) DeleteExpiredDownloads(ctx context.Context, now string) (int, error) {
	res, err := s.db.ExecContext(ctx, "delete from downloads where expires_at < ?", now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DeleteDelivery drops a party's delivery record. A reissue hands out a new
// link, and a record of a copy already sent would claim the new link had been
// delivered too, so the record goes with the link it described.
func (s *Store) DeleteDelivery(ctx context.Context, envelopeID, partyID string) error {
	_, err := s.db.ExecContext(ctx, "delete from deliveries where envelope_id = ? and party_id = ?",
		envelopeID, partyID)
	if err != nil {
		return fmt.Errorf("signstore: delete delivery: %w", err)
	}
	return nil
}

// ListUndeliveredParties returns the parties of a completed envelope whose copy
// has not been accepted. Delivery stopped for them — a transport failure, or a
// process that exited mid-run — and they are the ones a later pass has to reach.
func (s *Store) ListUndeliveredParties(ctx context.Context, envelopeID string) ([]Party, error) {
	rows, err := s.db.QueryContext(ctx,
		"select p."+partyCols+" from parties p"+
			" left join deliveries d on d.party_id = p.id"+
			" where p.envelope_id = ? and (d.id is null or d.status <> 'accepted')"+
			" order by p.order_idx, p.id", envelopeID)
	if err != nil {
		return nil, fmt.Errorf("signstore: list undelivered parties: %w", err)
	}
	defer rows.Close()
	out := []Party{}
	for rows.Next() {
		var p Party
		if err := scanRow(rows, &p.ID, &p.EnvelopeID, &p.OrderIdx, &p.Email, &p.Name, &p.Status,
			&p.TokenHash, &p.TokenExpires, &p.ClaimAt, &p.ConsentAt, &p.DeliveredAt,
			&p.SessionHash, &p.Reason); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPartyDeliveredAt stamps the moment one party's copy was accepted. The
// column is written only from the delivery path, so "delivered" in the party
// row always means an accepted copy, never a queued one.
func (s *Store) SetPartyDeliveredAt(ctx context.Context, partyID, at string) error {
	res, err := s.db.ExecContext(ctx, "update parties set delivered_at = ? where id = ?", at, partyID)
	if err != nil {
		return fmt.Errorf("signstore: set party delivered_at: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("signstore: party %q: %w", partyID, ErrNotFound)
	}
	return nil
}

// SetEnvelopeDeliveredAt stamps the envelope once every party's copy is
// accepted. It is a separate statement from the status transition so a status
// can never claim delivered without the stamp behind it.
func (s *Store) SetEnvelopeDeliveredAt(ctx context.Context, envelopeID, at string) error {
	res, err := s.db.ExecContext(ctx, "update envelopes set delivered_at = ? where id = ?", at, envelopeID)
	if err != nil {
		return fmt.Errorf("signstore: set envelope delivered_at: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("signstore: envelope %q: %w", envelopeID, ErrNotFound)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func emptyToNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}
