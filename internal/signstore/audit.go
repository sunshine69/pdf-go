package signstore

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The audit trail. The events table is append-only inside the process, and this
// file makes that visible from outside: each day's events are appended to a
// file, and every line carries the hash of the line before it.
//
// Verification has two halves, and they catch different attacks:
//
//   - The hash chain: a line removed, reordered, or edited inside a file stops
//     verifying, because prev_hash no longer matches.
//   - The cross-check against the events table, which is what the log is built
//     from. The table is append-only, so a row cannot be changed quietly. A line
//     edited *and rehashed* is invisible to the chain — the chain's tail is its
//     own anchor — so the chain alone is not enough, and this check is what sees
//     it.
//
// AuditWrite runs the chain check before appending, so a nightly job never
// extends a log that already fails to verify. It does not require the log to be
// up to date: lagging the table is the normal state between two runs.
//
// The chain is not a signature. It is tamper evidence for a file an operator can
// read. The keys in step 04 are what give signatures their force; this is what
// makes the audit log trustworthy as a record.
const (
	// AuditDay is the date layout the audit files are named with.
	AuditDay = "2006-01-02"
	// MaxAuditLine bounds a line of the audit file. A payload longer than this
	// is refused at write time, and the reader never allocates past it.
	MaxAuditLine = 1 << 20
)

// AuditLine is one line of an audit file. The payload is kept as the raw JSON
// bytes so a re-marshaled line reproduces them exactly: that is what makes the
// stored hash reproducible without canonicalising the payload.
type AuditLine struct {
	ID        int64           `json:"id"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
	Envelope  string          `json:"envelope_id"`
	Actor     string          `json:"actor"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
}

// AuditPath is the audit file for a day.
func AuditPath(dir, day string) string { return filepath.Join(dir, day+".jsonl") }

// auditHash is the line's own content hash: the fields joined by newlines, over
// the payload's raw bytes. SHA-256, lowercase hex.
func auditHash(l *AuditLine) string {
	sum := sha256.Sum256([]byte(l.Envelope + "\n" + l.Actor + "\n" + l.Kind + "\n" +
		l.CreatedAt + "\n" + string(l.Payload)))
	return hex.EncodeToString(sum[:])
}

// auditFiles lists the audit files in date order. Files are named by date, so
// lexical order is chronological order.
func auditFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

// auditChainCheck walks the audit files in date order and checks every line: its
// hash matches its content, its prev_hash matches the line before it, its id is
// after the line before it, and it matches the events table row with the same
// id. It returns the number of lines checked and the id of the last one, which
// is where the writer continues from. A directory that does not exist checks
// clean.
func auditChainCheck(db *sql.DB, dir string) (count int, lastID int64, err error) {
	files, err := auditFiles(dir)
	if err != nil {
		return 0, 0, err
	}
	var firstID int64
	if err := db.QueryRow("select coalesce(min(id), 0) from events").Scan(&firstID); err != nil {
		return 0, 0, err
	}
	var prev string
	for _, f := range files {
		in, err := os.Open(f)
		if err != nil {
			return count, lastID, err
		}
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 0, 64<<10), MaxAuditLine)
		n := 0
		for sc.Scan() {
			n++
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if len(line) > MaxAuditLine {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d exceeds %d bytes", f, n, MaxAuditLine)
			}
			var l AuditLine
			if err := json.Unmarshal([]byte(line), &l); err != nil {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d is not JSON", f, n)
			}
			if l.Hash != auditHash(&l) {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d: hash %s does not match content %s",
					f, n, l.Hash, auditHash(&l))
			}
			if l.PrevHash != prev {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d: prev_hash %q, expected %q (chain break)",
					f, n, l.PrevHash, prev)
			}
			// The events table's ids are contiguous: the rowid increases by one
			// per insert, and nothing is ever deleted. So a line whose id skips
			// ahead is a deleted event. Re-linking prev_hash and rehashing the
			// line after a deletion leaves a chain that is internally valid, ids
			// increasing, and every remaining line matching the table — this is
			// the check that sees it.
			if count == 0 {
				if l.ID != firstID {
					in.Close()
					return count, lastID, fmt.Errorf("audit: %s line %d: the log starts at id %d, "+
						"the events table starts at %d (events missing)", f, n, l.ID, firstID)
				}
			} else if l.ID != lastID+1 {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d: id %d, expected %d (events missing)",
					f, n, l.ID, lastID+1)
			}
			var rowID int64
			var envelope, actor, kind, payload, createdAt string
			qerr := db.QueryRow("select id, coalesce(envelope_id, ''), actor, kind, payload, created_at"+
				" from events where id = ?", l.ID).
				Scan(&rowID, &envelope, &actor, &kind, &payload, &createdAt)
			if qerr == sql.ErrNoRows {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d: event %d is not in the events table"+
					" (the table is append-only, so a missing row means the file is not the log)", f, n, l.ID)
			}
			if qerr != nil {
				in.Close()
				return count, lastID, qerr
			}
			if envelope != l.Envelope || actor != l.Actor || kind != l.Kind ||
				payload != string(l.Payload) || createdAt != l.CreatedAt {
				in.Close()
				return count, lastID, fmt.Errorf("audit: %s line %d: event %d is recorded as %s/%s/%s %s,"+
					" the events table says %s/%s/%s %s", f, n, l.ID,
					l.Envelope, l.Actor, l.Kind, string(l.Payload),
					envelope, actor, kind, payload)
			}
			prev, lastID = l.Hash, l.ID
			count++
		}
		if err := sc.Err(); err != nil {
			in.Close()
			return count, lastID, fmt.Errorf("audit: %s: %v", f, err)
		}
		in.Close()
	}
	return count, lastID, nil
}

// AuditVerify walks the audit files in date order and checks the chain against
// the events table, then requires the log to be complete: every event in the
// table must appear in the files. It returns the number of lines verified and an
// error naming the first break. A directory that does not exist verifies.
func AuditVerify(db *sql.DB, dir string) (int, error) {
	count, lastID, err := auditChainCheck(db, dir)
	if err != nil {
		return count, err
	}
	var maxID int64
	if err := db.QueryRow("select coalesce(max(id), 0) from events").Scan(&maxID); err != nil {
		return count, err
	}
	if maxID > lastID {
		return count, fmt.Errorf("audit: events up to id %d exist, the log ends at %d (events missing)",
			maxID, lastID)
	}
	return count, nil
}

// AuditWrite appends the events with id greater than the last position written
// to the file for day, continuing the chain across days. Events are written in
// id order, which is the order the append-only table produces them in.
//
// The chain is checked before anything is appended: a nightly job must not extend
// a log that already fails to verify, so a tampered file is reported at the write
// that would have hidden it. A day earlier than the last written day is refused —
// an audit log that can move backwards is not a log. Writing the same day twice
// appends to the existing file and continues its chain.
func AuditWrite(ctx context.Context, db *sql.DB, dir, day string) (int, error) {
	_, lastID, err := auditChainCheck(db, dir)
	if err != nil {
		return 0, fmt.Errorf("refusing to append: %v", err)
	}
	_, lastDay, found, err := auditLast(dir)
	if err != nil {
		return 0, err
	}
	if found && lastDay != "" && day < lastDay {
		return 0, fmt.Errorf("audit: day %s is before the last written day %s", day, lastDay)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(AuditPath(dir, day), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prev := lastHashOf(dir)
	rows, err := db.QueryContext(ctx,
		"select id, coalesce(envelope_id, ''), actor, kind, payload, created_at"+
			" from events where id > ? order by id", lastID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	w := bufio.NewWriter(f)
	n := 0
	for rows.Next() {
		var l AuditLine
		var payload string
		if err := rows.Scan(&l.ID, &l.Envelope, &l.Actor, &l.Kind, &payload, &l.CreatedAt); err != nil {
			return n, err
		}
		l.Payload = json.RawMessage(payload)
		if len(l.Payload) == 0 {
			l.Payload = json.RawMessage("{}")
		}
		if len(l.Payload) > MaxAuditLine {
			return n, fmt.Errorf("audit: event %d payload exceeds %d bytes", l.ID, MaxAuditLine)
		}
		l.PrevHash = prev
		l.Hash = auditHash(&l)
		b, err := json.Marshal(&l)
		if err != nil {
			return n, err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return n, err
		}
		prev = l.Hash
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	if err := w.Flush(); err != nil {
		return n, err
	}
	if err := f.Sync(); err != nil {
		return n, err
	}
	return n, nil
}

// auditLast returns the day of the newest audit file that contains a line. A day
// with no events leaves the chain where the last day that wrote anything left it.
func auditLast(dir string) (last AuditLine, day string, found bool, err error) {
	files, err := auditFiles(dir)
	if err != nil {
		return last, "", false, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		name := files[i]
		in, err := os.Open(name)
		if err != nil {
			return last, "", false, err
		}
		var l AuditLine
		var have bool
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 0, 64<<10), MaxAuditLine)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if err := json.Unmarshal([]byte(line), &l); err != nil {
				in.Close()
				return last, "", false, fmt.Errorf("audit: %s: unreadable line %q", name, line)
			}
			have = true
		}
		if err := sc.Err(); err != nil {
			in.Close()
			return last, "", false, err
		}
		in.Close()
		if have {
			return l, strings.TrimSuffix(filepath.Base(name), ".jsonl"), true, nil
		}
	}
	return last, "", false, nil
}

// lastHashOf is the hash the next line's prev_hash must carry. Recomputed from
// the tail's content, not read from the file: the chain has already been
// checked, so this is the same value.
func lastHashOf(dir string) string {
	l, _, found, err := auditLast(dir)
	if err != nil || !found {
		return ""
	}
	return auditHash(&l)
}
