package signstore

import (
	"context"
	"strings"
)

// ListEnvelopes returns envelopes, newest first. When status is non-empty it
// filters; when search is non-empty it matches the title, the envelope id, or
// a party's email or name. Every value is a bound parameter and the LIKE
// escape character is declared, so a search string is matched literally.
// MaxPageSize is the page size ceiling. The list is indexed, so a large page
// is a large response body; the cap keeps one request from asking for the
// whole table.
const MaxPageSize = 100

func (s *Store) ListEnvelopes(ctx context.Context, status, search string, limit, offset int) ([]Envelope, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	if offset < 0 {
		offset = 0
	}

	where := []string{"1=1"}
	args := []any{}
	if status != "" {
		where = append(where, "e.status = ?")
		args = append(args, status)
	}
	if search != "" {
		where = append(where, `(e.title LIKE '%' || ? || '%' ESCAPE '\'
			OR e.id = ?
			OR EXISTS (select 1 from parties p where p.envelope_id = e.id
				and (p.email LIKE '%' || ? || '%' ESCAPE '\'
				     or p.name LIKE '%' || ? || '%' ESCAPE '\')))`)
		// One value, four positions: the driver binds positionally.
		like := escapeLike(search)
		args = append(args, like, like, like, like)
	}
	cond := strings.Join(where, " and ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		"select count(*) from envelopes e where "+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		"select "+prefixCols(envelopeCols, "e")+" from envelopes e where "+cond+
			" order by e.created_at desc, e.rowid desc limit ? offset ?",
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []Envelope{}
	for rows.Next() {
		e, err := scanEnvelope(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *e)
	}
	return out, total, rows.Err()
}

// prefixCols qualifies a column list with a table alias. The lists in this
// package are constants, so the only string building in a query is over the
// fixed column names and the whitelisted column names of
// UpdateEnvelopeStatus/UpdatePartyStatus.
func prefixCols(cols, alias string) string {
	return alias + "." + strings.ReplaceAll(cols, ",", ", "+alias+".")
}
