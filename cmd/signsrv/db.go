package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// openStore loads the configuration, opens the database and applies pending
// migrations, so every database command runs against a schema this build
// understands.
func openStore(ctx context.Context, configPath string) (*Config, *signstore.Store, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, nil, err
	}
	db, err := signstore.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, nil, err
	}
	applied, err := signstore.Migrate(ctx, db)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	if applied > 0 {
		fmt.Printf("migrations applied: %d, schema version %d\n",
			applied, mustVersion(ctx, db))
	}
	return cfg, signstore.NewStore(db, cfg.StorageDir), nil
}

func mustVersion(ctx context.Context, db *sql.DB) int {
	v, err := signstore.SchemaVersion(ctx, db)
	if err != nil {
		return -1
	}
	return v
}

// migrateCmd: bring the database to this build's schema.
func migrateCmd(ctx context.Context, configPath string) int {
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	defer store.Close()
	v := mustVersion(ctx, store.DB())
	fmt.Printf("schema version %d, database %s\n", v, dbLabel(ctx, store))
	return 0
}

// sweepCmd: run one maintenance pass.
func sweepCmd(ctx context.Context, configPath string) int {
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	defer store.Close()
	r, err := signstore.Sweep(ctx, store.DB())
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	fmt.Printf("sweep at %s\n", r.Now)
	fmt.Printf("  envelopes expired : %d\n", r.EnvelopesExpired)
	fmt.Printf("  parties expired   : %d\n", r.PartiesExpired)
	fmt.Printf("  batches requeued  : %d\n", r.BatchesRequeued)
	fmt.Printf("  batches failed    : %d\n", r.BatchesFailed)
	fmt.Printf("  mail requeued     : %d\n", r.MailRequeued)
	fmt.Printf("  revoked jtis cut  : %d\n", r.JTIsDeleted)
	fmt.Printf("  refresh chains cut: %d\n", r.RefreshDeleted)
	return 0
}

// dbstatusCmd: counts and queue depths.
func dbstatusCmd(ctx context.Context, configPath string) int {
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	defer store.Close()
	db := store.DB()

	fmt.Printf("database         : %s\n", dbLabel(ctx, store))
	fmt.Printf("schema version   : %d\n", mustVersion(ctx, db))
	for _, q := range [][2]string{
		{"envelopes", "select count(*) from envelopes"},
		{"by status", "select coalesce(group_concat(status || ':' || n, ' '), '') from (select status, count(*) n from envelopes group by status)"},
		{"parties", "select count(*) from parties"},
		{"  consented", "select count(*) from parties where status = 'consented'"},
		{"revisions", "select count(*) from revisions"},
		{"consents", "select count(*) from consents"},
		{"events", "select count(*) from events"},
		{"admins", "select count(*) from admins"},
		{"clients", "select count(*) from clients"},
		{"mail pending", "select count(*) from mail_queue where sent_at is null"},
		{"mail sent", "select count(*) from mail_queue where sent_at is not null"},
		{"batches queued", "select count(*) from batch_queue"},
		{"revoked jtis", "select count(*) from revoked_jtis"},
		{"refresh live", "select count(*) from refresh_tokens where consumed_at is null"},
		{"refresh spent", "select count(*) from refresh_tokens where consumed_at is not null"},
	} {
		var v string
		if err := db.QueryRowContext(ctx, q[1]).Scan(&v); err != nil {
			fmt.Fprintf(os.Stderr, "signsrv: %s: %v\n", q[0], err)
			return 1
		}
		fmt.Printf("%-16s: %s\n", q[0], v)
	}
	if sha, err := store.GetSetting(ctx, "ca_fingerprint"); err == nil {
		fmt.Printf("%-16s: %s\n", "ca fingerprint", sha)
	}
	if serial, err := store.GetSetting(ctx, "ca_serial"); err == nil {
		fmt.Printf("%-16s: %s\n", "ca serial", serial)
	}
	return 0
}

func dbLabel(ctx context.Context, store *signstore.Store) string {
	var p string
	if err := store.DB().QueryRowContext(ctx, "pragma database_list").Scan(new(int), &p, new(string)); err != nil {
		return "?"
	}
	return p
}

// adminCmd: `signsrv admin add <email>` and `signsrv admin list`. The
// password is read from SIGNSRV_ADMIN_PASSWORD or from the terminal, never
// from the command line where it would land in shell history.
func adminCmd(ctx context.Context, configPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "signsrv admin: needs add <email> or list")
		return 2
	}
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	defer store.Close()

	switch args[0] {
	case "list":
		admins, err := store.ListAdmins(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		if len(admins) == 0 {
			fmt.Println("no admins: create one with `signsrv admin add <email>`")
			return 0
		}
		for _, a := range admins {
			fmt.Printf("%d  %s  role=%s  created=%s  last login=%s\n",
				a.ID, a.Email, a.Role, a.CreatedAt, dash(a.LastLogin))
		}
		return 0
	case "add":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "signsrv admin add: needs exactly one email address")
			return 2
		}
		email := strings.ToLower(strings.TrimSpace(args[1]))
		if !validEmail(email) {
			fmt.Fprintf(os.Stderr, "signsrv admin add: %q is not an email address\n", email)
			return 2
		}
		pw, err := readPassword("admin password", "SIGNSRV_ADMIN_PASSWORD")
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		if len(pw) < 12 {
			fmt.Fprintln(os.Stderr, "signsrv admin add: password must be at least 12 characters")
			return 1
		}
		hash, err := signauth.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		if existing, err := store.GetAdminByEmail(ctx, email); err == nil {
			fmt.Fprintf(os.Stderr, "signsrv admin add: %s already exists (id %d)\n", email, existing.ID)
			return 1
		} else if err != signstore.ErrNotFound {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		id, err := store.AddAdmin(ctx, email, hash, "admin")
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		fmt.Printf("admin %d created for %s\n", id, email)
		return 0

	case "passwd":
		// Changing the password is the action a user takes when a token is
		// stolen, so it has to end the sessions the password protected:
		// the hash is replaced, the epoch is stamped, and the refresh chain
		// is deleted. Access tokens minted under the old password stop
		// working at their next check, and the chain cannot be refreshed.
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "signsrv admin passwd: needs one email address")
			return 2
		}
		email := strings.ToLower(strings.TrimSpace(args[1]))
		admin, err := store.GetAdminByEmail(ctx, email)
		if err == signstore.ErrNotFound {
			fmt.Fprintf(os.Stderr, "signsrv admin passwd: %s is not an admin\n", email)
			return 1
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		pw, err := readPassword("new admin password", "SIGNSRV_ADMIN_PASSWORD")
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		if len(pw) < 12 {
			fmt.Fprintln(os.Stderr, "signsrv admin passwd: password must be at least 12 characters")
			return 1
		}
		hash, err := signauth.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		if err := store.SetAdminPassword(ctx, admin.ID, hash); err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		removed, err := store.DeleteRefreshChain(ctx, signauth.AdminSubject(admin.ID))
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		fmt.Printf("admin %d: password changed, %d refresh token(s) removed\n", admin.ID, removed)
		fmt.Println("Access tokens minted under the old password are refused from now on.")
		return 0

	default:
		fmt.Fprintln(os.Stderr, "signsrv admin: unknown action", args[0])
		return 2
	}
}

// clientCmd: `signsrv client add <name>`, `signsrv client list`,
// `signsrv client revoke <id>`.
func clientCmd(ctx context.Context, configPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "signsrv client: needs add <name>, list, or revoke <id>")
		return 2
	}
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	defer store.Close()

	switch args[0] {
	case "list":
		clients, err := store.ListClients(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		for _, c := range clients {
			fmt.Printf("%d  %s  key=%s  scopes=%s  created=%s  revoked=%s\n",
				c.ID, c.Name, short(c.KeyHash), dash(c.Scopes), c.CreatedAt, dash(c.RevokedAt))
		}
		if len(clients) == 0 {
			fmt.Println("no clients")
		}
		return 0
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "signsrv client add: needs a name")
			return 2
		}
		key := randomKey()
		sum := sha256Of([]byte(key))
		id, err := store.AddClient(ctx, args[1], sum, defaultScopes(args[2:]))
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		fmt.Printf("client %d created: %s\n", id, args[1])
		fmt.Printf("key: %s\n", key)
		fmt.Println("The key is shown once and is not recoverable; the database stores its hash.")
		return 0
	case "revoke":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "signsrv client revoke: needs a client id")
			return 2
		}
		var id int64
		if _, err := fmt.Sscanf(args[1], "%d", &id); err != nil || id <= 0 {
			fmt.Fprintf(os.Stderr, "signsrv client revoke: %q is not a client id\n", args[1])
			return 2
		}
		if err := store.RevokeClient(ctx, id); err != nil {
			fmt.Fprintln(os.Stderr, "signsrv:", err)
			return 1
		}
		fmt.Printf("client %d revoked\n", id)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "signsrv client: unknown action", args[0])
		return 2
	}
}

// ---------- helpers ----------

// defaultScopes normalises the scopes given after the client name. Both shapes
// from the documentation work: `client add api "envelope:write envelope:read"`
// (one quoted argument, space separated) and `client add api envelope:write
// envelope:read`. The stored form is a comma-separated list, the order of the
// arguments preserved, duplicates dropped.
func defaultScopes(args []string) string {
	fields := strings.FieldsFunc(strings.Join(args, ","), func(r rune) bool {
		return r == ',' || r == ' '
	})
	scopes := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, s := range fields {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		scopes = append(scopes, s)
	}
	if len(scopes) == 0 {
		return "envelope:read,envelope:write"
	}
	return strings.Join(scopes, ",")
}

func randomKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A missing CSPRNG is fatal for a signing service.
		panic("signsrv: no randomness: " + err.Error())
	}
	return "key_" + hex.EncodeToString(b)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

func validEmail(s string) bool {
	at := strings.Index(s, "@")
	if at < 1 || at == len(s)-1 {
		return false
	}
	dot := strings.LastIndex(s[at:], ".")
	if dot < 1 || dot == len(s)-at-1 {
		return false
	}
	for _, r := range s {
		if r > 127 {
			return false
		}
		if strings.IndexByte(" ()<>;,:\\\"", byte(r)) >= 0 {
			return false
		}
	}
	return true
}
