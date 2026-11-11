package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

func dispatch(ctx context.Context, store *signstore.Store, args []string) int {
	group, rest := args[0], args[1:]
	switch group {
	case "admin":
		return adminCmd(ctx, store, rest)
	case "client":
		return clientCmd(ctx, store, rest)
	case "status":
		return statusCmd(ctx, store, rest)
	default:
		fmt.Fprintf(os.Stderr, "signsrv-utils: unknown command %q\n", group)
		usage()
		return 2
	}
}

// ---------------------------------------------------------------- admin ----

func adminCmd(ctx context.Context, store *signstore.Store, args []string) int {
	if len(args) == 0 {
		return fail("admin: needs list, add EMAIL, or passwd EMAIL")
	}
	switch args[0] {
	case "list":
		admins, err := store.ListAdmins(ctx)
		if err != nil {
			return fail("admin list: %v", err)
		}
		if len(admins) == 0 {
			fmt.Println("no admins — create one with: signsrv-utils admin add you@example.org")
			return 0
		}
		for _, a := range admins {
			fmt.Printf("%d  %-40s role=%-8s created=%s last-login=%s\n",
				a.ID, a.Email, a.Role, dash(a.CreatedAt), dash(a.LastLogin))
		}
		return 0

	case "add":
		if len(args) != 2 {
			return fail("admin add: needs one email address")
		}
		email := strings.ToLower(strings.TrimSpace(args[1]))
		if !strings.Contains(email, "@") || strings.HasSuffix(email, "@") {
			return fail("admin add: %q is not an email address", email)
		}
		if existing, err := store.GetAdminByEmail(ctx, email); err == nil {
			return fail("admin add: %s already exists (id %d) — use: admin passwd %s",
				email, existing.ID, email)
		} else if !errors.Is(err, signstore.ErrNotFound) {
			return fail("admin add: %v", err)
		}
		pw, err := readPassword("admin password")
		if err != nil {
			return fail("admin add: %v", err)
		}
		hash, err := signauth.HashPassword(pw)
		if err != nil {
			return fail("admin add: %v", err)
		}
		id, err := store.AddAdmin(ctx, email, hash, "admin")
		if err != nil {
			return fail("admin add: %v", err)
		}
		fmt.Printf("admin %d created for %s\n", id, email)
		return 0

	case "passwd":
		if len(args) != 2 {
			return fail("admin passwd: needs one email address")
		}
		email := strings.ToLower(strings.TrimSpace(args[1]))
		admin, err := store.GetAdminByEmail(ctx, email)
		if errors.Is(err, signstore.ErrNotFound) {
			return fail("admin passwd: %s is not an admin (admin list shows who is)", email)
		}
		if err != nil {
			return fail("admin passwd: %v", err)
		}
		pw, err := readPassword("new admin password")
		if err != nil {
			return fail("admin passwd: %v", err)
		}
		hash, err := signauth.HashPassword(pw)
		if err != nil {
			return fail("admin passwd: %v", err)
		}
		if err := store.SetAdminPassword(ctx, admin.ID, hash); err != nil {
			return fail("admin passwd: %v", err)
		}
		// A password change is what an operator does after a token is stolen, so
		// it has to end the sessions the password protected. Same as the server.
		removed, err := store.DeleteRefreshChain(ctx, signauth.AdminSubject(admin.ID))
		if err != nil {
			return fail("admin passwd: password changed, but the refresh chain was not cleared: %v", err)
		}
		fmt.Printf("admin %d: password changed, %d refresh token(s) removed\n", admin.ID, removed)
		fmt.Println("Access tokens minted under the old password are refused from now on.")
		return 0

	default:
		return fail("admin: unknown subcommand %q (list, add, passwd)", args[0])
	}
}

// -------------------------------------------------------------- client -----

func clientCmd(ctx context.Context, store *signstore.Store, args []string) int {
	if len(args) == 0 {
		return fail("client: needs list, add NAME [SCOPE...], or revoke ID")
	}
	switch args[0] {
	case "list":
		clients, err := store.ListClients(ctx)
		if err != nil {
			return fail("client list: %v", err)
		}
		if len(clients) == 0 {
			fmt.Println("no clients")
			return 0
		}
		for _, c := range clients {
			fmt.Printf("%d  %-20s scopes=%-40s created=%s revoked=%s\n",
				c.ID, c.Name, dash(c.Scopes), c.CreatedAt, dash(c.RevokedAt))
		}
		return 0

	case "add":
		if len(args) < 2 {
			return fail("client add: needs a name, e.g. client add batch envelope:write envelope:read")
		}
		key, err := randomKey()
		if err != nil {
			return fail("client add: %v", err)
		}
		sum := sha256.Sum256([]byte(key))
		id, err := store.AddClient(ctx, args[1], hex.EncodeToString(sum[:]), strings.Join(args[2:], ","))
		if err != nil {
			return fail("client add: %v", err)
		}
		fmt.Printf("client %d created: %s\n", id, args[1])
		fmt.Printf("key: %s\n", key)
		fmt.Println("The key is shown once and cannot be recovered; the database stores only its hash.")
		return 0

	case "revoke":
		if len(args) != 2 {
			return fail("client revoke: needs a client id")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return fail("client revoke: %q is not a client id", args[1])
		}
		if err := store.RevokeClient(ctx, id); err != nil {
			return fail("client revoke: %v", err)
		}
		fmt.Printf("client %d revoked\n", id)
		return 0

	default:
		return fail("client: unknown subcommand %q (list, add, revoke)", args[0])
	}
}

// --------------------------------------------------------------- status ----

// statusCmd answers "is this the database the service is using, and is it
// healthy?" without the operator having to know any table names.
func statusCmd(ctx context.Context, store *signstore.Store, args []string) int {
	db := store.DB()
	var version int
	if err := db.QueryRowContext(ctx, "pragma schema_version").Scan(&version); err != nil {
		return fail("status: %v", err)
	}
	fmt.Printf("schema_version   %d\n", version)

	counts := []struct{ label, table string }{
		{"admins", "admins"},
		{"clients", "clients"},
		{"users", "users"},
		{"envelopes", "envelopes"},
		{"tokens", "refresh_tokens"},
	}
	for _, c := range counts {
		var n int
		// A missing table is a fact about an unmigrated or partial database, not
		// a crash. Report it and move on: the point is the whole picture at once.
		if err := db.QueryRowContext(ctx, "select count(*) from "+c.table).Scan(&n); err != nil {
			fmt.Printf("%-16s %s\n", c.label, noSuchTable(err))
			continue
		}
		fmt.Printf("%-16s %d\n", c.label, n)
	}
	return 0
}

func noSuchTable(err error) string {
	if strings.Contains(err.Error(), "no such table") {
		return "(no such table)"
	}
	return "(" + err.Error() + ")"
}

// ------------------------------------------------------------ helpers ------

// readPassword takes the password from the environment if it is set, otherwise
// prompts twice. The environment path exists for scripts and containers; the
// prompt exists so a password never has to appear in a shell history line.
//
// Unlike the server, an empty SIGNSRV_ADMIN_PASSWORD falls through to the
// prompt rather than erroring — the operator may have an unset variable left
// over from a sourced file, and "type it" is a better outcome than "it is blank".
func readPassword(label string) (string, error) {
	if v := os.Getenv("SIGNSRV_ADMIN_PASSWORD"); v != "" {
		if len(v) < 12 {
			return "", fmt.Errorf("SIGNSRV_ADMIN_PASSWORD is only %d characters; 12 is the minimum", len(v))
		}
		return v, nil
	}
	first, err := promptHidden(label + ": ")
	if err != nil {
		return "", err
	}
	second, err := promptHidden("repeat it:   ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("the two entries do not match")
	}
	if len(first) < 12 {
		return "", fmt.Errorf("password must be at least 12 characters")
	}
	return first, nil
}

func randomKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sk_" + hex.EncodeToString(b[:]), nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
