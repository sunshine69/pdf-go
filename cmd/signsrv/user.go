package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// userCmd: the credential desk. One account table serves both doors, so these
// verbs create and maintain the rows behind both of them.
//
//	signsrv user list [-config FILE]
//	signsrv user add USERNAME [SCOPES...] [--password-stdin] [-config FILE]
//	signsrv user rotate USERNAME [-config FILE]
//	signsrv user revoke USERNAME [-config FILE]
//
// These are local verbs, and deliberately so. The row carries the shared secret
// that signs a caller's tokens, so creating one is the moment of highest
// privilege in the system: the API cannot hand out a credential that the API's
// own authentication is built on. A user is added on the machine that holds the
// database. Everything they do afterwards — create an envelope, list envelopes,
// cancel one — is HTTP, from anywhere.
//
// The secret is printed exactly once. It is stored in the clear, so the
// database is the secret store: its file mode and its backups are the trust
// boundary, and `rotate` is how a secret that leaked stops being a key.
func userCmd(ctx context.Context, configPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "signsrv user: needs add <username>, list, rotate <username>, or revoke <username>")
		return 2
	}
	cfg, store, err := openStore(ctx, configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	defer store.Close()

	// A remote store is refused rather than attempted: the credential is the
	// root of the API's authentication, so minting one is a local act.
	if cfg.DBFile() == "" {
		fmt.Fprintln(os.Stderr, "signsrv user: the store is postgres. The shared secret is the root of API")
		fmt.Fprintln(os.Stderr, "authentication, so accounts are minted on the machine that runs the service.")
		fmt.Fprintln(os.Stderr, "For a remote database, insert the row with the deployment's own tooling.")
		return 1
	}

	switch args[0] {
	case "list":
		return userList(ctx, store)
	case "add":
		return userAdd(ctx, store, args[1:])
	case "rotate":
		return userRotate(ctx, store, args[1:])
	case "revoke":
		return userRevoke(ctx, store, args[1:])
	default:
		fmt.Fprintln(os.Stderr, "signsrv user: unknown action", args[0])
		return 2
	}
}

func userList(ctx context.Context, store *signstore.Store) int {
	rows, err := store.ListUsers(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	for _, u := range rows {
		// Presence, never value. The list command runs in front of a shoulder
		// and in a paste into a ticket; the secret is only ever printed once,
		// by `user add`, at the moment it is created.
		pw := "-"
		if u.HasPassword {
			pw = "argon2id"
		}
		secret := "-"
		if u.HasSecret {
			secret = "set"
		}
		fmt.Printf("%d  %s  secret=%s  pw=%s  scopes=%s  created=%s  revoked=%s\n",
			u.ID, u.Username, secret, pw, dash(u.Scopes), u.CreatedAt, dash(u.RevokedAt))
	}
	if len(rows) == 0 {
		fmt.Println("no users")
	}
	return 0
}

// usernamePattern is the shape of a subject. The value becomes the "sub" claim
// of every token this account signs, so it must be safe inside a JSON string, a
// URL and a log line, and it must never be confusable with another username.
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

func userAdd(ctx context.Context, store *signstore.Store, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "signsrv user add: needs a username")
		return 2
	}
	name := args[0]
	if !usernamePattern.MatchString(name) {
		fmt.Fprintf(os.Stderr, "signsrv user add: %q is not a username\n", name)
		fmt.Fprintln(os.Stderr, "use lower case letters, digits, dot, dash, underscore; 2 to 63 characters, starting with a letter or digit")
		return 2
	}
	// Scopes: the same argument shapes as `client add`. Defaults to the
	// dispatch pair, which is what a contract desk needs.
	scopes := defaultScopes(args[1:])
	if scopes == "" {
		scopes = signauth.ScopeEnvelopeWrite + "," + signauth.ScopeEnvelopeRead
	}
	// The admin scope is refused here and refused by the guard. The admin
	// surface takes a token minted by the service with its EdDSA key, so
	// granting admin:read in a row would promise access the system will not
	// honour — and a widened scopes column must never be a path to takeover.
	for _, s := range signstore.ScopeList(scopes) {
		if s == signauth.ScopeAdminRead {
			fmt.Fprintln(os.Stderr, "signsrv user add: admin:read cannot be granted to a user account")
			fmt.Fprintln(os.Stderr, "the admin surface is signed by the service's own key, not by a client secret.")
			return 2
		}
	}

	pw, err := readPasswordArg(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv user add:", err)
		return 1
	}
	hash := ""
	if pw != "" {
		if len(pw) < 10 {
			fmt.Fprintln(os.Stderr, "signsrv user add: the web-login password must be at least 10 characters, or empty to skip it")
			return 2
		}
		hash, err = signauth.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "signsrv user add:", err)
			return 1
		}
	}

	secret, err := signstore.NewJWTSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv user add:", err)
		return 1
	}
	id, err := store.AddUser(ctx, name, hash, secret, scopes, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv user add:", err)
		return 1
	}

	fmt.Printf("user %d created: %s\n", id, name)
	fmt.Printf("jwt_secret: %s\n", secret)
	fmt.Printf("scopes: %s\n", scopes)
	if hash == "" {
		fmt.Println("web login: no password set (the account can sign API requests only)")
	}
	fmt.Println()
	fmt.Println("The secret is shown once and cannot be recovered — but it is stored in the clear in")
	fmt.Println("the users table, because the service must recompute the signature. The database file")
	fmt.Println("is therefore the secret: keep it 0600 and treat its backups as secrets. Rotating")
	fmt.Println("(`signsrv user rotate`) stops every token signed with the old value.")
	fmt.Println()
	fmt.Println("With it, the CLI mints its own token and needs no token round trip:")
	fmt.Printf("  export SIGNSRV_USERNAME=%s\n", name)
	fmt.Printf("  export SIGNSRV_JWT_SECRET='%s'\n", secret)
	fmt.Println("  pdf-go envelope create --server https://sign.example --spec fill.json --parties parties.json")
	return 0
}

// userRotate replaces the secret of one account. The password is untouched, so
// a web login keeps working; only API tokens stop verifying, and only ones
// minted before the change.
func userRotate(ctx context.Context, store *signstore.Store, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "signsrv user rotate: needs a username")
		return 2
	}
	row, secret, err := store.RotateJWTSecretByUsername(ctx, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv user rotate:", err)
		return 1
	}
	fmt.Printf("user %d: secret rotated (%s)\n", row.ID, row.Username)
	fmt.Printf("jwt_secret: %s\n", secret)
	fmt.Println()
	fmt.Println("Every token signed with the old secret is refused from now on. Hand the new")
	fmt.Println("secret to the machine that signs its own requests.")
	return 0
}

func userRevoke(ctx context.Context, store *signstore.Store, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "signsrv user revoke: needs a username")
		return 2
	}
	row, err := store.RevokeUserByUsername(ctx, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv user revoke:", err)
		return 1
	}
	fmt.Printf("user %d revoked (%s): every token for it is refused, and its web login is closed\n",
		row.ID, row.Username)
	return 0
}

// readPasswordArg takes a web-login password from the environment, from a pipe
// with --password-stdin, or not at all. It is never a command line argument:
// argv is visible in `ps`, in shell history, and in a shell's audit log.
//
// An account with no password is legal and is the normal shape today: the
// credential that matters for the API is the shared secret; the password is the
// future web-login door.
func readPasswordArg(args []string) (string, error) {
	if v, ok := os.LookupEnv("SIGNSRV_USER_PASSWORD"); ok {
		return strings.TrimSpace(v), nil
	}
	for _, a := range args {
		if a == "--password-stdin" {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		}
	}
	return "", nil
}
