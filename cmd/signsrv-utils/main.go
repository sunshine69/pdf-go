// Command signsrv-utils is the operator's console for a signsrv database.
//
// It exists because `signsrv admin list` runs the full server configuration
// check — keystore passphrase, SMTP relay, https public_url — before it will
// open a database. That is the wrong question to ask of a command that only
// reads a table: an operator trying to find out which admins exist is told the
// configuration is unusable while the service is happily signing documents.
//
// So this binary asks one question of one file: where is the database?
//
//	signsrv-utils admin list
//	signsrv-utils admin add you@example.org
//	signsrv-utils client add batch envelope:write envelope:read
//
// With no -config it reads /etc/signsrv/signsrv.env. -db bypasses config
// entirely and opens a file directly, which is what you want when the config
// itself is the thing you are debugging.
//
// It never starts a server, never touches the keystore, and never validates
// anything it does not use.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

const version = "0.0.1"

// defaultConfig is where the Debian package puts its settings, and what the
// systemd unit passes to the service. Hard-coded on purpose: the point of this
// tool is that you do not have to remember a path to answer a question about
// your own installation.
const defaultConfig = "/etc/signsrv/signsrv.env"

// knownDatabases are the paths the Debian package and the docs use. They are
// consulted only when the config file does not name one, to turn "no db
// setting" into "here is the database I found, use it if that is the one".
var knownDatabases = []string{
	"/var/lib/signsrv/signsrv.db", // the Debian package
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx := context.Background()

	dbFlag := ""
	cfgFlag := ""
	rest := []string{}

	// Hand-rolled flag parsing, one step at a time. The flags are few and the
	// failure modes are worth controlling: a typo here should say which word
	// was wrong, not print a usage block for the whole tool.
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-db" || a == "--db":
			if i+1 >= len(args) {
				return fail("%s needs a path", a)
			}
			i++
			dbFlag = args[i]
		case a == "-config" || a == "--config":
			if i+1 >= len(args) {
				return fail("%s needs a path", a)
			}
			i++
			cfgFlag = args[i]
		case a == "-h" || a == "--help" || a == "help":
			usage()
			return 0
		case a == "-v" || a == "--version" || a == "version":
			fmt.Println("signsrv-utils", version)
			return 0
		case strings.HasPrefix(a, "-"):
			return fail("unknown flag %q (try: signsrv-utils help)", a)
		default:
			rest = append(rest, a)
		}
	}

	if len(rest) == 0 {
		usage()
		return 2
	}

	// Resolve the database before dispatching, so every command reports the
	// same failure the same way and none of them can forget to.
	dbPath, source, err := resolveDB(dbFlag, cfgFlag)
	if err != nil {
		return fail("%v", err)
	}

	db, err := openAndMigrate(ctx, dbPath)
	if err != nil {
		return fail("open %s: %v", dbPath, err)
	}
	defer db.Close()

	// Naming the file and where the path came from is not decoration. Half the
	// confusion this tool exists to fix is an operator editing one database
	// while the service uses another.
	fmt.Fprintf(os.Stderr, "# db=%s (from %s)\n", dbPath, source)

	return dispatch(ctx, db, rest)
}

// resolveDB answers "which database?" from, in order of precedence:
//
//	-db PATH        you said so, on the command line
//	$db             the environment, so a container or a cron job can point it
//	$config         the key "db" (or its alias "db_path") in the file
//	/config/../var/signsrv.db  nothing was configured; say so and stop
//
// There is no default path baked in beyond the config file itself. Guessing
// where a signing database lives, and then writing to it, is how an operator
// ends up with two of them.
func resolveDB(dbFlag, cfgFlag string) (path, source string, err error) {
	if dbFlag != "" {
		return dbFlag, "-db", nil
	}
	if v := os.Getenv("DB"); v != "" {
		return v, "$DB", nil
	}

	cfg := cfgFlag
	if cfg == "" {
		cfg = defaultConfig
	}
	if v := os.Getenv("CONFIG"); v != "" && cfgFlag == "" {
		cfg = v
	}

	settings, err := readDotEnv(cfg)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", cfg, err)
	}
	// "db" is the documented key; "db_path" is accepted because the config
	// loader accepts it and an existing installation may have been written with
	// it. Both are read, "db" wins, and neither is required — which is the
	// whole difference from the server's loader.
	path = firstSet(settings, "db", "db_path")
	if path == "" {
		// A config with no db= is usually an older install where the path was
		// implicit. Rather than guess silently, name the one that is actually
		// there and let the operator repeat it back on the command line.
		for _, c := range knownDatabases {
			if _, err := os.Stat(c); err == nil {
				return "", "", fmt.Errorf("no db= setting in %s, but %s exists — run: signsrv-utils -db %s", cfg, c, c)
			}
		}
		return "", "", fmt.Errorf("no db= setting in %s and no database at %s — find it with the service's own -config file, or pass -db PATH",
			cfg, strings.Join(knownDatabases, " or "))
	}
	return path, cfg, nil
}

// readDotEnv reads KEY=value lines. Nothing more.
//
// It is deliberately not the server's config loader: that one rejects unknown
// keys, applies defaults, and validates the result as the configuration of a
// running service. A rescue tool must not fail for the same reasons the tool it
// is rescuing you from fails. So an unrecognised key here is ignored, and the
// only errors are "cannot read the file".
//
// The server writes this file with bare lowercase keys (listen=...), but a
// hand-written one is usually uppercase (LISTEN=...) because that is how an
// EnvironmentFile reads. Both shapes are accepted here, and so is a leading
// SIGNSRV_ on any of them.
func readDotEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // a secrets file can hold long base64
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue // a stray comment, or a shell line; not ours to police
		}
		k = strings.ToLower(strings.TrimSpace(k))
		k = strings.TrimPrefix(k, "signsrv_")
		if k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if _, seen := out[k]; !seen { // first wins: the order in the file is the order of intent
			out[k] = v
		}
	}
	return out, sc.Err()
}

func firstSet(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func usage() {
	fmt.Println(`signsrv-utils ` + version + ` - operator console for a signsrv database

  admin list
  admin add EMAIL
  admin passwd EMAIL
  client list
  client add NAME [SCOPE...]
  client revoke ID
  status

Flags (before the command):
  -config FILE   read db= from FILE      (default ` + defaultConfig + `)
  -db PATH       open this database, read no config at all

The database is found by, in order: -db, then $DB, then db= in the
config file. Nothing else about the config is read, and nothing in it is
validated — this tool works while the service is refusing to start.

Passwords are read from $ADMIN_PASSWORD, or prompted twice with the
echo off. They are never given on the command line.`)
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "signsrv-utils: "+format+"\n", a...)
	return 1
}

// trimLine strips the line ending and surrounding spaces. Shared by the two
// terminal implementations so a CRLF from a piped file behaves the same as
// from a keyboard.
func trimLine(s string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r"))
}
