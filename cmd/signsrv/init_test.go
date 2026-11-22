package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// initConfig builds a Config whose state lives in a temp dir, so the
// first-start path runs against real files rather than against a mock of them.
// dev=false is the shape that needs an admin account: in dev the service seeds
// dev@localhost by itself (cmd/signsrv/devadmin.go), and the two paths must not
// collide.
func initConfig(t *testing.T, dev bool) *Config {
	t.Helper()
	dir := t.TempDir()
	public := "https://sign.example.test"
	if dev {
		public = "http://127.0.0.1:8080"
	}
	return &Config{
		Listen:     "127.0.0.1:0",
		PublicURL:  public,
		Dev:        dev,
		DBPath:     filepath.Join(dir, "signsrv.db"),
		StorageDir: filepath.Join(dir, "storage"),
		Keystore:   filepath.Join(dir, "keystore"),
		Outbox:     filepath.Join(dir, "outbox"),
		AuditDir:   filepath.Join(dir, "audit"),
		LogPath:    filepath.Join(dir, "log", "signsrv.jsonl"),
		TSAURL:     "https://tsa.example.test/tsr",
		MailFrom:   "signsrv@example.test",
		SMTPHost:   "smtp.example.test",
		MaxPDFMB:   25,
		LogLevel:   "debug",
		jwtFile:    filepath.Join(dir, "jwt.ed25519.key"),
		env: map[string]string{
			"keystore_pass":  "test-passphrase-at-least-12",
			"admin_password": "test-admin-password-1234",
		},
	}
}

// captureLog collects the JSON log records so a test can assert on what the
// operator would read, not only on what landed in the database.
func captureLog(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// logLines splits the captured log into records. Each line is one record; a
// test that wants "was this said" searches the records, not the raw text, so a
// message that happens to contain the word in a value does not read as a match.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		out = append(out, rec)
	}
	return out
}

func hasLog(buf *bytes.Buffer, msg string) bool {
	for _, line := range strings.Split(buf.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] == msg {
			return true
		}
	}
	return false
}

// ---------- the state check ----------

// A brand new volume is the case the whole feature is about: nothing exists, so
// every state file is absent and the instance counts as new.
func TestFirstStartOnEmptyState(t *testing.T) {
	cfg := initConfig(t, false)
	fresh, listing, err := firstStart(cfg)
	if err != nil {
		t.Fatalf("firstStart: %v", err)
	}
	if !fresh {
		t.Fatalf("an empty state directory must read as a first start; listing: %v", listing)
	}
	if len(listing) != 3 {
		t.Fatalf("listing = %v, want the database and both keystore files", listing)
	}
	for _, entry := range listing {
		if !strings.Contains(entry, "absent") {
			t.Errorf("listing entry %q is not absent", entry)
		}
	}
}

// The database is the thing that says "this instance has run". A volume that
// holds a database but no keystore is not new, and must not get a new CA.
func TestFirstStartIsFalseOnceTheDatabaseExists(t *testing.T) {
	cfg := initConfig(t, false)
	if err := os.WriteFile(cfg.DBFile(), []byte("not really a database, but present"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh, listing, err := firstStart(cfg)
	if err != nil {
		t.Fatalf("firstStart: %v", err)
	}
	if fresh {
		t.Fatalf("a state directory with a database is not a first start; listing: %v", listing)
	}
}

// One keystore file and not the other is damage, not a first start. signpdf
// refuses to issue a CA over a surviving half (internal/signpdf, LoadCAWith),
// and this check must not quietly classify the same shape as "nothing here yet".
func TestFirstStartIsFalseOnAHalfPresentKeystore(t *testing.T) {
	cfg := initConfig(t, false)
	if err := os.MkdirAll(cfg.Keystore, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Keystore, "ca.crt"), []byte("-----BEGIN CERTIFICATE-----"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := firstStart(cfg)
	if err != nil {
		t.Fatalf("firstStart: %v", err)
	}
	if fresh {
		t.Fatal("ca.crt present with ca.key missing must not read as a first start")
	}
}

// A file that cannot be examined is not a file that is absent. The action that
// follows from "absent" is issuing a CA, and issuing one because a stat failed
// would orphan the signatures made with the CA the stat could not see.
func TestFirstStartRefusesToGuessOnAnUnreadableStateFile(t *testing.T) {
	cfg := initConfig(t, false)
	if err := os.MkdirAll(cfg.Keystore, 0o750); err != nil {
		t.Fatal(err)
	}
	// A directory named ca.key: not a database key, and not nothing.
	if err := os.MkdirAll(filepath.Join(cfg.Keystore, "ca.key"), 0o750); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := firstStart(cfg)
	if err == nil {
		t.Fatalf("want an error for an unreadable state file, got fresh=%v", fresh)
	}
	if !strings.Contains(err.Error(), "ca.key") {
		t.Errorf("the error should name the file: %v", err)
	}
}

// ---------- which CA a fresh instance gets ----------

func TestInstanceName(t *testing.T) {
	cases := map[string]string{
		"https://test-pdfsign.kaykraft.org":  "test-pdfsign.kaykraft.org",
		"https://sign.example.org:8443":      "sign.example.org",
		"https://sign.example.org/somewhere": "sign.example.org",
		"http://127.0.0.1:8080":              "", // an address is not an identity
		"":                                   "",
		"https://[2001:db8::1]:7000":         "",
		"  https://lower.example.org  ":      "lower.example.org",
	}
	for url, want := range cases {
		cfg := &Config{PublicURL: url}
		if got := instanceName(cfg); got != want {
			t.Errorf("instanceName(%q) = %q, want %q", url, got, want)
		}
	}
}

// An operator who set the ca_* keys set them on purpose, and the identity they
// chose is the one that must end up in the certificate.
func TestFirstStartHonoursAConfiguredCASubject(t *testing.T) {
	cfg := initConfig(t, false)
	cfg.CASubject = &signpdf.CASubject{CommonName: "Example Ltd Signing CA", Organization: "Example Ltd"}
	got := firstStartCASubject(cfg)
	if got == nil || got.CommonName != "Example Ltd Signing CA" {
		t.Fatalf("configured subject was replaced: %+v", got)
	}
}

// Dev mode keeps the historical name. A dev instance has no public host worth
// putting into a certificate, and its CA should read like every earlier dev CA.
func TestFirstStartKeepsTheDefaultSubjectInDev(t *testing.T) {
	cfg := initConfig(t, true)
	if got := firstStartCASubject(cfg); got != nil {
		t.Fatalf("dev mode should leave the built-in subject alone, got %+v", got)
	}
}

// A production instance that named no subject gets its own host as one, and the
// name lands in the certificate that is about to become permanent. This is the
// point of deriving it: the subject is honoured on the first start only, so a
// fresh instance is the only moment it can be chosen well.
func TestFirstStartIssuesANamedCAWhenTheOperatorNamedNone(t *testing.T) {
	cfg := initConfig(t, false)
	ctx := context.Background()
	log, buf := captureLog(t)

	svc, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	subject := svc.CA().Cert.Subject.CommonName
	if !strings.Contains(subject, "sign.example.test") {
		t.Fatalf("CA subject = %q, want the instance host it was issued for", subject)
	}
	if !hasLog(buf, "first start: issuing the signing CA") {
		t.Errorf("the run did not say which name it chose before fixing it:\n%s", buf.String())
	}
	if !hasLog(buf, "signing CA ready") {
		t.Errorf("the run did not report the CA it made:\n%s", buf.String())
	}
}

// The fingerprint is the value a recipient checks out of band, and the log line
// that carries it is gone by the time anyone asks. It has to be readable from
// the database, which is what `signsrv dbstatus` prints.
func TestFirstStartRecordsTheCAIdentityInTheDatabase(t *testing.T) {
	cfg := initConfig(t, false)
	ctx := context.Background()
	log, _ := captureLog(t)

	svc, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	for _, kv := range [][2]string{
		{"ca_fingerprint", svc.CA().Fingerprint()},
		{"ca_serial", svc.CA().Cert.SerialNumber.String()},
	} {
		got, err := store.GetSetting(ctx, kv[0])
		if err != nil {
			t.Fatalf("setting %s: %v", kv[0], err)
		}
		if got != kv[1] {
			t.Errorf("setting %s = %q, want %q", kv[0], got, kv[1])
		}
	}
}

// The migration that creates the tables has to have run before the seed writes
// to them, so the schema version after a first start is this build's, not zero.
func TestFirstStartRunsTheMigrations(t *testing.T) {
	cfg := initConfig(t, false)
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	version, err := signstoreVersion(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if version <= 0 {
		t.Fatalf("schema version %d after a first start, want the migrations to have run", version)
	}
	if !hasLog(buf, "database migrations applied") {
		t.Errorf("the start did not report the migrations it applied:\n%s", buf.String())
	}
}

// SQLite creates the database under the process umask, so a fresh file lands
// 0644 and the config then warns that the file holding the account secrets is
// readable by others. A file this start created is the one file this start can
// set the mode of, so it should arrive at 0600 and the warning should not be
// there to act on by hand.
func TestFirstStartCreatesTheDatabaseFileAtZeroSixHundred(t *testing.T) {
	cfg := initConfig(t, false)
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	store.Close()

	info, err := os.Stat(cfg.DBFile())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("new database file has mode %04o, want 0600", info.Mode().Perm())
	}
	if strings.Contains(buf.String(), "database file is readable by others") {
		t.Errorf("the start warned about a file it just made:\n%s", buf.String())
	}
}

// ---------- the admin account ----------

// The failure this exists to prevent: a container comes up green, /healthz
// answers 200, and /admin/ refuses every login because ADMIN_PASSWORD
// is a password that belongs to nobody (docs/DEPLOY-DOCKER.md, "Accounts").
func TestFirstStartCreatesTheAdminNamedByTheEnvironment(t *testing.T) {
	cfg := initConfig(t, false)
	t.Setenv("DEFAULT_ADMIN_EMAIL", "Test-Admin@Example.com")
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	// Lower-cased: the login compares addresses, and a mixed-case value in an
	// environment variable is the same account typed differently.
	a, err := store.GetAdminByEmail(ctx, "test-admin@example.com")
	if err != nil {
		t.Fatalf("no admin for test-admin@example.com: %v\nlog:\n%s", err, buf.String())
	}
	if a.Role != "admin" {
		t.Errorf("role = %q, want admin", a.Role)
	}
	ok, err := signauth.VerifyPassword(cfg.AdminPassword(), a.PWHash)
	if err != nil || !ok {
		t.Errorf("the password in the environment does not unlock the account it created: %v", err)
	}
	if !hasLog(buf, "admin account created") {
		t.Errorf("the run did not say it made an account:\n%s", buf.String())
	}
}

// A container restarts. The second start must not fail on the account the first
// one made, and must not make a second one.
func TestFirstStartAdminSeedIsIdempotentAcrossRestarts(t *testing.T) {
	cfg := initConfig(t, false)
	t.Setenv("DEFAULT_ADMIN_EMAIL", "test-admin@example.com")
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		log, buf := captureLog(t)
		_, store, err := firstStartInit(ctx, cfg, log)
		if err != nil {
			t.Fatalf("start %d: %v\nlog:\n%s", i, err, buf.String())
		}
		admins, err := store.ListAdmins(ctx)
		store.Close()
		if err != nil {
			t.Fatalf("start %d: list admins: %v", i, err)
		}
		if len(admins) != 1 {
			t.Fatalf("start %d left %d admins, want the one account\nlog:\n%s", i, len(admins), buf.String())
		}
		if hasLog(buf, "admin account created") && i > 1 {
			t.Errorf("start %d created a second account", i)
		}
	}
}

// After the first start, who is an admin is decided by `admin add`. A restart
// weeks later, on an instance that has gained accounts since, must not add an
// address because an environment variable still names it — but it must say why
// it did nothing, because a silent skip reads as success.
func TestFirstStartDoesNotCreateAnAdminOnAnExistingInstance(t *testing.T) {
	cfg := initConfig(t, false)
	ctx := context.Background()

	// First start, without the variable in force: the instance is created with
	// the built-in address, and that account is the one the restart must leave
	// alone.
	os.Unsetenv("DEFAULT_ADMIN_EMAIL")
	_, store, err := firstStartInit(ctx, cfg, captureLogOnly(t))
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	store.Close()

	// The restart happens with the variable set, as it would be in a container
	// whose compose file always passes it.
	t.Setenv("DEFAULT_ADMIN_EMAIL", "someone@example.com")

	log, buf := captureLog(t)
	_, store, err = firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	defer store.Close()

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 1 || admins[0].Email != defaultAdminEmail {
		t.Fatalf("admins after a restart = %v, want only the %s the first start created", admins, defaultAdminEmail)
	}
	if !hasLog(buf, "DEFAULT_ADMIN_EMAIL was not created") {
		t.Errorf("the skip was silent; the operator is left guessing:\n%s", buf.String())
	}
}

// A password shorter than the service's own minimum cannot seed an account. The
// run says so and creates nothing, rather than writing a credential that the
// login path then refuses.
func TestFirstStartAdminSeedRefusesAShortPassword(t *testing.T) {
	cfg := initConfig(t, false)
	cfg.env["admin_password"] = "short"
	t.Setenv("DEFAULT_ADMIN_EMAIL", "test-admin@example.com")
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 0 {
		t.Fatalf("created %d admin(s) from a %d-character password", len(admins), len(cfg.AdminPassword()))
	}
	if !hasLog(buf, "admin seed skipped: the admin password is too short") {
		t.Errorf("no warning about the rejected password:\n%s", buf.String())
	}
}

// Not an address is not an account. The value is echoed back so an operator
// reading a container log can see the typo.
func TestFirstStartAdminSeedRejectsANonAddress(t *testing.T) {
	cfg := initConfig(t, false)
	t.Setenv("DEFAULT_ADMIN_EMAIL", "not-an-address")
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	admins, _ := store.ListAdmins(ctx)
	if len(admins) != 0 {
		t.Fatalf("created %d admin(s) from %q", len(admins), "not-an-address")
	}
	if !hasLog(buf, "DEFAULT_ADMIN_EMAIL is not an email address") {
		t.Errorf("no warning about the bad address:\n%s", buf.String())
	}
}

// The "green but locked out" case, closed: a fresh instance with no variable
// still gets a login, from the built-in address, and the log says which address
// it used and that the variable was not set.
func TestFirstStartFallsBackToTheBuiltInAdminAddress(t *testing.T) {
	cfg := initConfig(t, false)
	t.Setenv("DEFAULT_ADMIN_EMAIL", "")
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 1 || admins[0].Email != defaultAdminEmail {
		t.Fatalf("admins after a first start with no variable = %v, want one %s", admins, defaultAdminEmail)
	}
	if !hasLog(buf, "seeding the built-in address") {
		t.Errorf("the fallback happened silently:\n%s", buf.String())
	}
}

// Dev mode already seeds dev@localhost (cmd/signsrv/devadmin.go). The first-start
// seed has to leave that job alone, or a dev run ends up with two accounts and
// an operator guessing which one works.
func TestFirstStartSeedLeavesDevModeToTheDevAccount(t *testing.T) {
	cfg := initConfig(t, true)
	ctx := context.Background()
	log, buf := captureLog(t)

	_, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		t.Fatalf("firstStartInit: %v", err)
	}
	defer store.Close()

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 0 {
		t.Fatalf("got %d admins before ensureDevAdmin ran, want none", len(admins))
	}
	if !keystorePresent(cfg) {
		t.Errorf("dev first start did not create a CA")
	}
	// A dev first start still says what it did about the CA, so a throwaway
	// instance is no harder to audit than a real one.
	if !hasLog(buf, "signing CA ready") {
		t.Errorf("dev first start did not report the CA:\n%s", buf.String())
	}
}

// captureLogOnly is captureLog for a run whose log a test does not inspect.
func captureLogOnly(t *testing.T) *slog.Logger {
	t.Helper()
	log, _ := captureLog(t)
	return log
}

// signstoreVersion is the schema version of an open store, named so the tests
// read as the question ("did the schema arrive?") rather than as a call into
// another package.
func signstoreVersion(ctx context.Context, store *signstore.Store) (int, error) {
	return signstore.SchemaVersion(ctx, store.DB())
}
