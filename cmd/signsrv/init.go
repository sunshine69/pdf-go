// First-start initialization: the run a service makes when it meets an empty
// state directory.
//
// Three objects define an instance, and all three were created lazily, by
// whichever call first needed them: the database schema (signstore.Migrate),
// the signing CA (signpdf.LoadCAWith, inside signpdf.NewService) and the token
// key (signauth.LoadKeyring). Lazy creation works, but it leaves an operator
// with no record of what was made, when, or under what name — and the CA is the
// one object that can never be changed afterwards, because every signature
// already issued leads to it. So `serve` now decides up front, from an intent
// to initialize, and says what it did.
//
// DEFAULT_ADMIN_EMAIL (environment only, never a config key) names the account
// to create at first start. It is deliberately not a config setting: an address
// in a file cannot say "on purpose", and a service that creates an admin
// because a line in a file mentions an address is the behaviour this project
// refused in production — see docs/DEPLOY-DOCKER.md, "Accounts". The deb
// package's equivalent is SIGNSETUP_ADMIN_EMAIL, read by
// packaging/deb/signsrv-firstboot.sh; a container runs no firstboot script, so
// this is the path a container takes.
//
// A keystore that is half present is NOT a first start: one file and not the
// other is a damaged keystore, and signpdf.LoadCAWith refuses exactly that
// rather than issuing a second CA over the surviving half. That refusal is
// preserved — this file only decides the subject of a CA it is certain is new.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// adminEmailEnvVar names the account to create at first start. Setup input,
// not a service setting: after the first start the accounts are rows in the
// database and `admin add` decides who is one.
const adminEmailEnvVar = "DEFAULT_ADMIN_EMAIL"

// defaultAdminEmail is the address used when DEFAULT_ADMIN_EMAIL is unset. A
// first start that creates no account is the failure this project kept hitting:
// the container comes up green, /healthz answers 200, and /admin/ refuses every
// login because the password belongs to nobody (docs/DEPLOY-DOCKER.md,
// "Accounts"). So a new instance gets a login even when the operator named
// none, and the log says which address it used and that it was the fallback.
const defaultAdminEmail = "admin@pdfsign.com"

// stateFile is one file whose presence answers "has this instance run before?".
type stateFile struct {
	label string
	path  string
}

// stateFiles lists the files to look at, in the order the service creates them.
// The database and the two halves of the keystore; not the JWT key, the storage
// directory or the outbox — those are recreated on their own without any
// consequence for documents already signed, so their absence must not make a
// live instance look new.
func stateFiles(cfg *Config) []stateFile {
	return []stateFile{
		{"database", cfg.DBFile()},
		{"ca.crt", filepath.Join(cfg.Keystore, "ca.crt")},
		{"ca.key", filepath.Join(cfg.Keystore, "ca.key")},
	}
}

// keystorePresent answers whether this instance already has a CA. Both halves
// are required: a keystore with one file is damaged, not present, and the
// damage is reported by LoadCAWith when the service opens it.
func keystorePresent(cfg *Config) bool {
	cert, key := cfg.Keystore, cfg.Keystore
	_, e1 := os.Stat(filepath.Join(cert, "ca.crt"))
	_, e2 := os.Stat(filepath.Join(key, "ca.key"))
	return e1 == nil && e2 == nil
}

// fileState is the state of one path as a word an operator can read in a log.
//
// Only "does not exist" counts as absent. A permission error, a directory where
// a file should be, or an unreadable volume mount is reported as unreadable,
// because reading it as absent would decide "this CA has never been issued" from
// a failure to look at it — and the action that follows from that decision is
// issuing a new CA.
func fileState(path string) string {
	info, err := os.Stat(path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return "present"
	case err == nil:
		// A directory where a file belongs. It is not absent — and calling it
		// present would let the keystore open read it as damage, which is the
		// right answer, but only after this check stops claiming the instance
		// is new.
		return "unreadable: " + path + " is not a regular file"
	case errors.Is(err, os.ErrNotExist):
		return "absent"
	default:
		return "unreadable: " + err.Error()
	}
}

// firstStart answers: no database, and neither half of a keystore?
//
// An unreadable state file is an error, not a guess. The caller logs it and
// starts anyway; what it must not do is create a CA on the strength of a stat
// that failed.
func firstStart(cfg *Config) (bool, []string, error) {
	files := stateFiles(cfg)
	listing := make([]string, 0, len(files))
	fresh := true
	for _, f := range files {
		if f.path == "" {
			return false, nil, fmt.Errorf("cannot check the %s: the store is not a SQLite file (%s)", f.label, cfg.DBPath)
		}
		state := fileState(f.path)
		listing = append(listing, f.label+"="+state+" "+f.path)
		switch state {
		case "absent":
		case "present":
			fresh = false
		default:
			return false, listing, fmt.Errorf("cannot read the %s at %s (%s)", f.label, f.path, state)
		}
	}
	return fresh, listing, nil
}

// instanceName is the host part of public_url: the name a fresh CA is issued
// for when the operator set no ca_* key. "" when the URL holds nothing a
// certificate subject can carry — an IP address, a bare port, or nothing at all
// — in which case the built-in "signsrv CA" name is kept.
func instanceName(cfg *Config) string {
	name := strings.TrimSpace(cfg.PublicURL)
	name = strings.TrimPrefix(strings.TrimPrefix(name, "https://"), "http://")
	if i := strings.IndexAny(name, "/?#"); i >= 0 {
		name = name[:i]
	}
	if host, _, err := net.SplitHostPort(name); err == nil {
		name = host
	}
	if name == "" || net.ParseIP(name) != nil {
		return ""
	}
	return name
}

// firstStartCASubject decides the identity of a CA this run is about to create.
//
// The subject is written once and is permanent: re-issuing a keystore to match a
// changed config would break every document signed under the old name, so
// signpdf ignores a changed subject on a keystore that exists (internal/signpdf,
// LoadCAWith). That makes the first run the only one where the choice matters,
// and the built-in fallback — "signsrv CA" — is the one thing a deployment can
// do better than the default, because the deployment knows its own host.
//
// The operator's ca_* keys win outright. Dev mode keeps the historical name: a
// dev instance has no public host worth putting in a certificate, and its runs
// should look like every earlier dev run.
func firstStartCASubject(cfg *Config) *signpdf.CASubject {
	if cfg.CASubject != nil {
		return cfg.CASubject
	}
	if cfg.Dev {
		return nil
	}
	name := instanceName(cfg)
	if name == "" {
		return nil
	}
	return &signpdf.CASubject{CommonName: name + " Document Signing CA", Organization: name}
}

// initStore opens the database and runs the migrations, logging what the CLI
// path (openStore) prints to stdout. Migrations run before anything else at
// start: every other step here writes to the database, and the tables they
// write to are created by them.
func initStore(ctx context.Context, cfg *Config, log *slog.Logger) (*signstore.Store, error) {
	// SQLite creates the file under the process umask, which is usually 022.
	// The config warns about a database file that anyone on the machine can
	// read (cmd/signsrv/config.go), and the warning is right: the users table
	// holds each account's shared secret. A file this run created is the one
	// file this run can choose the mode of, so it gets the mode the config
	// asks for instead of a warning the operator has to act on by hand.
	dbFile := cfg.DBFile()
	dbPreexisting := dbFile != "" && fileState(dbFile) == "present"
	store, applied, err := openMigrated(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if dbFile != "" && !dbPreexisting {
		if err := os.Chmod(dbFile, 0o600); err != nil {
			store.Close()
			return nil, fmt.Errorf("set mode on the new database file: %w", err)
		}
	}
	version, err := signstore.SchemaVersion(ctx, store.DB())
	if err != nil {
		version = -1
	}
	if applied > 0 {
		log.Info("database migrations applied", "applied", applied, "schema_version", version, "db", cfg.DBPath)
	} else {
		log.Info("database ready", "schema_version", version, "db", cfg.DBPath)
	}
	return store, nil
}

// initSigningCA opens the keystore, creating the CA when this instance has
// none, and reports which of the two happened.
//
// created is decided from the state read BEFORE the open, not from the open's
// result: signpdf.NewService both loads and creates, and a log line that says
// "created" for a keystore it merely opened is a lie about the one object that
// cannot be corrected afterwards.
func initSigningCA(cfg *Config, log *slog.Logger, fresh bool) (*signpdf.Service, bool, error) {
	before := keystorePresent(cfg)
	subject := firstStartCASubject(cfg)
	switch {
	case !before && fresh && subject != nil:
		// The name is about to become permanent, so it is printed before the
		// certificate exists: after it exists, changing the config is not an
		// action anyone can take.
		log.Info("first start: issuing the signing CA",
			"keystore_dir", cfg.Keystore,
			"ca_subject", subjectLine(subject),
			"note", "the ca_* config keys are honoured on this first run only; this certificate is fixed for its whole life")
	case !before && fresh:
		log.Info("first start: issuing the signing CA",
			"keystore_dir", cfg.Keystore,
			"ca_subject", "default (CN=signsrv CA)",
			"note", "set the ca_* config keys before the first start to name this CA; they are honoured on this run only")
	case !before:
		// A database that has run before, with no keystore: this start issues a
		// SECOND root over the same instance. Documents signed under the earlier
		// CA still verify — verification needs the certificate, which is public —
		// but the recipient who imported the first one now has an anchor that
		// does not match. That is loud enough to deserve a WARN.
		log.Warn("issuing a new signing CA on an instance that already has a database",
			"keystore_dir", cfg.Keystore,
			"ca_subject", subjectLine(subject),
			"note", "documents already signed still verify against their own certificate, but this instance now signs under a new root; if the keystore was lost rather than never created, restoring ca.crt and ca.key keeps one root")
	}
	fontData, fontName := selftestFont(cfg)
	svc, err := signpdf.NewService(signpdf.Config{
		KeystoreDir: cfg.Keystore,
		Passphrase:  cfg.KeystorePassphrase(),
		CASubject:   subject,
		TSAURL:      cfg.TSAURL,
		FontData:    fontData,
		FontName:    fontName,
		Clock:       time.Now,
	})
	if err != nil {
		return nil, false, err
	}
	created := !before
	ca := svc.CA()
	if ca == nil || ca.Cert == nil {
		return svc, created, nil
	}
	log.Info("signing CA ready",
		"created", created,
		"keystore_dir", cfg.Keystore,
		"ca_subject", ca.Cert.Subject.String(),
		"ca_fingerprint", ca.Fingerprint(),
		"ca_serial", ca.Cert.SerialNumber.String(),
		"ca_expires", ca.Cert.NotAfter.Format("2006-01-02"),
		"note", "the fingerprint is what a recipient checks before importing ca.crt; the certificate is at /ca.crt and the fingerprint at /api/v1/ca")
	return svc, created, nil
}

// subjectLine renders a derived subject the way checkconfig renders a
// configured one, so the same words appear in both places.
func subjectLine(s *signpdf.CASubject) string {
	if s == nil {
		return "default (CN=signsrv CA)"
	}
	parts := make([]string, 0, 2)
	if s.CommonName != "" {
		parts = append(parts, "CN="+s.CommonName)
	}
	if s.Organization != "" {
		parts = append(parts, "O="+s.Organization)
	}
	return strings.Join(parts, ", ")
}

// initJWTKey loads the token key, creating it when absent. LoadKeyring already
// creates with 0600; the log line exists so the creation is attributed to this
// start rather than discovered when someone wonders where the key came from.
func initJWTKey(cfg *Config, log *slog.Logger) error {
	path := cfg.JWTFile()
	if path == "" {
		return nil
	}
	_, existed := os.Stat(path)
	if _, err := signauth.LoadKeyring(path); err != nil {
		return err
	}
	if os.IsNotExist(existed) {
		log.Info("token signing key created", "file", path, "mode", "0600")
	}
	return nil
}

// firstStartInit is the whole first-start run: state, schema, CA, token key,
// admin account. It returns the signing service the caller hands to the server,
// so the CA the log describes is the CA the process then signs with.
//
// A failure to read the state is a warning, not a refusal: the steps that
// follow are the ones that already ran at every start, and refusing to start
// over a stat error would take a healthy instance down. What it does not do is
// name a CA subject for an instance it could not prove was new.
func firstStartInit(ctx context.Context, cfg *Config, log *slog.Logger) (*signpdf.Service, *signstore.Store, error) {
	fresh, listing, err := firstStart(cfg)
	if err != nil {
		log.Warn("first-start check", "error", err.Error(), "state", strings.Join(listing, "; "))
	} else if fresh {
		log.Info("first start: initializing the instance", "state", strings.Join(listing, "; "))
	}

	store, err := initStore(ctx, cfg, log)
	if err != nil {
		return nil, nil, err
	}
	if err := initJWTKey(cfg, log); err != nil {
		store.Close()
		return nil, nil, err
	}
	svc, created, err := initSigningCA(cfg, log, fresh)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	if created {
		recordCAIdentity(ctx, store, svc, log)
	}
	seedAdminFromEnv(ctx, cfg, store, log, fresh)
	return svc, store, nil
}

// recordCAIdentity puts the CA's fingerprint and serial where `signsrv dbstatus`
// can print them. A fresh instance's first log line is gone from a container's
// terminal by the time anyone asks which CA this database signed with, and the
// settings table is the only place that outlives the log.
func recordCAIdentity(ctx context.Context, store *signstore.Store, svc *signpdf.Service, log *slog.Logger) {
	ca := svc.CA()
	if ca == nil || ca.Cert == nil {
		return
	}
	for _, kv := range [][2]string{
		{"ca_fingerprint", ca.Fingerprint()},
		{"ca_serial", ca.Cert.SerialNumber.String()},
	} {
		if err := store.SetSetting(ctx, kv[0], kv[1]); err != nil {
			log.Warn("could not record the CA identity in the settings table", "key", kv[0], "error", err.Error())
		}
	}
}

// seedAdminFromEnv creates the account DEFAULT_ADMIN_EMAIL names, when this
// instance is new and has no admins.
//
// Idempotence is the point: a container restarts, and an account created on the
// first start must not become an error on the second, nor a second account on
// an instance that has since gained one. So the rule is: create only on a fresh
// instance with no admins; otherwise stay silent when the address already is an
// admin, and say what to run when it is not.
//
// Nothing here is fatal. A seed that fails leaves a service that serves, signs,
// and has no login — which the warning states, along with the command that
// fixes it. `admin add` is the operator's path either way.
func seedAdminFromEnv(ctx context.Context, cfg *Config, store *signstore.Store, log *slog.Logger, fresh bool) {
	if store == nil {
		return
	}
	email := strings.ToLower(strings.TrimSpace(os.Getenv(adminEmailEnvVar)))
	fallback := false
	if email == "" {
		// Nothing named. A new instance still gets a login, from the built-in
		// address; an instance that has already run does not, because creating
		// an account there is an operator's decision, made with a command. Dev
		// mode is left to its own account (ensureDevAdmin, dev@localhost).
		if !fresh || cfg.Dev {
			return
		}
		email = defaultAdminEmail
		fallback = true
		log.Info("seeding the built-in address",
			"email", email,
			"hint", "set "+adminEmailEnvVar+" before the first start to name it yourself")
	}
	if !validEmail(email) {
		log.Warn(adminEmailEnvVar+" is not an email address", "value", email,
			"hint", "no account was created; fix the value and restart, or run: signsrv-utils admin add "+email)
		return
	}

	admins, err := store.ListAdmins(ctx)
	if err != nil {
		log.Warn("admin seed: could not read the admins table", "error", err.Error())
		return
	}
	for _, a := range admins {
		if a.Email == email {
			return // already an account, by this or an earlier start: nothing to do
		}
	}
	if !fresh {
		// The first start is over. Creating an account now is an operator's
		// decision to make with a command, not something a restart should do.
		log.Warn(adminEmailEnvVar+" was not created", "email", email, "admins", len(admins),
			"hint", "this instance already exists, so the account is added by hand: signsrv-utils admin add "+email)
		return
	}

	pw := cfg.AdminPassword()
	if pw == "" {
		log.Warn("admin seed skipped: no admin password to seed", "email", email,
			"hint", "set ADMIN_PASSWORD (12 characters or more) and restart")
		return
	}
	if len(pw) < 12 {
		log.Warn("admin seed skipped: the admin password is too short", "email", email, "characters", len(pw),
			"hint", "ADMIN_PASSWORD must be at least 12 characters; nothing was created")
		return
	}
	hash, err := signauth.HashPassword(pw)
	if err != nil {
		log.Warn("admin seed: password hash", "error", err.Error())
		return
	}
	id, err := store.AddAdmin(ctx, email, hash, "admin")
	if err != nil {
		log.Warn("admin seed: could not create the account", "email", email, "error", err.Error())
		return
	}
	source := adminEmailEnvVar + " with the ADMIN_PASSWORD in the environment"
	if fallback {
		source = "the built-in address, " + adminEmailEnvVar + " was not set"
	}
	log.Info("admin account created", "email", email, "id", id, "source", source,
		"note", "rotate it when convenient: signsrv admin passwd "+email)
}
