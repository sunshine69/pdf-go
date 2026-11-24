package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signpdf"
)

// Config is the effective configuration of the service.
//
// Secret values are never exported as plain fields: the loader stores
// digests of them and hands out accessor functions, so a logger that walks
// the struct cannot print a secret. A secret value lives in memory only for
// the call that needs it.
type Config struct {
	// Paths and listeners.
	Listen     string
	PublicURL  string
	DBPath     string
	StorageDir string
	Keystore   string
	Outbox     string
	// CASubject identifies the CA certificate when a keystore is created on
	// first start. nil leaves the built-in "signsrv CA" name in place.
	CASubject  *signpdf.CASubject
	TrustProxy bool
	Dev        bool
	// SignLimits are the per-route request budgets. Loaded from the
	// rate_limit_* keys; unset keys keep the built-in defaults. A negative
	// value switches that bucket off.
	SignLimits signauth.Limits
	// WorkerInterval is how often the worker drains the mail queue and
	// advances expiries. A zero interval means the worker does not run.
	WorkerInterval time.Duration
	LogPath        string
	LogLevel       string
	MaxPDFMB       int
	// AuditDir is where the nightly audit files are written. The chain of
	// hashes across the files is what makes a tampered audit log detectable.
	AuditDir string
	// DownloadsDir holds the binaries a recipient is sent to download, served
	// read-only at /dl/. Empty means the instance offers no downloads and the
	// endpoint says so, rather than guessing a path.
	DownloadsDir string

	// Signing policy.
	TSAURL  string
	LinkTTL time.Duration

	// Mail, non-secret part.
	SMTPHost     string
	SMTPPort     int
	SMTPStartTLS bool
	SMTPUser     string
	MailFrom     string

	// Secret digests, for logging and for config checks. The secret itself is
	// returned by the accessor, which reads the environment again.
	env             map[string]string
	file            map[string]string
	keystoreDigest  string
	jwtFile         string
	keystoreSet     bool
	smtpPassDigest  string
	adminPassDigest string
	warnings        []string

	problems []string

	// path is the config file this configuration was read from, empty when the
	// values came from the environment. A CLI command that runs on the same
	// machine as the database resolves the path of the store through it.
	path string
}

// ConfigPath is the file this configuration was loaded from, "" when the
// settings came from the environment.
func (c *Config) ConfigPath() string { return c.path }

// DBFile is the SQLite path this configuration points at, "" when the store is
// postgres. The local CLI commands (user add, user rotate) need it: the
// credentials live in the database, and only a process on the database's own
// machine is allowed to write them.
func (c *Config) DBFile() string {
	if strings.HasPrefix(c.DBPath, "postgres://") || strings.HasPrefix(c.DBPath, "postgresql://") {
		return ""
	}
	return c.DBPath
}

// secret returns the raw value of a config secret. It is deliberately a
// method: the value never appears in the struct, in a log line, or in a JSON
// dump of the configuration.
//
// The value may come from the environment (*) or from the config
// file; the environment wins.
func (c *Config) secret(key string) string {
	if v := c.env[key]; v != "" {
		return v
	}
	return c.file[key]
}

// KeystorePassphrase returns the keystore passphrase.
func (c *Config) KeystorePassphrase() string { return c.secret("keystore_pass") }

// SMTPPassword returns the SMTP password.
func (c *Config) SMTPPassword() string { return c.secret("smtp_pass") }

// AdminPassword returns the initial admin password. It is only used to seed
// the admin account at first start; after that the hash in the database is
// the source of truth.
func (c *Config) AdminPassword() string { return c.secret("admin_password") }

// JWTFile is the Ed25519 key the access tokens are signed with. It is a path,
// not a secret, and it is 0600.
func (c *Config) JWTFile() string { return c.jwtFile }

// LoadConfig reads the optional file and then the environment, the
// environment winning over the file. It validates the combination, not just
// the individual values, and collects every problem it finds.
func LoadConfig(path string) (*Config, error) {
	file := map[string]string{}
	if path != "" {
		v, err := readConfigFile(path)
		if err != nil {
			return nil, err
		}
		file = v
	}
	// The environment names are the config keys, uppercased: PUBLIC_URL,
	// KEYSTORE_PASS, ADMIN_PASSWORD. The service is scoped by how it is
	// launched — a systemd unit with EnvironmentFile, a container with an
	// env_file — so the names do not need a product prefix to be unambiguous.
	// That is the only spelling: an unrelated variable in the environment is
	// not a setting, and the loader never chooses between two names for one
	// value.
	env := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" {
			continue
		}
		if name := strings.ToLower(k); configKeys[name] {
			env[name] = v
		}
	}
	get := func(key, def string) string {
		if v, ok := env[key]; ok && v != "" {
			return v
		}
		if v, ok := file[key]; ok && v != "" {
			return v
		}
		return def
	}

	c := &Config{env: env, file: file, path: path}

	boolVal := func(key string, def bool) bool {
		raw := get(key, "")
		switch strings.ToLower(raw) {
		case "":
			return def
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
		cproblems(c, key+": not a boolean (use true/false): "+raw)
		return def
	}
	c.Listen = get("listen", "127.0.0.1:8080")
	c.PublicURL = get("public_url", "")
	c.DBPath = firstNonEmpty(get("db", ""), get("db_path", "var/signsrv.db"))
	c.StorageDir = get("storage_dir", "var/storage")
	c.Keystore = get("keystore_dir", "var/keystore")
	c.keystoreSet = env["keystore_dir"] != "" || file["keystore_dir"] != ""
	c.CASubject = caSubjectFrom(get)
	c.Outbox = get("outbox_dir", "var/outbox")
	c.TSAURL = get("tsa_url", "https://freetsa.org/tsr")
	c.SMTPHost = get("smtp_host", "")
	c.SMTPStartTLS = boolVal("smtp_starttls", true)
	c.SMTPUser = get("smtp_user", "")
	c.MailFrom = get("mail_from", "")
	c.jwtFile = get("jwt_secret_file", "var/jwt.ed25519.key")

	c.WorkerInterval, _ = duration(get("worker_interval", "15s"), 15*time.Second)

	c.Dev = boolVal("dev", false)
	c.TrustProxy = boolVal("trust_proxy", false)
	c.SignLimits = loadLimits(c, get)

	var err error
	if c.TSAURL == "" {
		c.TSAURL = "https://freetsa.org/tsr"
	}
	c.LinkTTL, err = duration(get("link_ttl", "168h"), 168*time.Hour)
	if err != nil {
		cproblems(c, "link_ttl: "+err.Error())
	}
	c.MaxPDFMB, err = atoi(get("max_pdf_mb", "25"), 25)
	if err != nil {
		cproblems(c, "max_pdf_mb: "+err.Error())
	}
	c.SMTPPort, err = atoi(get("smtp_port", "587"), 587)
	if err != nil {
		cproblems(c, "smtp_port: "+err.Error())
	}

	c.LogPath = get("log_path", "var/log/signsrv.jsonl")
	c.AuditDir = get("audit_dir", "var/audit")
	c.DownloadsDir = get("downloads_dir", "")
	c.LogLevel = strings.ToLower(get("log_level", "info"))
	switch c.LogLevel {
	case "debug", "info", "warn", "error", "warning":
	case "":
		c.LogLevel = "info"
	default:
		cproblems(c, "log_level must be debug, info, warn or error: "+c.LogLevel)
	}

	// Dev mode must be runnable with an empty configuration: generate
	// ephemeral secrets so the service can create its keystore and seed the
	// admin account. serve prints them once, at startup, in dev mode only.
	if c.Dev {
		if c.file["keystore_pass"] == "" && c.env["keystore_pass"] == "" {
			c.file["keystore_pass"] = "dev-" + randomHex(16)
		}
		if c.file["admin_password"] == "" && c.env["admin_password"] == "" {
			c.file["admin_password"] = "dev-" + randomHex(8)
		}
	}

	c.keystoreDigest = digest(c.KeystorePassphrase())
	c.smtpPassDigest = digest(c.SMTPPassword())
	c.adminPassDigest = digest(c.AdminPassword())

	c.validate()
	if len(c.problems) > 0 {
		return c, fmt.Errorf("configuration is not usable:\n  %s",
			strings.Join(c.problems, "\n  "))
	}
	return c, nil
}

func (c *Config) validate() {
	// The service speaks plain HTTP. Where the listener sits is the operator's
	// infrastructure decision, not this service's, so nothing here stops a bind
	// that reaches beyond the machine: a mesh with mutual TLS, a sidecar proxy,
	// or a private VLAN all make a public bind correct. The tradeoff is stated
	// once, in a run the service is willing to have.
	//
	// It is read before the dev branch so that a dev instance on a public bind
	// hears it too: in dev the keystore passphrase and the admin password are
	// generated at start and printed to the log, so a listener that reaches the
	// network is the one place where reading that log is enough to sign.
	if !bindsLoopbackOnly(c.Listen) {
		cwarnings(c, "listen binds outside loopback ("+c.Listen+"): the service serves plain HTTP, so TLS, a proxy, or network policy must terminate encryption in front of it, or party tokens and the admin password cross the network in the clear")
	}
	if c.Dev {
		return
	}
	if !strings.HasPrefix(c.PublicURL, "https://") {
		cproblems(c, "public_url must start with https:// (signing links carry a token)")
	}
	if c.PublicURL == "" {
		cproblems(c, "public_url is required: it builds the signing links")
	}
	if c.LinkTTL <= 0 || c.LinkTTL > 720*time.Hour {
		cproblems(c, "link_ttl must be between 1ns and 720h")
	}
	if c.SMTPHost == "" {
		cproblems(c, "smtp_host is required when dev mode is off (set DEV=1 to write mail to var/outbox)")
	}
	if c.MailFrom == "" {
		cproblems(c, "mail_from is required")
	}
	if c.KeystorePassphrase() == "" {
		cproblems(c, "keystore_pass is required: it protects the signing CA key")
	}
	if c.AdminPassword() == "" {
		cproblems(c, "admin_password is required: it seeds the admin account at first start")
	}
	if c.MaxPDFMB <= 0 || c.MaxPDFMB > 200 {
		cproblems(c, "max_pdf_mb must be between 1 and 200")
	}
	// The keystore holds the CA private key. If the directory the operator
	// named is not there, the service starts and fails at the first
	// signature. The default path is a relative one, used in dev, so it is
	// not checked: it is created at first use.
	//
	// A directory that does not exist yet is not the same finding as a
	// directory that cannot be read: a fresh instance is exactly the case
	// first-start initialization is for, and it creates this one (see
	// firstStartInit). So a missing path whose parent is there and is a
	// directory is a warning about what is about to happen; a missing path
	// under a parent that is not there is still the typo this check was
	// written to catch.
	if c.keystoreSet {
		switch f, err := os.Stat(c.Keystore); {
		case err == nil:
			if !f.IsDir() {
				cproblems(c, "keystore_dir is not a directory: "+c.Keystore)
			}
		case errors.Is(err, os.ErrNotExist):
			parent := filepath.Dir(c.Keystore)
			if pf, perr := os.Stat(parent); perr == nil && pf.IsDir() {
				cwarnings(c, "keystore_dir does not exist yet: "+c.Keystore+", the signing CA is issued at first start")
			} else {
				cproblems(c, "keystore_dir is not readable, and its parent directory is not there to create it: "+c.Keystore)
			}
		default:
			cproblems(c, "keystore_dir is not readable: "+c.Keystore)
		}
	}

	// The API signing key mints admin tokens, so it is readable by the
	// service and by nobody else.
	if c.jwtFile != "" {
		if f, err := os.Stat(c.jwtFile); err == nil {
			if f.Mode().Perm()&0o077 != 0 {
				cproblems(c, "jwt_secret_file is readable by others: mode must be 0600")
			}
		}
	}

	// The users table holds each account's shared secret in the clear, because
	// the service has to recompute the signature. The database file is
	// therefore a secret, and the mode says whether it is.
	if f, err := os.Stat(c.DBFile()); err == nil && f.Mode().Perm()&0o077 != 0 {
		cwarnings(c, "the database file is readable by others: mode must be 0600, it holds the account secrets")
	}

	// The timestamp authority signs the time in the signature. Over plain
	// HTTP a man in the middle can substitute a timestamp, which is the
	// one field a forged document needs.
	if strings.HasPrefix(c.TSAURL, "http://") {
		cwarnings(c, "tsa_url is not HTTPS: the timestamp is unauthenticated")
	}

	// The service reads the keystore and the signing key as the user it runs
	// as. As root, a compromised process has the whole machine.
	if os.Geteuid() == 0 {
		cwarnings(c, "running as root: run signsrv as the signsrv user")
	}
}

// Problems lists every configuration problem found.
func (c *Config) Problems() []string { return c.problems }

// Warnings lists every configuration warning found. A warning does not stop
// the service: it names a setting that works and should not be used.
func (c *Config) Warnings() []string { return c.warnings }

// Redacted prints the configuration with secrets replaced by digests.
func (c *Config) Redacted() string {
	dur := c.LinkTTL.String()
	return strings.Join([]string{
		"listen=" + c.Listen,
		"public_url=" + c.PublicURL,
		"db_path=" + c.DBPath,
		"storage_dir=" + c.StorageDir,
		"keystore_dir=" + c.Keystore,
		"ca_subject=" + c.describeCASubject(),
		"keystore_pass=" + c.keystoreDigest,
		"admin_password=" + c.adminPassDigest,
		"jwt_secret_file=" + c.jwtFile,
		"tsa_url=" + c.TSAURL,
		"link_ttl=" + dur,
		"max_pdf_mb=" + strconv.Itoa(c.MaxPDFMB),
		"log_path=" + c.LogPath,
		"audit_dir=" + c.AuditDir,
		"log_level=" + c.LogLevel,
		"smtp_host=" + c.SMTPHost,
		"smtp_port=" + strconv.Itoa(c.SMTPPort),
		"smtp_starttls=" + strconv.FormatBool(c.SMTPStartTLS),
		"smtp_user=" + c.SMTPUser,
		"smtp_pass=" + c.smtpPassDigest,
		"mail_from=" + c.MailFrom,
		"trust_proxy=" + strconv.FormatBool(c.TrustProxy),
		// One line for the whole budget set rather than eleven. The point of
		// printing it at all is that an operator comparing two instances can
		// see at a glance whether their limits differ.
		"rate_limits=" + c.describeLimits(),
		"dev=" + strconv.FormatBool(c.Dev),
	}, "\n")
}

// describeLimits renders the budget set as one compact line. A bucket that is
// switched off reads "off" rather than a negative number, because the summary
// is read by a person.
func (c *Config) describeLimits() string {
	l := c.SignLimits.Normalise()
	n := func(v int) string {
		if v <= 0 {
			return "off"
		}
		return strconv.Itoa(v)
	}
	return "login=" + n(l.Login) +
		" claim=" + n(l.Claim) +
		" consent=" + n(l.Consent) +
		" link=" + n(l.Link) +
		" create=" + n(l.Create) +
		" send=" + n(l.Send) +
		" api=" + n(l.API) +
		" remind=" + n(l.Remind) + "/" + l.RemindWindow.String() +
		" mail_test=" + n(l.MailTest) +
		" window=" + l.Window.String()
}

// KeystoreDigest is the digest of the keystore passphrase, safe to log.
func (c *Config) KeystoreDigest() string { return c.keystoreDigest }

// readConfigFile parses KEY=value lines, ignoring comments and blank lines.
func readConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		// One spelling per setting, in the file as in the environment.
		k = strings.ToLower(strings.TrimSpace(k))
		if !configKeys[k] {
			// The one mistyping this file shape invites is an environment
			// variable's name written into it. The answer is named rather
			// than left to be worked out; the key is still refused.
			if base := strings.TrimPrefix(k, "signsrv_"); base != k && configKeys[base] {
				return nil, fmt.Errorf("%s:%d: unknown config key %q: a file uses the plain key, write %q", path, n, k, base)
			}
			return nil, fmt.Errorf("%s:%d: unknown config key %q (see config.example.env)", path, n, k)
		}
		out[k] = strings.TrimSpace(strings.Trim(v, `"'`))
	}
	return out, sc.Err()
}

// configKeys is the set of recognised configuration keys. It does two jobs:
// a typo in a config file fails at startup instead of being silently ignored,
// and it is the whitelist for the environment — the env name for a key is the
// key uppercased (public_url and PUBLIC_URL), and an environment variable that
// is not one of these is ignored rather than becoming a setting. The names are
// short — DB, DEV, CONFIG are words a shell or a build tool already has in the
// environment — which is why the whitelist matters: a variable that is not a
// key has to stay out of the configuration, and there is no second spelling
// that could let it in.
var configKeys = map[string]bool{
	"listen": true, "public_url": true, "db": true, "db_path": true,
	"storage_dir": true, "keystore_dir": true, "outbox_dir": true,
	"keystore_pass": true, "admin_password": true, "jwt_secret_file": true,
	"ca_common_name": true, "ca_org": true, "ca_unit": true, "ca_email": true,
	"ca_locality": true, "ca_province": true, "ca_street": true,
	"ca_postal": true, "ca_country": true,
	"tsa_url": true, "link_ttl": true, "max_pdf_mb": true,
	"smtp_host": true, "smtp_port": true, "smtp_starttls": true,
	"smtp_user": true, "smtp_pass": true, "mail_from": true,
	"trust_proxy": true, "dev": true, "log_level": true, "log_path": true,
	"audit_dir": true, "downloads_dir": true,
	// worker_interval is read by Load (below) and documented in
	// config.example.env, so the parser has to accept it: an operator who sets
	// it in a config file gets a hard error otherwise, which is how a documented
	// knob becomes an unreachable one.
	"worker_interval": true,
	// The rate limits. Each is optional and defaults to the built-in value;
	// a negative value switches that bucket off. rate_limit_window is the
	// span every bucket counts except the remind bucket, which has its own.
	"rate_limit_login": true, "rate_limit_claim": true,
	"rate_limit_consent": true, "rate_limit_link": true,
	"rate_limit_create": true, "rate_limit_send": true,
	"rate_limit_api": true, "rate_limit_remind": true,
	"rate_limit_mail_test": true, "rate_limit_window": true,
	"rate_limit_remind_window": true,
}

func duration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration: %w", s, err)
	}
	return d, nil
}

func atoi(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def, fmt.Errorf("%q is not a number: %w", s, err)
	}
	return n, nil
}

// bindsLoopbackOnly answers one question: does this address reach only this
// machine? An empty host is NOT loopback - `:8080` means "every interface" to
// net.Listen, and the old helper called that loopback, so a config of
// listen=:8080 was waved through while binding every interface on the host.
//
// Nothing here stops a bind the function rejects. It only decides whether the
// plain-HTTP warning is worth printing.
func bindsLoopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port given
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1" ||
		strings.HasPrefix(host, "127.")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// randomHex returns n random bytes as hex, for the ephemeral dev secrets.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "unreadable"
	}
	return hex.EncodeToString(b)
}

func digest(s string) string {
	if s == "" {
		return "unset"
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// loadLimits reads the rate_limit_* keys into the default budget set. Every
// key is optional, which is what makes the section additive rather than a
// breaking change: an instance with no rate_limit_ lines runs exactly the
// limits it ran with before these keys existed.
//
// A value that is not a number is a problem, not a silent fallback, because a
// limit the operator typed wrong is a limit they believe they set. A negative
// value is accepted and switches that bucket off.
func loadLimits(c *Config, get func(key, def string) string) signauth.Limits {
	l := signauth.DefaultLimits()
	for _, k := range []struct {
		key string
		set *int
	}{
		{"rate_limit_login", &l.Login},
		{"rate_limit_claim", &l.Claim},
		{"rate_limit_consent", &l.Consent},
		{"rate_limit_link", &l.Link},
		{"rate_limit_create", &l.Create},
		{"rate_limit_send", &l.Send},
		{"rate_limit_api", &l.API},
		{"rate_limit_remind", &l.Remind},
		{"rate_limit_mail_test", &l.MailTest},
	} {
		raw := strings.TrimSpace(get(k.key, ""))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			cproblems(c, k.key+": not a number: "+raw)
			continue
		}
		*k.set = n
	}
	for _, k := range []struct {
		key string
		set *time.Duration
	}{
		{"rate_limit_window", &l.Window},
		{"rate_limit_remind_window", &l.RemindWindow},
	} {
		raw := strings.TrimSpace(get(k.key, ""))
		if raw == "" {
			continue
		}
		d, err := duration(raw, 0)
		if err != nil {
			cproblems(c, k.key+": "+err.Error())
			continue
		}
		if d < 0 {
			cproblems(c, k.key+": a window cannot be negative: "+raw)
			continue
		}
		*k.set = d
	}
	return l
}

func cproblems(c *Config, msg string) { c.problems = append(c.problems, msg) }

func cwarnings(c *Config, msg string) { c.warnings = append(c.warnings, msg) }
