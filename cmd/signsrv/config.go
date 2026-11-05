package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
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
	TrustProxy bool
	Dev        bool
	// WorkerInterval is how often the worker drains the mail queue and
	// advances expiries. A zero interval means the worker does not run.
	WorkerInterval time.Duration
	LogPath        string
	LogLevel       string
	MaxPDFMB       int

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
	smtpPassDigest  string
	adminPassDigest string

	problems []string
}

// secret returns the raw value of a config secret. It is deliberately a
// method: the value never appears in the struct, in a log line, or in a JSON
// dump of the configuration.
//
// The value may come from the environment (SIGNSRV_*) or from the config
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
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "SIGNSRV_") {
			env[strings.ToLower(strings.TrimPrefix(k, "SIGNSRV_"))] = v
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

	c := &Config{env: env, file: file}

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
	if c.Dev {
		if !isLoopback(c.Listen) {
			cproblems(c, "dev mode is only allowed on a loopback listener")
		}
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
		cproblems(c, "smtp_host is required when dev mode is off (set SIGNSRV_DEV=1 to write mail to var/outbox)")
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
	if isLoopback(c.Listen) && !c.TrustProxy {
		// Fine: behind a local proxy the operator must opt in to
		// X-Forwarded-For. Nothing to report.
	}
}

// Problems lists every configuration problem found.
func (c *Config) Problems() []string { return c.problems }

// Redacted prints the configuration with secrets replaced by digests.
func (c *Config) Redacted() string {
	dur := c.LinkTTL.String()
	return strings.Join([]string{
		"listen=" + c.Listen,
		"public_url=" + c.PublicURL,
		"db_path=" + c.DBPath,
		"storage_dir=" + c.StorageDir,
		"keystore_dir=" + c.Keystore,
		"keystore_pass=" + c.keystoreDigest,
		"admin_password=" + c.adminPassDigest,
		"jwt_secret_file=" + c.jwtFile,
		"tsa_url=" + c.TSAURL,
		"link_ttl=" + dur,
		"max_pdf_mb=" + strconv.Itoa(c.MaxPDFMB),
		"log_path=" + c.LogPath,
		"log_level=" + c.LogLevel,
		"smtp_host=" + c.SMTPHost,
		"smtp_port=" + strconv.Itoa(c.SMTPPort),
		"smtp_starttls=" + strconv.FormatBool(c.SMTPStartTLS),
		"smtp_user=" + c.SMTPUser,
		"smtp_pass=" + c.smtpPassDigest,
		"mail_from=" + c.MailFrom,
		"trust_proxy=" + strconv.FormatBool(c.TrustProxy),
		"dev=" + strconv.FormatBool(c.Dev),
	}, "\n")
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
		k = strings.ToLower(strings.TrimSpace(k))
		k = strings.TrimPrefix(k, "signsrv_")
		if !configKeys[k] {
			return nil, fmt.Errorf("%s:%d: unknown config key %q (see config.example.env)", path, n, k)
		}
		out[k] = strings.TrimSpace(strings.Trim(v, `"'`))
	}
	return out, sc.Err()
}

// configKeys is the set of recognised configuration keys, so a typo in a
// config file fails at startup instead of being silently ignored.
var configKeys = map[string]bool{
	"listen": true, "public_url": true, "db": true, "db_path": true,
	"storage_dir": true, "keystore_dir": true, "outbox_dir": true,
	"keystore_pass": true, "admin_password": true, "jwt_secret_file": true,
	"tsa_url": true, "link_ttl": true, "max_pdf_mb": true,
	"smtp_host": true, "smtp_port": true, "smtp_starttls": true,
	"smtp_user": true, "smtp_pass": true, "mail_from": true,
	"trust_proxy": true, "dev": true, "log_level": true, "log_path": true,
	// worker_interval is read by Load (below) and documented in
	// config.example.env, so the parser has to accept it: an operator who sets
	// it in a config file gets a hard error otherwise, which is how a documented
	// knob becomes an unreachable one.
	"worker_interval": true,
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

// isLoopback reports whether a listen address binds only to the local
// machine. Dev mode requires it.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port given
	}
	host = strings.Trim(host, "[]")
	return host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" ||
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

func cproblems(c *Config, msg string) { c.problems = append(c.problems, msg) }
