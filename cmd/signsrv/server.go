package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
	"github.com/sunshine69/pdf-go/web"
)

// server is the HTTP face of the service: API, static apps, health.
type server struct {
	cfg    *Config
	log    *slog.Logger
	mux    *http.ServeMux
	tokens tokenSource

	// clock is the wall clock of the service. It is a field so a test can
	// move time forward and prove an expired link is refused; production
	// sets it to time.Now. Every deadline check reads it, so there is one
	// notion of now in the process.
	clock func() time.Time
	// The three things the auth layer needs: the signing key, the store, and
	// the bundles built from them. The handlers never reach into the database
	// except through the store.
	keys     *signauth.Keyring
	store    *signstore.Store
	sessions *signauth.Sessions
	auth     *signauth.Auth

	// The signing service. Built once: the CA key is read only when signing,
	// and every signature opens its own document, so sharing it across
	// requests is safe. nil means this node cannot sign: it serves reads, and
	// create answers 503.
	signer *signpdf.Service

	// mail carries the renderer, the sender, the from address, and the link
	// base. The renderer is parsed once at startup, so a template that does
	// not parse is a startup error. nil sender means the queue is not drained
	// by the send: the worker (step 07) drains it.
	mail *signflow.Mailer
}

// tokenSource is implemented by signauth (step 03). The server asks for a
// request id and for bearer verification through this interface so the
// middleware chain is complete before the signing app exists.
type tokenSource interface {
	NewRequestID() string
}

type randSource struct{}

func (randSource) NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unknown"
	}
	return hex.EncodeToString(b[:])
}

// newServer loads the signing key and wires the auth layer. The key file is
// created with 0600 on first start. A store is optional: the health and static
// routes work without a database, which is what the shell tests exercise.
//
// The signing service is loaded here, from the keystore, unless the caller
// already has one — which is what `serve` does, so that the CA described by the
// first-start log line is the CA the process signs with and the keystore is
// opened once, not twice (newServerWithSigner).
func newServer(cfg *Config, log *slog.Logger, store *signstore.Store) *server {
	return newServerWithSigner(cfg, log, store, nil)
}

// newServerWithSigner is newServer with a signing service the caller loaded
// first. A nil signer means load it here, as before.
func newServerWithSigner(cfg *Config, log *slog.Logger, store *signstore.Store, signer *signpdf.Service) *server {
	keys, err := signauth.LoadKeyring(cfg.JWTFile())
	if err != nil {
		log.Error("jwt key", "error", err, "file", cfg.JWTFile())
		return nil
	}
	if signer == nil {
		signer = signService(cfg, log)
	}
	s := &server{cfg: cfg, log: log, mux: http.NewServeMux(), tokens: randSource{}, clock: time.Now,
		keys: keys, store: store, signer: signer, mail: newMailer(cfg, log)}
	if store != nil {
		s.sessions = &signauth.Sessions{Keys: keys, Store: store}
		s.auth = &signauth.Auth{
			Verifier:   keys,
			Revoked:    store,
			Store:      store,
			Epochs:     store,
			Users:      store,
			Limits:     signauth.NewLimiter(),
			TrustProxy: cfg.TrustProxy,
		}
		// The signing guard reads the same clock as every other deadline in
		// the process. A test that moves the server clock moves the guard with
		// it, so "the request is over" is decided in one place.
		s.auth.SetClock(s.clockNow)
	}
	s.routes()
	return s
}

// run starts the listener and blocks until ctx is cancelled, then drains.
func (s *server) run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.withDefaults(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.log.Info("signsrv listening", "addr", s.cfg.Listen, "dev", s.cfg.Dev,
		"go", runtime.Version(), "public_url", s.cfg.PublicURL)
	if s.cfg.Dev {
		s.ensureDevAdmin(ctx)
	}

	shutdown := make(chan struct{})
	go func() {
		<-ctx.Done()
		s.log.Info("signal received, draining")
		dctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(dctx)
		close(shutdown)
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	<-shutdown
	s.log.Info("signsrv stopped")
	return nil
}

// withDefaults wraps every request with the request id, the bound deadline
// and the response headers of the service.
func (s *server) withDefaults(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.tokens.NewRequestID()
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		r = r.WithContext(withRequestID(ctx, id))

		h := header{w: w}
		h.set("X-Request-Id", id)
		h.set("X-Content-Type-Options", "nosniff")
		h.set("Referrer-Policy", "no-referrer")
		h.set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		switch {
		case strings.HasPrefix(r.URL.Path, "/s/"),
			strings.HasPrefix(r.URL.Path, "/assets/spa/"):
			h.set("Content-Security-Policy", web.CSPSigner)
		case strings.HasPrefix(r.URL.Path, "/admin/"),
			strings.HasPrefix(r.URL.Path, "/assets/admin/"):
			h.set("Content-Security-Policy", web.CSPAdmin)
			h.set("X-Frame-Options", "DENY")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.set("Cache-Control", "no-store")
		}
		start := time.Now()
		next.ServeHTTP(&h, r)
		if !h.written() {
			w.WriteHeader(http.StatusOK)
		}
		s.logAccess(r, &h, start)
	})
}

// header accumulates headers and forwards Write calls to the response.
type header struct {
	w       http.ResponseWriter
	headers map[string]string
	status  int
}

func (h *header) set(k, v string) {
	if h.headers == nil {
		h.headers = map[string]string{}
	}
	h.headers[k] = v
}

func (h *header) written() bool { return h.status != 0 }

func (h *header) Header() http.Header {
	base := h.w.Header()
	for k, v := range h.headers {
		base.Set(k, v)
	}
	return base
}

func (h *header) Write(b []byte) (int, error) {
	h.status = http.StatusOK
	return h.w.Write(b)
}

func (h *header) WriteHeader(code int) {
	h.status = code
	for k, v := range h.headers {
		h.w.Header().Set(k, v)
	}
	h.w.WriteHeader(code)
}

// requestKey is the context key of the request id.
type requestKey struct{}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestKey{}, id)
}

// logAccess writes one request line. The path is redacted, the cookie header
// is reduced to names, and the authorization header is reduced to its scheme.
// The status and the duration are the useful part of a request log; the
// credentials in a request are not.
func (s *server) logAccess(r *http.Request, h *header, start time.Time) {
	status := h.status
	if status == 0 {
		status = http.StatusOK
	}
	s.logJSON(slog.LevelInfo, "request",
		"method", r.Method,
		"path", redactPath(r.URL.Path),
		"status", status,
		"dur_ms", time.Since(start).Milliseconds(),
		"ip", signauth.ClientIP(r, s.cfg.TrustProxy),
		"cookies", redactCookie(r.Header.Get("Cookie")),
		"auth", redactAuthorization(r.Header.Get("Authorization")),
		"request", requestID(r.Context()))
}

func requestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestKey{}).(string); ok {
		return v
	}
	return ""
}

// logJSON writes one structured log line.
func (s *server) logJSON(level slog.Level, msg string, kv ...any) {
	s.log.Log(context.Background(), level, msg, kv...)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// newMailer builds the mailer from the config. The renderer is parsed once:
// a template that does not parse is a startup error, not a failure at send
// time. The sender is the file sender in dev mode, so DEV=1 writes
// .eml files into var/outbox; in production it is SMTP. A config with no SMTP
// host and dev mode off has no sender, and the send endpoint enqueues without
// delivering.
func newMailer(cfg *Config, log *slog.Logger) *signflow.Mailer {
	r, err := signmail.NewRenderer(web.Templates())
	if err != nil {
		log.Error("mail templates", "error", err)
		return nil
	}
	var sender signmail.Sender
	if cfg.Dev {
		sender = &signmail.FileSender{Dir: cfg.Outbox}
	} else if cfg.SMTPHost != "" {
		sender = &signmail.SMTPSender{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			StartTLS: cfg.SMTPStartTLS,
			User:     cfg.SMTPUser,
			Password: cfg.SMTPPassword(),
		}
	}
	if sender == nil {
		// No transport. The queue is filled by create and send; nothing is
		// delivered. Logged once, at startup, so an operator sees it.
		log.Warn("no mail sender configured", "dev", cfg.Dev, "smtp_host", cfg.SMTPHost)
	}
	return &signflow.Mailer{
		Renderer: r,
		Sender:   sender,
		From:     cfg.MailFrom,
		LinkBase: cfg.PublicURL,
	}
}

// clockNow is the service's now. Every deadline check reads it, so there is
// one notion of time in the process, and a test that moves it moves every
// deadline at once.
func (s *server) clockNow() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock()
}

// Redaction of the credentials in the request line.
//
// A request that carries a link token, a bearer token, or a session cookie
// logs the request: the path, the cookie names, the method, the status. It
// never logs the value, because a log line is read by operators, shipped to a
// central collector, and kept for months. A log containing a link token is a
// log containing a signature: whoever reads it can sign as that party until the
// link expires.
//
// So the rule is: names in, values out. A path segment that looks like a
// credential is replaced. A cookie header keeps the cookie names. An
// authorization header keeps the scheme. Nothing else is logged, and the raw
// header is never logged in any handler.

// redactPath replaces the credential segment of a path. The two shapes that
// carry a credential in the path are the signing page (/s/<token>) and the
// signer API (/api/v1/sign/<token>/<action>). Position is enough: the service
// knows where its tokens sit, so nothing is guessed.
//
// An envelope id is not redacted. It is an identifier, not a capability:
// knowing it gets nothing, and it is the key every log line is searched by.
func redactPath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	if len(segs) >= 3 && segs[1] == "s" {
		segs[2] = "[token]"
	}
	if len(segs) >= 5 && segs[1] == "api" && segs[3] == "sign" {
		segs[4] = "[token]"
	}
	return strings.Join(segs, "/")
}

// redactCookie keeps the cookie names and drops the values.
func redactCookie(h string) string {
	if h == "" {
		return ""
	}
	var names []string
	for _, part := range strings.Split(h, ";") {
		name, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

// redactAuthorization keeps the scheme and drops the credential.
func redactAuthorization(h string) string {
	if h == "" {
		return ""
	}
	i := strings.Index(h, " ")
	if i < 0 {
		return "[credential]"
	}
	return h[:i] + " [credential]"
}
