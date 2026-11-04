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
func newServer(cfg *Config, log *slog.Logger, store *signstore.Store) *server {
	keys, err := signauth.LoadKeyring(cfg.JWTFile())
	if err != nil {
		log.Error("jwt key", "error", err, "file", cfg.JWTFile())
		return nil
	}
	s := &server{cfg: cfg, log: log, mux: http.NewServeMux(), tokens: randSource{},
		keys: keys, store: store, signer: signService(cfg, log)}
	if store != nil {
		s.sessions = &signauth.Sessions{Keys: keys, Store: store}
		s.auth = &signauth.Auth{
			Verifier:   keys,
			Revoked:    store,
			Store:      store,
			Epochs:     store,
			Limits:     signauth.NewLimiter(),
			TrustProxy: cfg.TrustProxy,
		}
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
	if s.cfg.Dev && strings.HasPrefix(s.cfg.AdminPassword(), "dev-") {
		// Dev mode only, and only for an ephemeral password that was
		// generated because the config had none. Never printed in production.
		s.log.Info("dev admin password", "password", s.cfg.AdminPassword(),
			"note", "dev mode only; set SIGNSRV_ADMIN_PASSWORD to fix it")
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
		next.ServeHTTP(&h, r)
		if !h.written() {
			w.WriteHeader(http.StatusOK)
		}
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

// setCSRFCookie sets a SameSite=Strict, HttpOnly cookie. Step 03 owns the
// session cookie; the helper lives here so every cookie in the service is
// set the same way.
func (s *server) setCSRFCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   !s.cfg.Dev,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, c)
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestKey{}, id)
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
