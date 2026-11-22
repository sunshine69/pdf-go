package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/sunshine69/pdf-go/internal/signauth"
)

// devAdminEmail is the account dev mode bootstraps. It exists so that a fresh
// clone with an empty database has a way in: dev mode already derives an
// admin password (from ADMIN_PASSWORD, or an ephemeral one it logs),
// and a password with no account behind it is a credential that cannot be
// used. Production never reaches this path — it is gated on cfg.Dev — and
// production's account comes from `signsrv admin add` or the package's
// first-boot helper, both of which ask for the address.
const devAdminEmail = "dev@localhost"

// ensureDevAdmin creates the dev admin account when the database has none.
//
// It runs after the migrations, before the first request is served, and only
// in dev mode. It is deliberately loud about what it did, because the point is
// that the operator can read the log line once and have a working login rather
// than discover an empty admins table by being locked out.
//
// A failure is logged and not fatal: a database that cannot be written is a
// bigger problem than a missing convenience account, and the health endpoint
// and the logs will say so.
func (s *server) ensureDevAdmin(ctx context.Context) {
	// Guarded here as well as at the call site. A function that can create an
	// account with a password taken from config should not rely on its caller
	// to keep it out of production.
	if !s.cfg.Dev || s.store == nil {
		return
	}
	admins, err := s.store.ListAdmins(ctx)
	if err != nil {
		s.log.Log(ctx, slog.LevelWarn, "dev admin check", "error", err)
		return
	}
	if len(admins) > 0 {
		// Somebody already made an account, by any name. Do not add a second
		// one and leave the operator guessing which address works.
		return
	}
	pw := s.cfg.AdminPassword()
	if pw == "" {
		// validate() rejects this before serve reaches it, so reaching here
		// means a caller skipped validation. Creating an account with an empty
		// password would be worse than not creating one.
		s.log.Log(ctx, slog.LevelWarn, "dev admin skipped: no admin password to seed")
		return
	}
	hash, err := signauth.HashPassword(pw)
	if err != nil {
		s.log.Log(ctx, slog.LevelWarn, "dev admin password hash", "error", err)
		return
	}
	id, err := s.store.AddAdmin(ctx, devAdminEmail, hash, "admin")
	if err != nil {
		s.log.Log(ctx, slog.LevelWarn, "dev admin create", "error", err)
		return
	}
	s.log.Info("dev admin account", "email", devAdminEmail, "id", id,
		"password", s.cfg.AdminPassword(),
		"note", devAdminNote(s))
}

// devAdminNote keeps the old advice for the case it was written for: an
// ephemeral password, regenerated at every start, is not something to depend
// on. When the config supplies the password there is nothing to fix.
func devAdminNote(s *server) string {
	if strings.HasPrefix(s.cfg.AdminPassword(), "dev-") {
		return "dev mode only; set ADMIN_PASSWORD to fix it"
	}
	return "dev mode only; created because the database had no admins"
}
