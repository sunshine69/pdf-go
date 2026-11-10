package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
	"github.com/sunshine69/pdf-go/internal/signflow"
	"github.com/sunshine69/pdf-go/internal/signpdf"
	"github.com/sunshine69/pdf-go/internal/signstore"
)

// signCmd is `signsrv sign NAME EMAIL IN [OUT]`: certify `IN` and add one
// approval signature for NAME/EMAIL. It is the CLI path for the same two calls
// the API uses, so a document can be signed from the command line with a
// named party, and the acceptance script can prove the chain works outside the
// test harness.
//
// The keystore passphrase comes from the config; the party key is generated
// for the call and dropped when the signature is written, exactly as in the
// service. Nothing is written to the database.
func signCmd(configPath, tsaOverride string, rest []string) int {
	if len(rest) < 3 {
		fmt.Fprintln(os.Stderr, "signsrv: sign takes NAME EMAIL IN [OUT]")
		return 2
	}
	name, email, inPath := rest[0], rest[1], rest[2]
	outPath := ""
	if len(rest) > 3 {
		outPath = rest[3]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv: configuration:", err)
		if cfg != nil {
			for _, p := range cfg.Problems() {
				fmt.Fprintln(os.Stderr, "  problem:", p)
			}
		}
		return 1
	}
	if tsaOverride != "" {
		cfg.TSAURL = tsaOverride
		if tsaOverride == "-" {
			cfg.TSAURL = ""
		}
	}

	in, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: read %s: %v\n", inPath, err)
		return 1
	}

	fontData, fontName := selftestFont(cfg)
	s, err := signpdf.NewService(signpdf.Config{
		KeystoreDir: cfg.Keystore,
		CASubject:   cfg.CASubject,
		Passphrase:  cfg.KeystorePassphrase(),
		TSAURL:      cfg.TSAURL,
		FontData:    fontData,
		FontName:    fontName,
		Clock:       time.Now,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: signing service: %v\n", err)
		return 1
	}
	// The report this command prints is the verification of a document it just
	// signed, so it has to check the signature against the CA that signed it.
	// Without the anchor, this command would print "valid": true for a document
	// the CA never issued.
	s.PinToCA()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := s.Certify(ctx, in, signpdf.CertifyOptions{
		Name:     "signsrv",
		Reason:   "certified",
		Location: "signsrv",
		Contact:  cfg.MailFrom,
		TSAURL:   cfg.TSAURL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: certify: %v\n", err)
		return 1
	}

	out, err = s.SignParty(ctx, out.Data, signpdf.PartyOptions{
		Name:      name,
		Email:     email,
		Reason:    "signed",
		Signature: name,
		TSAURL:    cfg.TSAURL,
		// X is left unset: a widget with neither coordinate keeps the default
		// bottom-right placement, which is where this single-signature command
		// has always put the signature.
		Widget: signpdf.Widget{W: signpdf.AppearanceWidth, H: signpdf.AppearanceHeight},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: sign: %v\n", err)
		return 1
	}

	rep, err := s.Verify(ctx, out.Data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: verify: %v\n", err)
		return 1
	}

	r := selftestReport{
		Valid:     rep.Valid,
		In:        inPath,
		SHA256:    hexSha(out.Data),
		Pages:     rep.Pages,
		CA:        hexSha(s.CA().Cert.Raw),
		TSAURL:    s.TSAURL(),
		Signers:   rep.Signers,
		Errors:    rep.Errors,
		ByteSize:  len(out.Data),
		CertStart: len(in),
	}
	applyTrust(&r, s, "keystore in "+cfg.Keystore, false)
	printReport(r)

	if outPath != "" {
		if err := os.WriteFile(outPath, out.Data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "signsrv: write %s: %v\n", outPath, err)
			return 1
		}
	}
	if !rep.Valid {
		return 1
	}
	return 0
}

// inlineName is the download name of the copy a signer sees. It is the
// request's title and nothing else: no "-document" suffix, because this is the
// document, not one of its exports.
func inlineName(title string) string {
	slug := slugify(title)
	if slug == "" {
		return "envelope"
	}
	return slug
}

// ---------------------------------------------------------------------------
// The public signing endpoints (step 07).
//
// A party arrives with a link token in the path. The token is the credential,
// so every rule is enforced server-side: the page the party runs is untrusted,
// and the link can be forwarded. Consent is data only — no PDF is opened,
// written, or signed on this path.

// handleSignerClaim is POST /api/v1/sign/{token}/claim. The stated address is
// compared with the invitation's; a match mints the session cookie, a refusal
// is a 403 and an event carrying the caller's IP.
func (s *server) handleSignerClaim(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &body, 4096) {
		return
	}
	res, err := signflow.Claim(r.Context(), s.store, signauth.PathToken(r),
		body.Email, s.clockNow(), signauth.ClientIP(r, s.cfg.TrustProxy), r.UserAgent())
	if err != nil {
		s.signProblem(w, r, err, "claim")
		return
	}
	// HttpOnly, so the signing page cannot read back what it proves;
	// SameSite=Strict, so a link opened from an email does not carry it
	// cross-site; 12 hours, so a browser left open on a shared machine stops
	// working before the next working day.
	http.SetCookie(w, s.signerCookie(res.Session, signflow.SessionTTL))
	s.logJSON(slog.LevelInfo, "claim ok", "party", res.PartyID,
		"request", requestID(r.Context()))
	// The answer is what the signing page shows after a claim: who it is
	// talking to, which request, and for how long. The address is not echoed.
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "name": res.Name, "title": res.Title,
		"expires_at": res.ExpiresAt,
	})
}

// handleSignerEnvelope is GET /api/v1/sign/{token}/envelope.
//
// It is deliberately allowed before a claim, because the party needs the title
// and the deadline to confirm they are where they think they are. Pre-claim
// that is all the answer holds: no party list, no slot, nothing that describes
// who else is in the request.
func (s *server) handleSignerEnvelope(w http.ResponseWriter, r *http.Request) {
	sg, err := signflow.ResolveSigner(r.Context(), s.store, signauth.PathToken(r), s.clockNow())
	if err != nil {
		s.signProblem(w, r, err, "envelope view")
		return
	}
	view, err := signflow.SignerViewFor(r.Context(), s.store, sg,
		s.sessionMatches(r, sg.Party), s.clockNow())
	if err != nil {
		s.signProblem(w, r, err, "envelope view")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleSignerDocument is GET /api/v1/sign/{token}/document. It streams the
// certified revision: the frozen bytes the party reviews and consents to. The
// disposition is inline because the party is reading the document they were
// invited to sign. A claim is required: a forwarded link gets the claim screen,
// not the document.
func (s *server) handleSignerDocument(w http.ResponseWriter, r *http.Request) {
	sg, err := s.requireSession(w, r)
	if err != nil {
		return
	}
	title, sha, data, err := signflow.SignerDocument(r.Context(), s.store, sg)
	if err != nil {
		s.signProblem(w, r, err, "document")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("Content-Disposition", `inline; filename="`+slugify(title)+`.pdf"`)
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Sha256", sha)
	if _, err := w.Write(data); err != nil {
		s.logJSON(slog.LevelWarn, "signer document write", "sha", sha,
			"error", err, "request", requestID(r.Context()))
	}
}

// handleSignerConsent is POST /api/v1/sign/{token}/consent. Every rule runs in
// the flow layer, in the order of the API table; the handler supplies the
// transport facts (IP, user agent) and maps the answer.
func (s *server) handleSignerConsent(w http.ResponseWriter, r *http.Request) {
	// 1 MB bounds the base64 of a 512 KB image with room to breathe; a larger
	// body is refused at read time, not after it is in memory.
	var in signflow.ConsentInput
	if !decodeJSON(w, r, &in, 1<<20) {
		return
	}
	in.IP = signauth.ClientIP(r, s.cfg.TrustProxy)
	in.UserAgent = r.UserAgent()
	res, err := s.flowDeps().Consent(r.Context(), signauth.PathToken(r), in, s.clockNow())
	if err != nil {
		s.signProblem(w, r, err, "consent")
		return
	}
	// The consent consumed the session: the store dropped the session hash, so
	// the cookie is dead. Expiring it here stops the page replaying it.
	s.expireSignerCookie(w)
	s.logJSON(slog.LevelInfo, "consent recorded", "consent", res.ConsentID,
		"all_consented", res.AllConsented, "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, res)
}

// handleSignerDecline is POST /api/v1/sign/{token}/decline.
func (s *server) handleSignerDecline(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &body, 1<<20) {
		return
	}
	res, err := s.flowDeps().Decline(r.Context(), signauth.PathToken(r), body.Reason,
		signflow.DeclineMeta{
			IP:        signauth.ClientIP(r, s.cfg.TrustProxy),
			UserAgent: r.UserAgent(),
		}, s.clockNow())
	if err != nil {
		s.signProblem(w, r, err, "decline")
		return
	}
	s.expireSignerCookie(w)
	s.logJSON(slog.LevelInfo, "declined", "request", requestID(r.Context()))
	writeJSON(w, http.StatusOK, res)
}

// requireSession resolves the link and proves the caller holds a session for
// this same party: RequireSigner's rule, expressed as a call so the handler
// also gets the resolved envelope.
func (s *server) requireSession(w http.ResponseWriter, r *http.Request) (*signflow.Signer, error) {
	sg, err := signflow.ResolveSigner(r.Context(), s.store, signauth.PathToken(r), s.clockNow())
	if err != nil {
		s.signProblem(w, r, err, "session")
		return nil, err
	}
	if !s.sessionMatches(r, sg.Party) {
		writeProblem(w, http.StatusUnauthorized, "claim_required",
			"claim this link with your email address first", "")
		return nil, errNoSession
	}
	return sg, nil
}

// sessionMatches reports whether the request carries a session cookie that the
// store resolves to this party, in this envelope.
func (s *server) sessionMatches(r *http.Request, p *signstore.Party) bool {
	c, err := r.Cookie(signauth.CookieName)
	if err != nil || c.Value == "" || s.store == nil {
		return false
	}
	session, err := s.store.GetPartyBySessionHash(r.Context(), signauth.HashToken(c.Value))
	if err != nil || session == nil {
		return false
	}
	return session.ID == p.ID && session.EnvelopeID == p.EnvelopeID
}

// expireSignerCookie kills the session cookie. The store has already dropped
// the hash; this stops the browser carrying a value that resolves to nothing.
func (s *server) expireSignerCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     signauth.CookieName,
		Value:    "",
		Path:     signauth.CookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.cfg.Dev,
		SameSite: http.SameSiteStrictMode,
	})
}

// signerCookie is the session cookie, built once. A session cookie has no
// Max-Age and no Expires: it lives until the browser is closed. The store holds
// the deadline, and the claim answer carries it; a cookie that advertised its
// own lifetime would tell an attacker how long a stolen link is good for.
func (s *server) signerCookie(value string, ttl time.Duration) *http.Cookie {
	c := signauth.NewSessionCookie(value, ttl, true)
	if s.cfg.Dev {
		// Dev serves plain HTTP, where a Secure cookie is never sent. The
		// flags are otherwise exactly the ones step 03 lists.
		c.Secure = false
	}
	return c
}

// signProblem maps a signing-path error onto the API's problem shape, in one
// place, so the codes stay the codes of step 05.
func (s *server) signProblem(w http.ResponseWriter, r *http.Request, err error, what string) {
	switch {
	case errors.Is(err, signflow.ErrTokenUnknown):
		writeProblem(w, http.StatusNotFound, "not_found", "this link is not valid", "")
	case errors.Is(err, signflow.ErrTokenExpired):
		writeProblem(w, http.StatusGone, "link_expired",
			"this link has expired, ask for a new one", "")
	case errors.Is(err, signflow.ErrLinkClosed):
		writeProblem(w, http.StatusGone, "request_closed", "this signing request is closed", "")
	case errors.Is(err, signflow.ErrClaimEmail):
		// 403, and the address is never echoed: the answer must not confirm
		// which address the invitation names.
		writeProblem(w, http.StatusForbidden, "claim_failed",
			"this link is issued to a different address", "")
	case errors.Is(err, signflow.ErrPartyStatus):
		writeProblem(w, http.StatusConflict, "state_conflict",
			"this party cannot act in its current state", "")
	case errors.Is(err, signflow.ErrDocumentSHA):
		writeProblem(w, http.StatusConflict, "document_changed",
			"the document changed, reload", "reload the document and consent again")
	case errors.Is(err, signflow.ErrStateConflict):
		writeProblem(w, http.StatusConflict, "state_conflict",
			"the request cannot accept this action in its current state", "")
	case errors.Is(err, signflow.ErrConsentRequired):
		writeProblem(w, http.StatusBadRequest, "consent_required", "consent true is required", "")
	case errors.Is(err, signflow.ErrSignatureText):
		writeProblem(w, http.StatusBadRequest, "invalid_signature_text",
			errText(err), "a name, up to 120 characters, no control characters")
	case errors.Is(err, signflow.ErrConsentImage):
		writeProblem(w, http.StatusBadRequest, "invalid_image",
			errText(err), "PNG or JPEG, up to 512 KB and 2000x2000")
	case errors.Is(err, signflow.ErrDeclineReason):
		writeProblem(w, http.StatusBadRequest, "invalid_reason", errText(err), "")
	case errors.Is(err, signstore.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not_found", "this link is not valid", "")
	default:
		s.logJSON(slog.LevelError, "signing endpoint", "what", what,
			"error", err, "request", requestID(r.Context()))
		writeProblem(w, http.StatusInternalServerError, "internal", "the request failed", "")
	}
}

// errText is the rule text of an error, without the package prefix, so the
// party sees the rule it broke and not the internal chain.
func errText(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && i+2 < len(msg) {
		return strings.TrimSpace(msg[i+2:])
	}
	return msg
}

// decodeJSON reads a JSON body with a size ceiling. A body over the ceiling is
// a 413, and a body that is not JSON is a 400 naming the field that broke.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "body_too_large",
				"the body is larger than this endpoint accepts", "")
			return false
		}
		writeProblem(w, http.StatusBadRequest, "body",
			"the body is not valid JSON"+unknownFieldHint(err),
			"a JSON object with the fields of this endpoint")
		return false
	}
	return true
}

// unknownFieldHint turns a DisallowUnknownFields failure into the field name.
// Naming the field is the difference between a client guessing and a client
// fixing.
func unknownFieldHint(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" {
		return ": unknown field " + te.Field
	}
	return ""
}

var errNoSession = errors.New("signsrv: no signing session")
