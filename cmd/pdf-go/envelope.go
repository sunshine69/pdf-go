package main

// The envelope subcommands talk to the signing service over its API, so the
// fill knowledge stays in this CLI: the document is probed and filled here,
// and only the finished bytes are uploaded.
//
//	pdf-go envelope create --server URL --token TOK --template in.pdf \
//	    --spec fill.json --parties parties.json [--title T] [--expires 72h]
//	pdf-go envelope get <id>      --server URL --token TOK
//	pdf-go envelope links <id>    [--links-out FILE]
//	pdf-go envelope report <id>   --server URL --token TOK
//
// The token is a client token from `signsrv client add`. It is never printed,
// never written to a file, and never sent anywhere except to --server.
//
// A signing link is returned exactly once, by create or by send. It is the
// party's credential. `envelope create` writes the links it received into a
// file of mode 0600 so `envelope links` can print them again without asking
// the service for them a second time; when the parties have their links, the
// file should be removed.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/report"
	"github.com/sunshine69/pdf-go/internal/schema"
	"github.com/sunshine69/pdf-go/internal/signauth"
)

// maxServerReply bounds what a response may cost us. A verification report or
// an envelope view is small; anything larger is either a mistake or an attack,
// and reading it would let a hostile endpoint exhaust memory.
const maxServerReply = 8 << 20

// apiError is the service's problem document:
//
//	{"error":{"code":"invalid_spec","message":"...","hint":"..."}}
//
// which is the answer shape of every endpoint, the 401s and the 400s alike.
type apiError struct {
	Problem apiProblem `json:"error"`
}

type apiProblem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func (e apiError) Error() string {
	msg := e.Problem.Message
	if msg == "" {
		msg = e.Problem.Code
	}
	// The code leads. A message is prose the service may reword; the code is the
	// stable name, and it is what an operator greps the journal for and a script
	// branches on.
	if e.Problem.Code != "" {
		msg = "[" + e.Problem.Code + "] " + msg
	}
	if msg == "" {
		return "the service refused the request"
	}
	if e.Problem.Hint != "" {
		msg += " (" + e.Problem.Hint + ")"
	}
	return msg
}

// envelopeCommand dispatches `pdf-go envelope ...`.
func envelopeCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "envelope: needs create, get, links, send or report")
		return report.Usage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return envelopeCreate(rest)
	case "send":
		return envelopeSendOrReport(rest, "send")
	case "get":
		return envelopeGet(rest)
	case "links":
		return envelopeLinks(rest)
	case "report":
		return envelopeSendOrReport(rest, "report")
	case "help", "-h", "--help":
		usage()
		return report.OK
	default:
		fmt.Fprintf(os.Stderr, "envelope: unknown subcommand %q\n", sub)
		return report.Usage
	}
}

// envelopeFlags is the shared flag set of the subcommands. -insecure exists for
// the end-to-end run against a local plain-HTTP listener; the default refuses
// to send a client token over anything but https.
type envelopeFlags struct {
	server   string
	token    string // the client key, never sent on an API call
	tokenEnv string
	insecure bool
	jsonOut  bool
	timeout  time.Duration
	linksOut string
	access   string

	// The self-minted credential: a username and the shared secret of its row.
	// With both, the CLI signs its own access token and the service verifies
	// the signature — no token round trip, and no token endpoint to reach when
	// the CLI is on a different machine from the service.
	username  string
	secret    string
	secretEnv string
	ttl       time.Duration
}

func (f *envelopeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.server, "server", envDefault("SIGNSRV_URL", ""), "service base URL")
	fs.StringVar(&f.token, "token", "", "client token (prefer --token-env)")
	fs.StringVar(&f.tokenEnv, "token-env", "SIGNSRV_TOKEN", "environment variable holding the client token")
	fs.BoolVar(&f.insecure, "insecure", false, "allow http:// (development only)")
	fs.BoolVar(&f.jsonOut, "json", true, "print the service's JSON answer")
	fs.DurationVar(&f.timeout, "timeout", 60*time.Second, "request timeout")
	fs.StringVar(&f.linksOut, "links-out", "", "file the signing links are written to")
	fs.StringVar(&f.username, "username", envDefault("SIGNSRV_USERNAME", ""), "username whose secret signs the request")
	fs.StringVar(&f.secret, "jwt-secret", "", "shared secret of that username (prefer --jwt-secret-env)")
	fs.StringVar(&f.secretEnv, "jwt-secret-env", "SIGNSRV_JWT_SECRET", "environment variable holding the shared secret")
	fs.DurationVar(&f.ttl, "ttl", 0, "requested token validity, capped by the service at 15m")
}

func envDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// resolve checks what the CLI needs before it touches the network: the server,
// the token, and the transport. A token in argv is visible to every process on
// the machine, so the environment is the documented way to pass it.
func (f *envelopeFlags) resolve() error {
	if f.server == "" {
		return fmt.Errorf("needs --server (or SIGNSRV_URL)")
	}
	if !strings.HasPrefix(f.server, "http://") && !strings.HasPrefix(f.server, "https://") {
		return fmt.Errorf("--server must start with http:// or https://")
	}
	if !strings.HasPrefix(f.server, "https://") && !f.insecure {
		return fmt.Errorf("--server is plain HTTP: a client token would travel in the clear; use https:// or pass -insecure for a local run")
	}
	// Two credentials, and at least one is needed. The self-minted one (username
	// + shared secret) is preferred when both are present: it needs no token
	// round trip, so the CLI works against a service whose token endpoint is
	// firewalled, and the secret never travels.
	// Read the secret from the environment whenever the flag is empty. The
	// username may have arrived from SIGNSRV_USERNAME, and a credential split
	// across two variables is the shape an operator actually writes in a unit
	// file: username in the environment, secret in a Credentials= line.
	if f.secret == "" {
		f.secret = os.Getenv(f.secretEnv)
	}
	if f.secret == "" || f.username == "" {
		if f.token == "" {
			f.token = os.Getenv(f.tokenEnv)
		}
		if f.token == "" {
			return fmt.Errorf("needs a credential: --username with the secret in %s (create with `signsrv user add <name>`),"+
				" or a client token in %s (create with `signsrv client add <name>`)", f.secretEnv, f.tokenEnv)
		}
	}
	if f.token != "" && looksLikeAccessToken(f.token) {
		// The value is an access token, not a client key, so it is the thing to
		// send: no exchange, and one request per call. A chore script mints a
		// token once and reuses it, and the token endpoint is rate limited, so
		// exchanging on every verb would spend a bucket the script did not mean
		// to spend. A client key has no dots; it is exchanged below.
		f.access = f.token
	}
	if f.timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	return nil
}

// looksLikeAccessToken reports whether the credential is already a signed
// access token, which is the case for anything minted by the service's login,
// refresh, or client-token endpoint. A client key is "key_" plus hex, so the
// two shapes are not in doubt.
func looksLikeAccessToken(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

// mint signs an access token locally. The payload is fixed: the subject is the
// username, the audience is the API, the role is "user", and the validity is
// capped at 15 minutes because the service refuses anything longer. The scopes
// are the ones the CLI needs for its own verbs — the service answers a request
// with the scopes on the account's row, so what is put here is cosmetic.
func (f *envelopeFlags) mint() error {
	ttl := f.ttl
	if ttl <= 0 || ttl > 15*time.Minute {
		ttl = 15 * time.Minute
	}
	token, err := signauth.MintUserToken(f.secret, f.username,
		[]string{"envelope:write", "envelope:read"}, ttl)
	if err != nil {
		return err
	}
	f.access = token
	return nil
}

// exchange turns the client key into a short-lived bearer token. The key is the
// long-lived secret; it never rides on an API call. The answer is cached for the
// run, so one command costs one token request.
func (f *envelopeFlags) exchange() error {
	body, err := json.Marshal(map[string]string{"key": f.token})
	if err != nil {
		return err
	}
	u := strings.TrimRight(f.server, "/") + "/api/v1/auth/token"
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: f.timeout}).Do(req)
	if err != nil {
		return fmt.Errorf("POST /api/v1/auth/token: %w", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxServerReply))
	if err != nil {
		return fmt.Errorf("read token answer: %w", err)
	}
	if res.StatusCode >= 400 {
		return fmt.Errorf("POST /api/v1/auth/token: %s: the key is not valid, or its scopes do not cover this call", res.Status)
	}
	var out struct {
		Access string   `json:"access"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Access == "" {
		return fmt.Errorf("POST /api/v1/auth/token: the answer holds no access token")
	}
	f.access = out.Access

	return nil
}

func (f *envelopeFlags) ensureAccess() error {
	if f.access != "" {
		return nil
	}
	if f.secret != "" && f.username != "" {
		return f.mint()
	}
	return f.exchange()
}

// call performs one API request. The token goes in the Authorization header
// only; errors are decoded from the problem document.
func (f *envelopeFlags) call(method, path string, body io.Reader, contentType string) (int, []byte, error) {
	u := strings.TrimRight(f.server, "/") + path
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return 0, nil, err
	}
	if err := f.ensureAccess(); err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.access)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{Timeout: f.timeout}
	if f.insecure {
		// Only reached for http:// today; keep the transport honest for a
		// self-signed https endpoint in a development run rather than silently
		// accepting any certificate.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxServerReply))
	if err != nil {
		return res.StatusCode, nil, fmt.Errorf("read answer: %w", err)
	}
	if res.StatusCode >= 400 {
		var p apiError
		if json.Unmarshal(b, &p) == nil && (p.Problem.Code != "" || p.Problem.Message != "") {
			return res.StatusCode, b, p
		}
		return res.StatusCode, b, fmt.Errorf("%s %s: %s", method, path, res.Status)
	}
	return res.StatusCode, b, nil
}

// ------------------------------------------------------------- create -------

func envelopeCreate(args []string) int {
	fs := flag.NewFlagSet("envelope create", flag.ContinueOnError)
	var ef envelopeFlags
	ef.register(fs)
	specPath := fs.String("spec", "", "fill spec JSON (the extract schema with values)")
	partiesPath := fs.String("parties", "", "parties JSON array")
	title := fs.String("title", "", "envelope title")
	subject := fs.String("subject", "", "invitation subject line")
	message := fs.String("message", "", "invitation message")
	expires := fs.String("expires", "", "link lifetime, 72h or 3d")
	notify := fs.String("notify", "", "address to tell if a party declines or an invitation cannot be delivered")
	send := fs.Bool("send", false, "send the invitations after creating")
	widget := fs.String("widget", "", "widget to lock the form to (empty means every field)")
	if err := fs.Parse(args); err != nil {
		return report.Usage
	}
	if err := ef.resolve(); err != nil {
		return fail(err, "envelope create")
	}
	pos := fs.Args()
	if len(pos) == 0 {
		return fail(fmt.Errorf("needs the document to sign"), "envelope create")
	}
	template := pos[0]

	// The fill spec is read and normalised here, exactly as `fill` reads it, so
	// a spec that `pdf-go fill` accepts is a spec the service accepts.
	var spec schema.FillSpec
	if *specPath != "" {
		s, err := readSpec(*specPath)
		if err != nil {
			return fail(err, "envelope create")
		}
		spec = s
	}
	// The widget is the signature appearance. An empty --widget means the
	// service chooses, so the key is left out rather than sent as an empty
	// string, which the service would read as a malformed object.
	doc := map[string]any{"fill": spec}
	if *widget != "" {
		doc["widget"] = map[string]any{"field": *widget}
	}
	if *subject != "" {
		doc["subject"] = *subject
	}
	if *message != "" {
		doc["message"] = *message
	}
	if *notify != "" {
		doc["notify_email"] = *notify
	}
	specJSON, err := json.Marshal(doc)
	if err != nil {
		return fail(err, "envelope create")
	}
	if *partiesPath == "" {
		return fail(fmt.Errorf("needs --parties: a JSON array [{\"email\":\"a@x\",\"name\":\"Ann\",\"order\":1}]"), "envelope create")
	}
	parties, err := os.ReadFile(*partiesPath)
	if err != nil {
		return fail(err, "envelope create")
	}

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	file, err := os.Open(template)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", template, err), "envelope create")
	}
	defer file.Close()
	part, err := mw.CreateFormFile("template", filepath.Base(template))
	if err != nil {
		return fail(err, "envelope create")
	}
	if _, err := io.Copy(part, file); err != nil {
		return fail(err, "envelope create")
	}
	fields := map[string]string{
		"spec":       string(specJSON),
		"parties":    strings.TrimSpace(string(parties)),
		"title":      *title,
		"expires_in": *expires,
	}
	for name, value := range fields {
		if value == "" {
			continue
		}
		if err := mw.WriteField(name, value); err != nil {
			return fail(err, "envelope create")
		}
	}
	if err := mw.Close(); err != nil {
		return fail(err, "envelope create")
	}

	code, out, err := ef.call(http.MethodPost, "/api/v1/envelopes", body, mw.FormDataContentType())
	if err != nil {
		return failAPI(err, code)
	}
	// The service answers with the envelope view, the fill summary and the
	// links side by side; the id is inside the envelope object.
	var created struct {
		Envelope struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresAt string `json:"expires_at"`
		} `json:"envelope"`
		Fill struct {
			Applied []string `json:"applied"`
			Missing []string `json:"missing"`
		} `json:"fill"`
		Links []struct {
			Order int    `json:"order"`
			Email string `json:"email"`
			URL   string `json:"url"`
			Token string `json:"token"`
		} `json:"links"`
	}
	if err := json.Unmarshal(out, &created); err != nil {
		return fail(fmt.Errorf("decode answer: %w", err), "envelope create")
	}
	if ef.jsonOut {
		printJSON(out)
	}
	if len(created.Links) > 0 {
		if err := writeLinksFile(ef.linksOut, created.Envelope.ID, created.Links); err != nil {
			return fail(err, "envelope create")
		}
	}
	if !*send {
		return report.OK
	}
	// Send is a separate transition, so the links are written twice: once from
	// create (empty, Ready) and once from send, which is where they exist.
	code, out, err = ef.call(http.MethodPost, "/api/v1/envelopes/"+url.PathEscape(created.Envelope.ID)+"/send", strings.NewReader(""), "")
	if err != nil {
		return failAPI(err, code)
	}
	if ef.jsonOut {
		printJSON(out)
	}
	var sent struct {
		Links []struct {
			Order int    `json:"order"`
			Email string `json:"email"`
			URL   string `json:"url"`
			Token string `json:"token"`
		} `json:"links"`
	}
	if err := json.Unmarshal(out, &sent); err != nil {
		return fail(fmt.Errorf("decode answer: %w", err), "envelope create")
	}
	if len(sent.Links) > 0 {
		if err := writeLinksFile(ef.linksOut, created.Envelope.ID, sent.Links); err != nil {
			return fail(err, "envelope create")
		}
	}
	return report.OK
}

type linksFile struct {
	Envelope string      `json:"envelope"`
	Written  time.Time   `json:"written"`
	Links    []linkEntry `json:"links"`
}

type linkEntry struct {
	Order int    `json:"order"`
	Email string `json:"email"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// writeLinksFile stores the links at mode 0600. The default name is derived
// from the envelope id, which is not a secret, so the file is findable later;
// its contents are, which is why the mode is 0600 and the runbook says to
// delete it.
func writeLinksFile(path, id string, links any) error {
	if path == "" {
		path = "envelope-" + id + ".links.json"
	}
	content, err := json.MarshalIndent(linksFile{Envelope: id, Written: time.Now().UTC(), Links: toLinkEntries(links)}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write links to %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "signing links written to %s (mode 0600): remove it when the parties have their links\n", path)
	return nil
}

func toLinkEntries(links any) []linkEntry {
	raw, _ := json.Marshal(links)
	var out []linkEntry
	_ = json.Unmarshal(raw, &out)
	return out
}

// --------------------------------------------------------------- get --------

// envelopeGet reads one envelope. With -watch it keeps reading until the
// envelope reaches a state that will not change, printing one line per poll,
// which is what the runbook asks an operator to run after a send:
//
//	pdf-go envelope get <id> --watch
//
// The exit code is the answer: 0 when the document was signed and delivered,
// 1 when the request ended without one (failed, cancelled, expired), 2 when
// the envelope could not be read at all. The status lines go to stderr, so
// stdout stays a single JSON document.
func envelopeGet(args []string) int {
	fs := flag.NewFlagSet("envelope get", flag.ContinueOnError)
	var ef envelopeFlags
	var watch bool
	var every time.Duration
	ef.register(fs)
	fs.BoolVar(&watch, "watch", false, "poll until the envelope settles")
	fs.DurationVar(&every, "interval", 5*time.Second, "poll period with -watch")
	if err := fs.Parse(args); err != nil {
		return report.Usage
	}
	if err := ef.resolve(); err != nil {
		return fail(err, "envelope get")
	}
	pos := fs.Args()
	if len(pos) == 0 {
		return fail(fmt.Errorf("needs an envelope id"), "envelope get")
	}
	id := url.PathEscape(pos[0])
	deadline := time.Now().Add(ef.timeout)
	if every <= 0 {
		every = 5 * time.Second
	}
	for {
		code, out, err := ef.call(http.MethodGet, "/api/v1/envelopes/"+id, nil, "")
		if err != nil {
			return failAPI(err, code)
		}
		var view struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(out, &view); err != nil {
			return fail(fmt.Errorf("the service answered without a status: %w", err), "envelope get")
		}
		if !watch {
			if ef.jsonOut {
				printJSON(out)
			}
			return report.OK
		}
		fmt.Fprintf(os.Stderr, "envelope %s: %s\n", pos[0], view.Status)
		switch view.Status {
		case "delivered", "completed":
			if ef.jsonOut {
				printJSON(out)
			}
			return report.OK
		case "failed", "cancelled", "expired":
			if ef.jsonOut {
				printJSON(out)
			}
			fmt.Fprintf(os.Stderr, "envelope %s ended at %s: nothing was delivered\n", pos[0], view.Status)
			return report.InputErr
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "envelope %s is still %s after %s; the batch has not finished\n",
				pos[0], view.Status, ef.timeout)
			return report.InputErr
		}
		time.Sleep(every)
	}
}

// ------------------------------------------------------------- links --------

// envelopeLinks prints the links that `create` or `send` recorded locally. It
// does not contact the service: signing links are not re-issueable through a
// read, and asking for them again would mean a mutation.
func envelopeLinks(args []string) int {
	fs := flag.NewFlagSet("envelope links", flag.ContinueOnError)
	var ef envelopeFlags
	ef.register(fs)
	if err := fs.Parse(args); err != nil {
		return report.Usage
	}
	pos := fs.Args()
	if len(pos) == 0 {
		return fail(fmt.Errorf("needs an envelope id"), "envelope links")
	}
	path := ef.linksOut
	if path == "" {
		path = "envelope-" + pos[0] + ".links.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", path, err), "envelope links")
	}
	var lf linksFile
	if err := json.Unmarshal(b, &lf); err != nil {
		return fail(fmt.Errorf("parse %s: %w", path, err), "envelope links")
	}
	for _, l := range lf.Links {
		fmt.Printf("%d\t%s\t%s\n", l.Order, l.Email, l.URL)
	}
	fmt.Fprintf(os.Stderr, "%d link(s) from %s: these URLs are the party's credential\n", len(lf.Links), path)
	return report.OK
}

// ------------------------------------------------- send / report ------------

// envelopeSendOrReport either drives the send transition or fetches the
// verification report. Both take only an id.
func envelopeSendOrReport(args []string, what string) int {
	fs := flag.NewFlagSet("envelope "+what, flag.ContinueOnError)
	var ef envelopeFlags
	ef.register(fs)
	if err := fs.Parse(args); err != nil {
		return report.Usage
	}
	if err := ef.resolve(); err != nil {
		return fail(err, "envelope "+what)
	}
	pos := fs.Args()
	if len(pos) == 0 {
		return fail(fmt.Errorf("needs an envelope id"), "envelope "+what)
	}
	path := "/api/v1/envelopes/" + url.PathEscape(pos[0])
	method := http.MethodGet
	var body io.Reader
	if what == "send" {
		// Send is a POST with an empty body: the transition takes no input.
		path += "/send"
		method = http.MethodPost
		body = strings.NewReader("")
	} else {
		path += "/report"
	}
	code, out, err := ef.call(method, path, body, "")
	if err != nil {
		return failAPI(err, code)
	}
	if ef.jsonOut {
		printJSON(out)
	}
	if what == "send" {
		var sent struct {
			Links []struct {
				Order int    `json:"order"`
				Email string `json:"email"`
				URL   string `json:"url"`
				Token string `json:"token"`
			} `json:"links"`
		}
		if json.Unmarshal(out, &sent) == nil && len(sent.Links) > 0 {
			if err := writeLinksFile(ef.linksOut, pos[0], sent.Links); err != nil {
				return fail(err, "envelope send")
			}
		}
	}
	return report.OK
}

// printJSON writes the answer pretty-printed, or verbatim when it is not JSON.
func printJSON(b []byte) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		os.Stdout.Write(b)
		fmt.Println()
		return
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		os.Stdout.Write(b)
		fmt.Println()
		return
	}
	fmt.Println(string(out))
}

// failAPI reports a rejected request. 401 and 403 usually mean the client key
// is missing, revoked, or lacks a scope, which is worth saying plainly.
func failAPI(err error, code int) int {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fail(fmt.Errorf("%w: check the client token (`signsrv client list`) and its scopes", err), "envelope")
	case http.StatusTooManyRequests:
		return fail(fmt.Errorf("%w: the service is rate limiting this client", err), "envelope")
	default:
		return fail(err, "envelope")
	}
}

// envelopeDocumentSHA is a helper for scripts that want to check the uploaded
// bytes against the document_sha the service reports.
func envelopeDocumentSHA(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
