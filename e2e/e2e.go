//go:build e2e

// Command e2e is the acceptance test of the signing service: it runs the real
// binaries, drives the real signing app in a real browser, and checks the
// result against the rules the service claims to hold. It sits behind the e2e
// build tag on purpose, so `go test ./...` stays fast and offline.
//
//	go build -tags e2e -o /tmp/e2e ./e2e && /tmp/e2e
//	e2e/run.sh                 # the same, with the tool check first
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/digitorus/timestamp"
)

const (
	adminEmail = "admin@e2e.test"
	adminPass  = "e2e-admin-password-long"
	keystorePW = "e2e-keystore-passphrase-long"
)

var (
	root      string
	work      string
	base      string
	port      int
	adminTok  string
	clientKey string
	envID     string
	links     = map[string]string{}
	tsa       *mockTSA
	tsaHits   atomic.Int64
	tsaStamps atomic.Int64
	server    *exec.Cmd
	failed    int
	// stops are the phases named on the command line. The run then goes in
	// order and stops after the last one named, because the phases build on
	// each other: skipping ahead to "audit chain" without signing anything
	// would prove nothing.
	stops []string
)

// clientAccess is the bearer token the API accepts for the e2e client key. The
// key itself never rides on an API call: it is exchanged at /auth/token exactly
// as the CLI does, and the answer is reused for the checks that need it.
var clientAccess string

// clientTokenExchange performs the exchange and returns the access token.
func clientTokenExchange() string {
	body, _ := json.Marshal(map[string]string{"key": clientKey})
	res, err := http.Post(base+"/api/v1/auth/token", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("   - client token exchange: %v\n", err)
		return ""
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		fmt.Printf("   - client token exchange: %s: %s\n", res.Status, b)
		return ""
	}
	var out struct {
		Access string `json:"access"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Access == "" {
		fmt.Printf("   - client token exchange: no access token in %s\n", b)
		return ""
	}
	return out.Access
}

type linkRec struct {
	PartyID string `json:"party_id"`
	Email   string `json:"email"`
	Order   int    `json:"order"`
	Token   string `json:"token"`
	URL     string `json:"url"`
}

func main() {
	// Without a browser, the run stops after the send: the phases past that
	// point all need the consents the browser phase produces.
	if os.Getenv("E2E_SKIP_BROWSER") == "1" {
		stops = []string{"send + outbox"}
	}
	for _, a := range os.Args[1:] {
		if a == "-list" || a == "--list" {
			for _, s := range phases() {
				fmt.Println(s)
			}
			return
		}
		if strings.HasPrefix(a, "-") {
			bail("unknown flag %q (try -list)", a)
		}
		if !slices.Contains(phases(), a) {
			bail("no phase %q (try -list)", a)
		}
		stops = append(stops, a)
	}
	start := time.Now()
	var err error
	root, err = os.Getwd()
	if err != nil {
		bail("cwd: %v", err)
	}
	work = envOr("E2E_WORK", filepath.Join(os.TempDir(), "signsrv-e2e"))
	if err := os.RemoveAll(work); err != nil {
		bail("clean %s: %v", work, err)
	}
	for _, d := range []string{"", "keystore", "storage", "audit", "outbox", "log", "reports"} {
		if err := os.MkdirAll(filepath.Join(work, d), 0o755); err != nil {
			bail("mkdir %s: %v", d, err)
		}
	}

	phase("build", buildBinaries)
	phase("mock tsa", startTSA)
	phase("config", writeConfig)
	phase("start service", startService)
	phase("admin login", adminLogin)
	phase("client key", clientKeyPhase)
	phase("cli create", cliCreate)
	phase("send + outbox", sendAndOutbox)
	phase("browser signing", browserSigning)
	phase("cli watch", cliWatch)
	phase("cli report", cliReport)
	phase("audit chain", auditChain)
	phase("artefacts", copyArtefacts)
	phase("negatives", negatives)
	phase("rate limit", rateLimit)
	phase("log redaction", logRedaction)
	phase("graceful stop", gracefulStop)

	// A subset run stops before the graceful-stop phase, and the service the
	// run started must not outlive it.
	if server != nil && server.ProcessState == nil {
		_ = server.Process.Signal(syscall.SIGTERM)
		_ = server.Wait()
	}

	fmt.Printf("\n%s\nfailures: %d   duration: %s\n", strings.Repeat("-", 66), failed, time.Since(start).Round(time.Millisecond))
	fmt.Println("evidence:", filepath.Join(work, "reports"))
	if failed > 0 {
		os.Exit(1)
	}
}

func phases() []string {
	return []string{"build", "mock tsa", "config", "start service", "admin login", "client key",
		"cli create", "send + outbox", "browser signing", "cli watch", "cli report", "audit chain",
		"artefacts", "rate limit", "negatives", "log redaction", "graceful stop"}
}

// phase runs one step. A failure is recorded and the run continues: the point
// of an acceptance run is the list of what broke, not the first break. A phase
// that cannot be recovered from calls bail itself.
func phase(name string, fn func() error) {
	fmt.Printf("\n== %s\n", name)
	if skipped(name) {
		fmt.Printf("   not selected on the command line\n")
		return
	}
	if err := fn(); err != nil {
		fmt.Printf("   FAIL %s: %v\n", name, err)
		failed++
		return
	}
	fmt.Printf("   ok\n")
}

// skipped reports whether a phase falls past the last phase named on the
// command line. Everything up to that point runs, because the phases build on
// each other: asking for "audit chain" needs the signing that produces the
// events it verifies.
func skipped(name string) bool {
	if len(stops) == 0 {
		return false
	}
	last, all := 0, phases()
	for _, s := range stops {
		for i, p := range all {
			if p == s && i > last {
				last = i
			}
		}
	}
	for i, p := range all {
		if p == name {
			return i > last
		}
	}
	return false
}

func checkf(cond bool, format string, args ...any) {
	if !cond {
		fmt.Printf("   - %s\n", fmt.Sprintf(format, args...))
		failed++
	}
}

func bail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "e2e: %s\n", fmt.Sprintf(format, args...))
	if server != nil && server.Process != nil {
		_ = server.Process.Kill()
	}
	os.Exit(1)
}

// evidence writes a phase's output where a person can go and read it.
func evidence(name string, body []byte) {
	p := filepath.Join(work, "reports", name+".txt")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		fmt.Printf("   - write evidence %s: %v\n", name, err)
		return
	}
	fmt.Printf("   evidence: %s (%d bytes)\n", p, len(body))
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func bin(name string) string { return filepath.Join(work, name) }

// ----------------------------------------------------------------- build ----

func buildBinaries() error {
	goBin := envOr("GO", "go")
	for _, b := range []struct{ out, pkg string }{
		{"signsrv", "./cmd/signsrv"},
		{"pdf-go", "./cmd/pdf-go"},
	} {
		cmd := exec.Command(goBin, "build", "-mod=vendor", "-o", bin(b.out), b.pkg)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("build %s: %v\n%s", b.pkg, err, out)
		}
	}
	fmt.Printf("   built signsrv and pdf-go in %s\n", work)
	return nil
}

// -------------------------------------------------------------- mock TSA ----

// The run needs a TSA, and it needs to be able to prove afterwards that a
// timestamp was really obtained. The mock answers a real RFC 3161 request with
// a real token, so the token embedded in the PDF is genuine; the URL, the hit
// counter and the issued-token counter are the evidence that a round trip
// happened, and the log lines naming tsa_url are the audit trail of it.
type mockTSA struct {
	srv  *httptest.Server
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	url  string
}

func startTSA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20261106),
		Subject:      pkix.Name{CommonName: "signsrv e2e TSA", Organization: []string{"signsrv e2e"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		// The TSA certificate is the parent of the timestamp token, so it has
		// to be a CA certificate: the PKCS#7 verifier walks the chain and a
		// plain leaf certificate cannot sign a token.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	tsa = &mockTSA{cert: cert, key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/tsr", func(w http.ResponseWriter, r *http.Request) {
		hits := tsaHits.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "mock tsa: bad request: "+err.Error())
			return
		}
		policy := req.TSAPolicyOID
		if len(policy) == 0 {
			policy = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 1}
		}
		ts := &timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now().UTC(),
			Accuracy:          time.Second,
			SerialNumber:      big.NewInt(hits),
			Policy:            policy,
			Nonce:             req.Nonce,
			Certificates:      []*x509.Certificate{tsa.cert},
			AddTSACertificate: true,
		}
		resp, err := ts.CreateResponseWithOpts(tsa.cert, tsa.key, crypto.SHA256)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "mock tsa: "+err.Error())
			return
		}
		tsaStamps.Add(1)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(resp)
	})
	tsa.srv = httptest.NewServer(mux)
	tsa.url = tsa.srv.URL + "/tsr"
	fmt.Printf("   mock TSA at %s\n", tsa.url)
	return nil
}

// ----------------------------------------------------------------- config ---

var cfgPath string

// freePort asks the kernel for a port nobody is holding and hands it back. The
// service binds a port named in its config, so a fixed port would make the run
// collide with anything already listening on the machine — and a run that
// cannot start the service proves nothing.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func writeConfig() error {
	cfgPath = filepath.Join(work, "e2e.env")
	p, err := freePort()
	if err != nil {
		return err
	}
	port = p
	fmt.Printf("   listening on 127.0.0.1:%d\n", port)
	// Dev mode is what makes an offline acceptance run possible: it allows a
	// plain-HTTP loopback listener and writes the invitations as .eml files
	// instead of talking to SMTP. Nothing here is a production shape except the
	// tsa_url, which is the mock.
	body := strings.Join([]string{
		"listen = 127.0.0.1:" + fmt.Sprint(port),
		"public_url = http://127.0.0.1:" + fmt.Sprint(port),
		"dev = true",
		"db = " + filepath.Join(work, "e2e.db"),
		"storage_dir = " + filepath.Join(work, "storage"),
		"keystore_dir = " + filepath.Join(work, "keystore"),
		"outbox_dir = " + filepath.Join(work, "outbox"),
		"audit_dir = " + filepath.Join(work, "audit"),
		"log_path = " + filepath.Join(work, "log", "signsrv.jsonl"),
		"log_level = info",
		"jwt_secret_file = " + filepath.Join(work, "jwt.ed25519.key"),
		"keystore_pass = " + keystorePW,
		"admin_password = " + adminPass,
		"link_ttl = 72h",
		"mail_from = signsrv@e2e.test",
		"tsa_url = " + tsa.url,
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write config: %v", err)
	}
	fmt.Printf("   wrote %s (mode 0600)\n", cfgPath)
	return nil
}

// --------------------------------------------------------------- service ----

func startService() error {
	if out, err := run(root, bin("signsrv"), "checkconfig", "-config", cfgPath); err != nil {
		return fmt.Errorf("checkconfig: %v\n%s", err, out)
	} else {
		evidence("checkconfig", out)
	}
	if out, err := run(root, bin("signsrv"), "migrate", "-config", cfgPath); err != nil {
		return fmt.Errorf("migrate: %v\n%s", err, out)
	} else {
		evidence("migrate", out)
	}
	// The admin account is created by the operator, with the password in the
	// environment rather than on a terminal.
	out, err := runEnv(map[string]string{"SIGNSRV_ADMIN_PASSWORD": adminPass}, root,
		bin("signsrv"), "admin", "add", adminEmail, "-config", cfgPath)
	if err != nil && !strings.Contains(string(out), "already exists") {
		return fmt.Errorf("admin add: %v\n%s", err, out)
	}
	evidence("admin-add", out)

	srv := exec.Command(bin("signsrv"), "serve", "-config", cfgPath)
	srv.Dir = root
	srv.Stdout = io.Discard
	srv.Stderr = io.Discard
	if err := srv.Start(); err != nil {
		return fmt.Errorf("serve: %v", err)
	}
	server = srv
	base = "http://127.0.0.1:" + fmt.Sprint(port)
	for i := 0; i < 80; i++ {
		res, err := http.Get(base + "/healthz")
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				fmt.Printf("   healthz: %s\n", strings.TrimSpace(string(b)))
				fmt.Printf("   serving at %s (pid %d)\n", base, srv.Process.Pid)
				return nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("healthz never answered 200 at %s", base)
}

func run(dir, name string, args ...string) ([]byte, error) {
	return runEnv(nil, dir, name, args...)
}

func runEnv(env map[string]string, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd.CombinedOutput()
}

// ----------------------------------------------------------------- login ----

func adminLogin() error {
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, adminEmail, adminPass)
	req, _ := http.NewRequest("POST", base+"/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("login %s: %s", res.Status, b)
	}
	var out struct {
		Access string   `json:"access"`
		Role   string   `json:"role"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	adminTok = out.Access
	checkf(adminTok != "", "login returned no access token")
	checkf(out.Role == "admin", "role is %q, want admin", out.Role)
	fmt.Printf("   logged in as %s, role %s, scopes %v\n", adminEmail, out.Role, out.Scopes)
	return nil
}

func clientKeyPhase() error {
	out, err := run(root, bin("signsrv"), "client", "add", "e2e-cli", "envelope:write", "envelope:read", "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("client add: %v\n%s", err, out)
	}
	evidence("client-add", out)
	for _, l := range strings.Split(string(out), "\n") {
		if v := strings.TrimPrefix(l, "key: "); v != l {
			clientKey = strings.TrimSpace(v)
		}
	}
	if clientKey == "" {
		return fmt.Errorf("no key in the client add output: %s", out)
	}
	// The API-facing checks (the negative set) need the exchanged token, not
	// the key: the key is the credential, the token is what rides on a call.
	clientAccess = clientTokenExchange()
	if clientAccess == "" {
		return fmt.Errorf("the client key could not be exchanged for an access token")
	}
	fmt.Printf("   client key created (%d characters, shown once)\n", len(clientKey))
	return nil
}

// ---------------------------------------------------------------- create ----

func cliCreate() error {
	specPath := filepath.Join(work, "fill.json")
	// The spec file is the plain `pdf-go fill` JSON: the CLI wraps it into the
	// create document, so the same file drives the CLI fill and the API fill.
	spec := map[string]any{"values": map[string]string{
		"Text1": "Acme Ltd",
		"Text2": "2026-11-06",
		"Text3": "USD 12,400",
		"Text4": "Twelve widgets, net 30 days.",
		"Text5": "Acme / Beta supply agreement",
		"Text6": "signsrv acceptance run",
	}}
	b, _ := json.Marshal(spec)
	if err := os.WriteFile(specPath, b, 0o644); err != nil {
		return err
	}
	partyPath := filepath.Join(work, "parties.json")
	pb, _ := json.Marshal([]map[string]any{
		{"email": "ana@e2e.test", "name": "Ana Renderer", "order": 1, "reason": "I agree to the terms"},
		{"email": "bob@e2e.test", "name": "Bob Countersign", "order": 2, "reason": "Countersigned"},
	})
	if err := os.WriteFile(partyPath, pb, 0o600); err != nil {
		return err
	}

	cmd := exec.Command(bin("pdf-go"), "envelope", "create",
		"-server", base, "-token-env", "E2E_CLIENT_KEY", "-insecure",
		"-title", "Acme supply agreement", "-expires", "72h",
		"-spec", specPath, "-parties", partyPath,
		"-links-out", filepath.Join(work, "links.json"),
		filepath.Join(root, "testdata", "sample2.pdf"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "E2E_CLIENT_KEY="+clientKey)
	out, err := cmd.CombinedOutput()
	evidence("cli-create", out)
	if err != nil {
		return fmt.Errorf("cli envelope create: %v\n%s", err, out)
	}

	var created struct {
		Envelope struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"envelope"`
		Fill struct {
			Applied []string `json:"applied"`
			Missing []string `json:"missing"`
		} `json:"fill"`
		Links []linkRec `json:"links"`
	}
	if err := json.Unmarshal(firstJSON(out), &created); err != nil {
		return fmt.Errorf("decode create answer: %v", err)
	}
	envID = created.Envelope.ID
	if envID == "" {
		return fmt.Errorf("no envelope id in the create answer")
	}
	checkf(created.Envelope.Status == "ready", "status after create is %q, want ready", created.Envelope.Status)
	checkf(len(created.Fill.Applied) == 6, "fill applied %d field(s), want 6 (missing: %v)", len(created.Fill.Applied), created.Fill.Missing)
	// The create response is one of the two places a raw link exists at all.
	checkf(len(created.Links) == 2, "create returned %d links, want 2", len(created.Links))
	fmt.Printf("   envelope %s created (ready), %d fields filled, %d missing\n",
		envID, len(created.Fill.Applied), len(created.Fill.Missing))
	return nil
}

// firstJSON pulls the JSON object out of CLI output that may carry prose.
func firstJSON(out []byte) []byte {
	s := string(out)
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return nil
	}
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return []byte(s[i : j+1])
			}
		}
	}
	return nil
}

// ----------------------------------------------------------------- send -----

func sendAndOutbox() error {
	// Flags come before the positional id: Go's flag parser stops at the first
	// non-flag argument.
	cmd := exec.Command(bin("pdf-go"), "envelope", "send",
		"-server", base, "-token-env", "E2E_CLIENT_KEY", "-insecure",
		"-links-out", filepath.Join(work, "links.json"),
		envID)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "E2E_CLIENT_KEY="+clientKey)
	out, err := cmd.CombinedOutput()
	evidence("cli-send", out)
	if err != nil {
		return fmt.Errorf("cli envelope send: %v\n%s", err, out)
	}
	var sent struct {
		Envelope struct {
			Status string `json:"status"`
		} `json:"envelope"`
		Links []linkRec `json:"links"`
	}
	if err := json.Unmarshal(firstJSON(out), &sent); err != nil {
		return fmt.Errorf("decode send answer: %v", err)
	}
	checkf(sent.Envelope.Status == "sent", "status after send is %q, want sent", sent.Envelope.Status)
	checkf(len(sent.Links) == 2, "send returned %d links, want 2", len(sent.Links))
	for _, l := range sent.Links {
		links[l.Email] = l.URL
		checkf(strings.Contains(l.URL, "/s/") && l.Token != "", "link for %s is not a signing link", l.Email)
	}
	checkf(len(links) == 2, "have %d links, want 2", len(links))

	// `envelope links` reads back what create/send recorded, so the operator
	// can print the links again without asking the service for a new ones.
	// `envelope links` re-reads the file the send wrote: the operator can print
	// the links again without asking the service to mint new ones. The links
	// file is not an API resource, so this command needs no server or token.
	out, err = run(root, bin("pdf-go"), "envelope", "links",
		"-links-out", filepath.Join(work, "links.json"), envID)
	evidence("cli-links", out)
	if err != nil {
		return fmt.Errorf("cli envelope links: %v\n%s", err, out)
	}
	for _, l := range links {
		checkf(bytes.Contains(out, []byte(l)), "envelope links did not print %s", l)
	}

	fi, err := os.Stat(filepath.Join(work, "links.json"))
	if err != nil {
		return fmt.Errorf("links file: %v", err)
	}
	checkf(fi.Mode().Perm() == 0o600, "the links file is mode %o, want 600", fi.Mode().Perm())

	// The worker renders the invitations. In dev mode they land as .eml files,
	// which is the artifact the runbook points an operator at.
	if err := waitOutbox(2); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(work, "outbox"))
	if err != nil {
		return err
	}
	var all []byte
	names := []string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".eml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(work, "outbox", e.Name()))
		if err != nil {
			return err
		}
		names = append(names, e.Name())
		all = append(all, b...)
		all = append(all, "\n---\n"...)
	}
	evidence("outbox", all)
	text := string(all)
	for _, email := range []string{"ana@e2e.test", "bob@e2e.test"} {
		checkf(strings.Contains(text, email), "no invitation addressed to %s (%d files)", email, len(names))
	}
	checkf(strings.Contains(text, base+"/s/"), "no invitation carries a signing link")
	checkf(len(links) == 2 && strings.Contains(text, tokenOf(links["ana@e2e.test"])), "the invitation does not carry ana's own link")
	fmt.Printf("   outbox holds %d invitation(s): %s\n", len(names), strings.Join(names, ", "))

	// An unknown link token must be refused without describing the request it
	// does not belong to. The check is on the API, not on /s/<token>: the shell
	// page is served for every /s/ path on purpose — the SPA decides, from the
	// API's answer, whether the link is real.
	res, err := http.Get(base + "/api/v1/sign/deadbeefdeadbeefdeadbeefdeadbeef/envelope")
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	res.Body.Close()
	checkf(res.StatusCode == http.StatusNotFound, "an unknown link token gave %s, want 404 (%s)", res.Status, b)
	evidence("unknown-link-token", []byte(res.Status+" "+string(b)))
	return nil
}

func tokenOf(url string) string {
	i := strings.LastIndex(url, "/")
	if i < 0 {
		return url
	}
	return url[i+1:]
}

func waitOutbox(n int) error {
	for i := 0; i < 80; i++ {
		count := 0
		entries, err := os.ReadDir(filepath.Join(work, "outbox"))
		if err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".eml") {
					count++
				}
			}
		}
		if count >= n {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("the outbox never received %d invitation(s); is the worker running?", n)
}

// ------------------------------------------------------------ browser -------

func browserSigning() error {
	script := filepath.Join(work, "signer.js")
	js := fmt.Sprintf(`
const { chromium } = require(%q);
const base = %q;
const parties = %s;
(async () => {
  const browser = await chromium.launch({ executablePath: %q, args: ['--no-sandbox','--disable-dev-shm-usage'] });
  const say = [];
  for (const p of parties) {
    const step = (label, text) => say.push([p.email, label, String(text).replace(/\s+/g,' ')].join('\t'));

    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(new URL(p.link, base).toString(), { waitUntil: 'networkidle' });
    step('link-open', (await page.textContent('h1')).trim());

    // 1. claim: the link names a person, and the app asks who they are.
    await page.waitForSelector('input[type=email]');
    await page.fill('input[type=email]', p.email);
    await page.click('button');
    await page.waitForSelector('iframe', { timeout: 20000 });
    step('document-shown', 'iframe ' + await page.getAttribute('iframe', 'src'));

    // The review panel is separate from the document: opening the document is
    // not the same as consenting to it. The Sign button proves that.
    await page.click('text=I have reviewed it: continue');
    await page.waitForSelector('textarea', { timeout: 20000 });
    const agree = page.locator('button:has-text("Sign")');
    step('sign-disabled-before-typing', await agree.isDisabled());
    await page.fill('textarea', p.name);
    step('sign-disabled-without-checkbox', await agree.isDisabled());
    await page.check('input[type=checkbox]');
    step('sign-enabled-after-consent', await agree.isDisabled());
    await agree.click();
    await page.waitForSelector('h1', { timeout: 40000 });
    step('result', (await page.textContent('h1')).trim());
    await ctx.close();

    // The same link, claimed by someone else, must be refused.
    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    await page2.goto(new URL(p.link, base).toString(), { waitUntil: 'networkidle' });
    await page2.waitForSelector('input[type=email]');
    await page2.fill('input[type=email]', 'someone-else@e2e.test');
    await page2.click('button');
    await page2.waitForSelector('#statusline', { timeout: 20000 });
    step('wrong-address-refused', (await page2.textContent('#statusline')).trim());
    await ctx2.close();
  }
  await browser.close();
  console.log(say.join('\n'));
})().catch(e => { console.error('BROWSER FAIL: ' + e.message); process.exit(1); });
`, nodePlaywright(), base, partyJS(), envOr("CHROME", "/usr/bin/google-chrome"))

	if err := os.WriteFile(script, []byte(js), 0o644); err != nil {
		return err
	}
	cmd := exec.Command(envOr("NODE", "node"), script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "NODE_PATH="+envOr("E2E_NODE_MODULES", "/tmp/pw/node_modules"))
	out, err := cmd.CombinedOutput()
	evidence("browser-flow", out)
	if err != nil {
		return fmt.Errorf("browser flow: %v\n%s", err, out)
	}
	text := string(out)
	fmt.Printf("   browser transcript:\n")
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		fmt.Printf("     %s\n", strings.ReplaceAll(l, "\t", " | "))
	}
	for _, email := range []string{"ana@e2e.test", "bob@e2e.test"} {
		checkf(strings.Contains(text, email+"\tresult"), "%s never reached the result screen", email)
		checkf(strings.Contains(text, email+"\tdocument-shown"), "%s never saw the document", email)
		checkf(strings.Contains(text, email+"twrong-address-refused") || strings.Contains(text, email+"\twrong-address-refused"),
			"%s: the wrong-address case was not exercised", email)
	}
	checkf(strings.Contains(text, "sign-disabled-before-typing\ttrue"), "the Sign button was enabled before anything was typed")
	checkf(strings.Contains(text, "sign-disabled-without-checkbox\ttrue"), "the Sign button was enabled without ticking the consent box")
	checkf(strings.Contains(text, "sign-enabled-after-consent\tfalse"), "the Sign button stayed disabled after typing and consenting")

	status, err := waitEnvelope("delivered", 60*time.Second)
	if err != nil {
		return err
	}
	checkf(status == "delivered", "envelope status is %q, want delivered", status)
	return nil
}

func partyJS() string {
	return fmt.Sprintf(`[{"email":"ana@e2e.test","name":"Ana Renderer","link":%q},{"email":"bob@e2e.test","name":"Bob Countersign","link":%q}]`,
		links["ana@e2e.test"], links["bob@e2e.test"])
}

func nodePlaywright() string {
	return envOr("E2E_NODE_MODULES", "/tmp/pw/node_modules") + "/playwright-core"
}

func waitEnvelope(want string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	status := ""
	for time.Now().Before(deadline) {
		b, err := apiGet("/api/v1/envelopes/" + envID)
		if err != nil {
			return status, err
		}
		var env struct {
			Status  string `json:"status"`
			Parties []struct {
				Email  string `json:"email"`
				Status string `json:"status"`
			} `json:"parties"`
			Consented int `json:"consented"`
			Total     int `json:"total"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			return status, err
		}
		status = env.Status
		if status == want {
			for _, p := range env.Parties {
				fmt.Printf("   party %s: %s\n", p.Email, p.Status)
			}
			fmt.Printf("   consented %d of %d\n", env.Consented, env.Total)
			return status, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return status, fmt.Errorf("the envelope stayed %q, never reached %q", status, want)
}

func apiGet(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 400 {
		return b, fmt.Errorf("%s: %s: %s", path, res.Status, b)
	}
	return b, nil
}

// ---------------------------------------------------------------- report ----

// cliWatch runs the operator's own command after a send:
//
//	pdf-go envelope get <id> --watch
//
// It is the documented way to see a request settle, so the run asserts it
// settles on "delivered" and exits 0, and that the answer carries the party
// list the admin page shows.
func cliWatch() error {
	cmd := exec.Command(bin("pdf-go"), "envelope", "get",
		"-server", base, "-token-env", "E2E_CLIENT_KEY", "-insecure",
		"-watch", "-interval", "1s", "-timeout", "60s", envID)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "E2E_CLIENT_KEY="+clientKey)
	out, err := cmd.CombinedOutput()
	evidence("cli-watch", out)
	if err != nil {
		return fmt.Errorf("cli envelope get --watch: %v\n%s", err, out)
	}
	var view struct {
		Status  string `json:"status"`
		Parties []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"parties"`
	}
	if err := json.Unmarshal(firstJSON(out), &view); err != nil {
		return fmt.Errorf("decode envelope view: %v", err)
	}
	checkf(view.Status == "delivered", "--watch settled on %q, want delivered", view.Status)
	consented := 0
	for _, p := range view.Parties {
		if p.Status == "consented" {
			consented++
		}
	}
	checkf(consented == 2, "the envelope view has %d consented parties, want 2", consented)
	fmt.Printf("   --watch reached %s with %d consented parties\n", view.Status, consented)
	return nil
}

func cliReport() error {
	cmd := exec.Command(bin("pdf-go"), "envelope", "report",
		"-server", base, "-token-env", "E2E_CLIENT_KEY", "-insecure",
		envID)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "E2E_CLIENT_KEY="+clientKey)
	out, err := cmd.CombinedOutput()
	evidence("verification-report", out)
	if err != nil {
		return fmt.Errorf("cli envelope report: %v\n%s", err, out)
	}
	var wrapped struct {
		Envelope        string `json:"envelope"`
		SHA256          string `json:"sha256"`
		SignedParties   int    `json:"signed_parties"`
		RequiredParties int    `json:"required_parties"`
		Complete        bool   `json:"complete"`
		Report          struct {
			Valid   bool `json:"valid"`
			Signers []struct {
				Name        string `json:"name"`
				Valid       bool   `json:"valid"`
				Timestamped bool   `json:"timestamped"`
				Time        string `json:"time"`
			} `json:"signers"`
			Errors []string `json:"errors"`
		} `json:"report"`
	}
	if err := json.Unmarshal(firstJSON(out), &wrapped); err != nil {
		return fmt.Errorf("decode report: %v", err)
	}
	checkf(wrapped.Report.Valid, "the signed document does not verify: %v", wrapped.Report.Errors)
	checkf(wrapped.SignedParties == 2, "the document carries %d party signatures, want 2", wrapped.SignedParties)
	checkf(wrapped.Complete, "the report says the envelope is not complete (%d of %d)", wrapped.SignedParties, wrapped.RequiredParties)
	stamped := 0
	for _, s := range wrapped.Report.Signers {
		checkf(s.Valid, "signer %q is not valid", s.Name)
		if s.Timestamped {
			stamped++
		}
	}
	checkf(stamped == len(wrapped.Report.Signers), "%d of %d signatures carry a timestamp token", stamped, len(wrapped.Report.Signers))
	fmt.Printf("   report: valid=%v, %d signers, %d timestamped\n", wrapped.Report.Valid, len(wrapped.Report.Signers), stamped)

	// The signed bytes have to be downloadable and verify offline, with the
	// service's own tool, from the bytes a client fetched.
	req, err := http.NewRequest("GET", base+"/api/v1/envelopes/"+envID+"/document", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	pdfBytes, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download the signed document: %s", res.Status)
	}
	signed := filepath.Join(work, "signed.pdf")
	if err := os.WriteFile(signed, pdfBytes, 0o644); err != nil {
		return err
	}
	checkf(bytes.HasPrefix(pdfBytes, []byte("%PDF-")), "the downloaded document is not a PDF")

	out, err = run(root, bin("signsrv"), "checkpdf", "-config", cfgPath, "-tsa", tsa.url, signed)
	evidence("checkpdf", out)
	if err != nil {
		return fmt.Errorf("checkpdf on the downloaded document: %v\n%s", err, out)
	}
	fmt.Printf("   checkpdf verified the downloaded document offline\n")
	return nil
}

// -------------------------------------------------------------- audit chain --

func auditChain() error {
	// The audit files are the offline copy of the trail, and the service does
	// not write them as it goes: `audit-write` appends the events newer than
	// the last written position. So the write comes first, then the verify.
	out, err := run(root, bin("signsrv"), "audit-write", "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("audit-write: %v\n%s", err, out)
	}
	evidence("audit-write", out)
	out, err = run(root, bin("signsrv"), "audit-verify", "-config", cfgPath)
	evidence("audit-verify", out)
	if err != nil {
		return fmt.Errorf("audit-verify: %v\n%s", err, out)
	}
	checkf(strings.Contains(string(out), "chain valid"), "audit-verify did not report a valid chain: %s", out)

	out, err = run(root, bin("signsrv"), "dbstatus", "-config", cfgPath)
	evidence("dbstatus", out)
	if err != nil {
		return fmt.Errorf("dbstatus: %v\n%s", err, out)
	}
	status := string(out)
	fmt.Printf("   counters:\n")
	for _, l := range strings.Split(strings.TrimSpace(status), "\n") {
		if strings.Contains(l, " : ") {
			fmt.Printf("     %s\n", strings.TrimSpace(l))
		}
	}
	checkf(counter(status, "parties") >= 2, "parties = %d, want 2", counter(status, "parties"))
	checkf(counter(status, "consented") >= 2, "consented = %d, want 2", counter(status, "consented"))
	checkf(counter(status, "consents") >= 2, "consents = %d, want 2", counter(status, "consents"))
	checkf(counter(status, "revisions") >= 3, "revisions = %d, want at least 3 (certified blank plus one per party)", counter(status, "revisions"))
	checkf(counter(status, "events") >= 6, "events = %d, want the full audit trail of this envelope", counter(status, "events"))
	checkf(counter(status, "revoked jtis") == 0, "revoked jtis = %d, want 0: nothing was revoked in this run", counter(status, "revoked jtis"))
	checkf(counter(status, "mail pending") == 0, "mail pending = %d, want 0: every invitation was delivered", counter(status, "mail pending"))

	// The chain check has to be able to fail, or it proves nothing. Tamper with
	// one byte of one audit file, expect a refusal, put the file back, expect
	// acceptance.
	path, b := pickAuditFile()
	if path == "" {
		return fmt.Errorf("no audit file in %s", filepath.Join(work, "audit"))
	}
	tampered := append([]byte{}, b...)
	at := len(tampered) / 2
	tampered[at] = tampered[at] ^ 0x20
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		return err
	}
	out, err = run(root, bin("signsrv"), "audit-verify", "-config", cfgPath)
	evidence("audit-verify-tampered", out)
	checkf(err != nil, "audit-verify accepted a tampered audit file (exit %v): %s", err, out)
	checkf(!bytes.Contains(out, []byte("chain valid")) || err != nil, "audit-verify printed a valid chain for tampered bytes")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	out, err = run(root, bin("signsrv"), "audit-verify", "-config", cfgPath)
	checkf(err == nil, "audit-verify failed again after the audit file was restored: %s", out)

	// The events table is append-only: nothing in this build updates or deletes
	// an event row, and the audit files carry the same trail in a form that
	// verifies without the database.
	out, err = run(root, bin("signsrv"), "audit-write", "-config", cfgPath, "e2e acceptance marker")
	if err == nil {
		out2, _ := run(root, bin("signsrv"), "audit-verify", "-config", cfgPath)
		checkf(bytes.Contains(out2, []byte("chain valid")), "the chain broke after appending an event: %s", out2)
	}

	// The audit zip is what an auditor takes away.
	req, err := http.NewRequest("GET", base+"/api/v1/envelopes/"+envID+"/audit.zip", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	zip, _ := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	res.Body.Close()
	checkf(res.StatusCode == http.StatusOK, "audit.zip gave %s", res.Status)
	checkf(len(zip) > 4 && string(zip[:2]) == "PK", "audit.zip is not a zip (%d bytes)", len(zip))
	if err := os.WriteFile(filepath.Join(work, "audit.zip"), zip, 0o644); err != nil {
		return err
	}
	evidence("audit-zip", []byte(fmt.Sprintf("audit.zip: %d bytes\n%s", len(zip), zipList(zip))))
	return nil
}

func zipList(zip []byte) string {
	out, err := run(work, "unzip", "-l", "audit.zip")
	if err != nil {
		return "(unzip not available; zip magic checked in Go)"
	}
	return string(out)
}

func pickAuditFile() (string, []byte) {
	entries, err := os.ReadDir(filepath.Join(work, "audit"))
	if err != nil {
		return "", nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		p := filepath.Join(work, "audit", e.Name())
		b, err := os.ReadFile(p)
		if err != nil || len(b) < 64 {
			continue
		}
		return p, b
	}
	return "", nil
}

func counter(out, label string) int {
	for _, l := range strings.Split(out, "\n") {
		i := strings.LastIndex(l, ":")
		if i < 0 {
			continue
		}
		if strings.TrimSpace(l[:i]) != label {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(l[i+1:]), "%d", &n); err == nil {
			return n
		}
	}
	return -1
}

// ------------------------------------------------------------ rate limits ---

func rateLimit() error {
	// The public signing read is the endpoint with no bearer token to hide
	// behind, so it is the one worth proving.
	var after int
	for i := 1; i <= 120; i++ {
		req, _ := http.NewRequest("GET", base+"/api/v1/sign/deadbeefdeadbeefdeadbeefdeadbeef/envelope", nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			evidence("rate-limit", []byte(fmt.Sprintf("429 after %d requests: %s", i, b)))
			after = i
			break
		}
	}
	checkf(after > 0 && after <= 120, "120 requests to one rate limited endpoint never produced a 429")
	if after > 0 {
		fmt.Printf("   429 received after %d requests\n", after)
	}

	// Scopes: the CLI key may write envelopes and must not read the admin
	// counters.
	clientAccess = clientTokenExchange()
	checkf(clientAccess != "", "the client key could not be exchanged for an access token")

	req, _ := http.NewRequest("GET", base+"/api/v1/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer "+clientAccess)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	res.Body.Close()
	checkf(res.StatusCode == http.StatusForbidden, "an envelope-scoped key read /admin/stats with %s: %s", res.Status, b)
	evidence("scoped-client-refused", []byte(res.Status+" "+string(b)))

	// A revoked key stops working immediately, at the next request.
	out, err := run(root, bin("signsrv"), "client", "list", "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("client list: %v\n%s", err, out)
	}
	id := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "e2e-cli") {
			if f := strings.Fields(l); len(f) > 0 {
				id = f[0]
			}
			break
		}
	}
	if id == "" {
		return fmt.Errorf("the e2e client is not in client list: %s", out)
	}
	// The revocation clock has one-second resolution, and a token minted in
	// the same second as the revocation is not yet provably older than it.
	// Wait, so this proves the rule instead of racing it.
	time.Sleep(1500 * time.Millisecond)
	out, err = run(root, bin("signsrv"), "client", "revoke", id, "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("client revoke: %v\n%s", err, out)
	}
	req, _ = http.NewRequest("GET", base+"/api/v1/envelopes/"+envID, nil)
	req.Header.Set("Authorization", "Bearer "+clientAccess)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	b, _ = io.ReadAll(io.LimitReader(res.Body, 1<<16))
	res.Body.Close()
	checkf(res.StatusCode == http.StatusUnauthorized, "a revoked client key still authenticated (%s): %s", res.Status, b)
	evidence("revoked-client", []byte(res.Status+" "+string(b)))
	fmt.Printf("   revoked key refused with %s\n", res.Status)
	return nil
}

// ------------------------------------------------------------- log hygiene --

func logRedaction() error {
	b, err := os.ReadFile(filepath.Join(work, "log", "signsrv.jsonl"))
	if err != nil {
		return fmt.Errorf("read the log: %v", err)
	}
	evidence("log", b)
	text := string(b)
	lines := strings.Split(strings.TrimSpace(text), "\n")
	fmt.Printf("   %d log line(s)\n", len(lines))

	secrets := map[string]string{
		"keystore passphrase": keystorePW,
		"admin password":      adminPass,
		"client key":          clientKey,
		"access token":        adminTok,
	}
	for name, value := range secrets {
		if value == "" {
			continue
		}
		checkf(!strings.Contains(text, value), "the %s appears verbatim in the log", name)
		if len(value) > 12 {
			checkf(!strings.Contains(text, value[:12]), "a 12-character prefix of the %s appears in the log", name)
		}
	}
	for _, l := range links {
		token := tokenOf(l)
		if token == "" {
			continue
		}
		checkf(!strings.Contains(text, token), "a signing link token appears in the log")
	}
	checkf(strings.Contains(text, `"request"`), "the log carries no request ids")
	if strings.Contains(text, "/api/v1/sign/") {
		for _, l := range lines {
			if strings.Contains(l, "/api/v1/sign/") && !strings.Contains(l, "[token]") {
				fmt.Printf("   UNREDACTED SIGNING PATH: %s\n", l)
				failed++
			}
		}
	}
	checkf(!strings.Contains(text, `"password"`), "the log carries a password field")
	checkf(!strings.Contains(text, `"authorization"`), "the log carries an authorization header")
	fmt.Printf("   no secret and no link token appears in the log\n")
	return nil
}

// ----------------------------------------------------------- graceful stop ----

func gracefulStop() error {
	if server == nil || server.Process == nil {
		return fmt.Errorf("the service is not running")
	}
	go func() {
		time.Sleep(400 * time.Millisecond)
		b, err := apiGet("/api/v1/envelopes/" + envID)
		if err != nil {
			fmt.Printf("   - the in-flight request failed: %v\n", err)
			return
		}
		fmt.Printf("   in-flight request answered with 200 (%d bytes)\n", len(b))
	}()
	if err := server.Process.Signal(syscall.SIGTERM); err != nil {

		return fmt.Errorf("SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("the service exited with an error after SIGTERM: %v", err)
		}
	case <-time.After(25 * time.Second):
		_ = server.Process.Kill()
		server = nil
		return fmt.Errorf("the service did not exit within 25s of SIGTERM")
	}
	server = nil
	res, err := http.Get(base + "/healthz")
	if err == nil {
		res.Body.Close()
		return fmt.Errorf("something still answers on %s after the service exited", base)
	}
	fmt.Printf("   the process exited cleanly on SIGTERM\n")
	return nil
}

// ------------------------------------------------------------ artefacts -----

// copyArtefacts keeps the things a reviewer can open: every revision the
// service wrote, the delivery mail, and the PDF taken out of the delivery
// attachment. The signed PDF inside the email is the copy the party actually
// receives, so it is verified on its own, and it has to be the document the
// envelope says it is.
func copyArtefacts() error {
	out := filepath.Join(work, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	// The revisions, in the order they were written: template, filled,
	// certified, then one per party.
	req, _ := http.NewRequest("GET", base+"/api/v1/envelopes/"+envID, nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<22))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("read the envelope for artefacts: %s", res.Status)
	}
	var view struct {
		DocumentSHA string `json:"document_sha"`
		Revisions   []struct {
			Kind      string `json:"kind"`
			SHA256    string `json:"sha256"`
			CreatedAt string `json:"created_at"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		return fmt.Errorf("decode envelope for artefacts: %v", err)
	}
	for i, rev := range view.Revisions {
		src := filepath.Join(work, "storage", rev.SHA256+".pdf")
		dst := filepath.Join(out, fmt.Sprintf("%03d-%s-%s.pdf", i+1, rev.Kind, short(rev.SHA256)))
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	fmt.Printf("   %d revisions copied for review\n", len(view.Revisions))

	// The signed attachment, taken out of the mail the service wrote.
	names, err := filepath.Glob(filepath.Join(work, "outbox", "signed-*.eml"))
	if err != nil || len(names) == 0 {
		return fmt.Errorf("no signed delivery in the outbox")
	}
	attachment, err := pdfFromEML(names[0])
	if err != nil {
		return err
	}
	signedFromMail := filepath.Join(out, "900-signed-from-email.pdf")
	if err := os.WriteFile(signedFromMail, attachment, 0o644); err != nil {
		return err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(attachment))
	checkf(sum == view.DocumentSHA,
		"the PDF attached to the delivery mail is %s, the envelope says the current document is %s",
		short(sum), short(view.DocumentSHA))

	out2, err := run(root, bin("signsrv"), "checkpdf", "-config", cfgPath, "-tsa", tsa.url, signedFromMail)
	evidence("checkpdf-from-email", out2)
	if err != nil {
		return fmt.Errorf("checkpdf on the PDF attached to the delivery mail: %v\n%s", err, out2)
	}
	// The mail itself is part of the evidence: it is what the party was sent.
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "900-"+filepath.Base(n)), b, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("   the PDF attached to the delivery mail verifies on its own\n")
	return nil
}

// pdfFromEML returns the PDF attachment of a .eml file written by the dev
// mailer. The dev outbox is the delivery path minus SMTP, so what is in the
// file is what the party's mailbox would hold.
func pdfFromEML(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	msg, err := mail.ReadMessage(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", filepath.Base(path), err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("%s: content type: %v", filepath.Base(path), err)
	}
	if !strings.HasPrefix(mt, "multipart/") {
		return nil, fmt.Errorf("%s is not multipart", filepath.Base(path))
	}
	reader := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %v", filepath.Base(path), err)
		}
		if !strings.HasPrefix(part.Header.Get("Content-Type"), "application/pdf") {
			part.Close()
			continue
		}
		// The dev mailer writes base64, as an attachment over SMTP requires.
		// Reading the part raw would hand back the base64 text, which is not
		// a PDF and would fail the check for the wrong reason.
		var r io.Reader = part
		if strings.EqualFold(part.Header.Get("Content-Transfer-Encoding"), "base64") {
			r = base64.NewDecoder(base64.StdEncoding, part)
		}
		b, err := io.ReadAll(io.LimitReader(r, 32<<20))
		part.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: pdf part: %v", filepath.Base(path), err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s carries no PDF attachment", filepath.Base(path))
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)

	if err != nil {
		return fmt.Errorf("copy %s: %v", src, err)
	}
	return os.WriteFile(dst, b, 0o644)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
