//go:build e2e

// The negative set. Every rule the service claims is one of these: a thing the
// service is supposed to refuse, and refuse in a way the party can see. Each
// check asserts a state, not only a status code, because a 400 that leaves the
// party halfway through a consent proves nothing.
//
// The set runs on envelopes of its own. The main envelope, the one the browser
// signs, is the artefact a reviewer opens, so nothing in this file touches it.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// negatives runs the negative set as one phase of the acceptance run. Every
// check runs even after one has failed, because the point is the list of what
// broke, not the first break.
func negatives() error {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"duplicate consent", negDuplicateConsent},
		{"expired link", negExpiredLink},
		{"cancel closes a request", negCancel},
		{"consent rules", negConsentRules},
		{"non-PDF upload", negNonPDF},
		{"consent limit is per envelope", negConsentLimit},
		{"login limit", negLoginLimit},
		{"link limit", negLinkLimit},
		{"caller-minted tokens", negCallerMintedTokens},
	}
	var broken []string
	for _, c := range checks {
		if err := c.fn(); err != nil {
			fmt.Printf("   NEG FAIL %s: %v\n", c.name, err)
			broken = append(broken, c.name)
			continue
		}
		fmt.Printf("   neg ok: %s\n", c.name)
	}
	if len(broken) > 0 {
		return fmt.Errorf("%d negative check(s) failed: %s", len(broken), strings.Join(broken, ", "))
	}
	// The refusals must not have damaged the record. The chain covers every
	// envelope this file created, because each of them wrote events.
	// The chain is written on a cadence, not per event, so the file trails the
	// database. Flush first: verifying the log against 18 events while the
	// table holds hundreds would report a gap that is only the unwritten tail.
	if out, err := run(root, bin("signsrv"), "audit-write", "-config", cfgPath); err != nil {
		return fmt.Errorf("audit write before the negative set's chain check: %v\n%s", err, out)
	}
	out, err := run(root, bin("signsrv"), "audit-verify", "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("audit chain after the negative set: %v\n%s", err, out)
	}
	fmt.Printf("   chain after the negative set: %s", firstLine(out))
	return nil
}

// ------------------------------------------------------------- duplicate -----

// negDuplicateConsent: a party consents, then replays the same consent. The
// replay is refused, the envelope keeps collecting, and the other party can
// still sign. A refusal that stranded a request would be worse than no refusal.
func negDuplicateConsent() error {
	negUseAddr(1)
	id, links, err := negCreate("Negatives: duplicate consent", "", 2)
	if err != nil {
		return err
	}
	a, b2 := links[0], links[1]
	if err := negClaimAgain(&a); err != nil {
		return err
	}
	// A valid consent names the digest of the document the party was shown:
	// the service compares it with the stored revision and refuses a consent
	// that does not match. So the digest has to be read from the envelope
	// before the consent can be written at all.
	sha := negEnvelope(id).documentSHA
	if sha == "" {
		return fmt.Errorf("no document digest on a ready request")
	}
	body := `{"signature_text":"First A","consent":true,"document_sha":"` + sha + `"}`

	code, b := negSign(a, body)
	if code != 200 {
		return fmt.Errorf("the first consent failed: %d %s", code, b)
	}
	st := negEnvelope(id)
	if st.status != "collecting" {
		return fmt.Errorf("envelope after one consent: want collecting, got %s", st.status)
	}
	if st.partyStatus[a.email] != "consented" {
		return fmt.Errorf("party after a consent: want consented, got %s", st.partyStatus[a.email])
	}

	// The replay. A consent consumes the session that minted it, and a
	// consented party is closed. So a replay has two doors and both are shut:
	// the party cannot claim again (409 — it may not reopen a session), and
	// the consent with the spent cookie is refused (401 — the session is
	// gone). Asserting only the second would pass on a service that let the
	// party re-claim.
	if code, b = negSelf().call("POST", "/api/v1/sign/"+a.token+"/claim", `{"email":"`+a.email+`"}`); code != 409 {
		return fmt.Errorf("claim by a party that has consented: want 409, got %d: %s", code, b)
	}
	evidence("neg-duplicate-consent-claim", b)
	code, b = negSign(a, body)
	if code != 409 {
		return fmt.Errorf("replayed consent: want 409, got %d: %s", code, b)
	}
	// The consent endpoint asks the party's state before it asks the session,
	// so the replay is refused as a closed party (409) and not as an
	// unauthenticated caller. The same body with no session at all is refused
	// as an unauthenticated caller (401), which is what shows the 409 above is
	// a rule about the party and not an artefact of a stale cookie.
	if code, b = negSelf().consent(a.token, "", body); code != 401 {
		return fmt.Errorf("consent with no session: want 401, got %d: %s", code, b)
	}
	evidence("neg-duplicate-consent", b)
	st = negEnvelope(id)
	if st.partyStatus[a.email] != "consented" {
		return fmt.Errorf("the replay moved the party to %s", st.partyStatus[a.email])
	}
	if n := negCount(st, "consented"); n != 1 {
		return fmt.Errorf("consented parties after the replay: want 1, got %d", n)
	}

	// The remaining party signs, and the request still completes. The refused
	// replay left the request open, which is the whole point: a refusal that
	// closed the request would be a denial of service against the signer.
	if err := negClaimAgain(&b2); err != nil {
		return err
	}
	if code, b = negSign(b2, `{"signature_text":"Second B","consent":true,"document_sha":"`+sha+`"}`); code != 200 {
		return fmt.Errorf("the second party could not sign after a refused replay: %d %s", code, b)
	}
	// The completion is watched for, not waited on for one status: the batch
	// signs and delivers in one run, so the request can pass through signed
	// into delivered faster than one poll interval. Delivered is the proof
	// the run wants — a signed PDF that reached the parties.
	if err := negWaitReached(id, []string{"signed", "delivered"}, 90*time.Second); err != nil {
		return err
	}
	fmt.Printf("   duplicate consent refused with 409; the request still reached signed\n")
	return nil
}

// --------------------------------------------------------------- expiry ------

// negExpiredLink: a link whose deadline has already passed. The deadline is set
// to one nanosecond at create time, so the link is dead the moment it exists
// instead of waiting out a 30-day window. The view, the claim and the consent
// all answer 410, and no consent is recorded.
func negExpiredLink() error {
	negUseAddr(2)
	id, links, err := negCreate("Negatives: expired link", "1ns", 1)
	if err != nil {
		return err
	}
	a := links[0]
	code, b, _ := negRaw("GET", "/api/v1/sign/"+a.token+"/envelope", "", "")
	if code != 410 {
		return fmt.Errorf("envelope view of an expired link: want 410, got %d: %s", code, b)
	}
	evidence("neg-expired-link", b)
	if !strings.Contains(string(b), "expired") {
		return fmt.Errorf("the expired link answer does not say the link expired: %s", b)
	}
	if code, b, _ = negRaw("POST", "/api/v1/sign/"+a.token+"/claim", `{"email":"`+a.email+`"}`, ""); code != 410 {
		return fmt.Errorf("claim on an expired link: want 410, got %d: %s", code, b)
	}
	code, b = negSign(a, `{"signature_text":"Too Late","consent":true}`)
	if code != 410 {
		return fmt.Errorf("consent on an expired link: want 410, got %d: %s", code, b)
	}
	if st := negEnvelope(id); st.partyStatus[a.email] == "consented" {
		return fmt.Errorf("a consent was recorded on an expired link")
	}
	fmt.Printf("   expired link: view, claim and consent all answer 410\n")
	return nil
}

// ------------------------------------------------------------- cancel --------

// negCancel: a cancel needs a reason, and a blank one changes nothing. A
// cancelled request is closed: no remind, no signing, and the status stays
// cancelled.
func negCancel() error {
	negUseAddr(3)
	id, links, err := negCreate("Negatives: cancel", "", 1)
	if err != nil {
		return err
	}
	code, b := negAdmin("POST", "/api/v1/envelopes/"+id+"/cancel", `{"reason":"   "}`)
	if code != 422 {
		return fmt.Errorf("cancel with a blank reason: want 422, got %d: %s", code, b)
	}
	evidence("neg-cancel-blank", b)
	if st := negEnvelope(id); st.status != "sent" {
		return fmt.Errorf("envelope after a refused cancel: want sent, got %s", st.status)
	}
	code, b = negAdmin("POST", "/api/v1/envelopes/"+id+"/cancel", `{"reason":"the run withdrew this document"}`)
	if code != 200 {
		return fmt.Errorf("cancel with a reason: want 200, got %d: %s", code, b)
	}
	st := negEnvelope(id)
	if st.status != "cancelled" {
		return fmt.Errorf("cancelled envelope: want cancelled, got %s", st.status)
	}
	if code, b = negAdmin("POST", "/api/v1/envelopes/"+id+"/remind", `{}`); code == 200 {
		return fmt.Errorf("a remind on a cancelled request was accepted")
	}
	evidence("neg-remind-closed", b)
	if st2 := negEnvelope(id); st2.status != "cancelled" {
		return fmt.Errorf("a refused remind changed the envelope to %s", st2.status)
	}
	a := links[0]
	if err := negClaimAgain(&a); err == nil {
		// The claim should not have worked at all: a closed request has no
		// open party to claim.
		return fmt.Errorf("a party claimed a link on a cancelled request")
	}
	if code, b = negSign(a, `{"signature_text":"Late","consent":true}`); code == 200 {
		return fmt.Errorf("a party signed a cancelled request")
	}
	if code != 410 && code != 409 {
		return fmt.Errorf("consent on a cancelled request: want 409 or 410, got %d: %s", code, b)
	}
	evidence("neg-consent-cancelled", b)
	fmt.Printf("   cancel: reason required, a closed request stays closed\n")
	return nil
}

// -------------------------------------------------------- consent rules ------

// negConsentRules: the payload rules of the consent, through the API. Every one
// is refused, and after all of them the request is still ready and the party is
// still invited: a refused consent must not spend the party. The consent is
// also the one action a party may not describe for itself, so the set includes
// the fields that would let it: a field rectangle, a key, a TSA url.
func negConsentRules() error {
	negUseAddr(4)
	// The consent bucket is ten a minute **per envelope** (it is keyed on the
	// envelope and not on the address, which is the point of negConsentLimit
	// below). The set is longer than ten cases, so it runs against more than
	// one request: each group gets a fresh envelope and every rule is
	// reached. A bucket that swallowed the tail of the set would let the
	// check pass while testing nothing.
	cases := []struct {
		name string
		body func(sha string) string
		want int
	}{
		{"consent absent", func(string) string {
			return `{"signature_text":"Neg One"}`
		}, 400},
		{"consent false", func(string) string {
			return `{"signature_text":"Neg One","consent":false}`
		}, 400},
		{"blank signature", func(string) string {
			return `{"signature_text":"   ","consent":true}`
		}, 400},
		{"signature over 120 characters", func(string) string {
			return `{"signature_text":"` + strings.Repeat("s", 121) + `","consent":true}`
		}, 400},
		{"signature with a control character", func(string) string {
			return `{"signature_text":"Neg\u0001One","consent":true}`
		}, 400},
		{"wrong document digest", func(string) string {
			return `{"signature_text":"Neg One","consent":true,"document_sha":"deadbeef"}`
		}, 409},
		{"document digest absent", func(string) string {
			return `{"signature_text":"Neg One","consent":true}`
		}, 409},
		{"unknown consent field", func(string) string {
			return `{"signature_text":"Neg One","consent":true,"signed_at":"2020-01-01T00:00:00Z"}`
		}, 400},
		{"consent carries a field rectangle", func(string) string {
			return `{"signature_text":"Neg One","consent":true,"field":"Signature1"}`
		}, 400},
		{"consent carries a key id", func(string) string {
			return `{"signature_text":"Neg One","consent":true,"key_id":"1"}`
		}, 400},
		{"consent carries a TSA url", func(string) string {
			return `{"signature_text":"Neg One","consent":true,"tsa_url":"http://x"}`
		}, 400},
		{"consent carries an order", func(string) string {
			return `{"signature_text":"Neg One","consent":true,"order":1}`
		}, 400},
		{"image is not base64", func(sha string) string {
			return `{"signature_text":"Neg One","consent":true,"document_sha":"` + sha + `","image":"not base64!!"}`
		}, 400},
		{"image is over 512 KB", func(sha string) string {
			return `{"signature_text":"Neg One","consent":true,"document_sha":"` + sha + `","image":"` + strings.Repeat("A", 700_000) + `"}`
		}, 400},
		// The image is sniffed, not taken from its label: a PNG body under a
		// jpeg label is accepted, so a case built that way proves nothing. What
		// the service refuses is a body that is neither format, whatever the
		// label claims — here a GIF body labelled jpeg.
		{"an image that is neither PNG nor JPEG", func(sha string) string {
			return `{"signature_text":"Neg One","consent":true,"document_sha":"` + sha +
				`","image":"data:image/jpeg;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"}`
		}, 400},
	}
	const perEnvelope = 8
	ran := 0
	for from := 0; from < len(cases); from += perEnvelope {
		stop := from + perEnvelope
		if stop > len(cases) {
			stop = len(cases)
		}
		id, links, err := negCreate("Negatives: consent rules", "", 1)
		if err != nil {
			return err
		}
		a := links[0]
		if err := negClaimAgain(&a); err != nil {
			return err
		}
		// A consent names the digest of the document the party was shown: the
		// service compares it with the stored revision, so the digest has to be
		// read before a case can name a wrong one on purpose.
		sha := negEnvelope(id).documentSHA
		if sha == "" {
			return fmt.Errorf("no document digest on a ready request")
		}
		for _, c := range cases[from:stop] {
			code, b := negSign(a, c.body(sha))
			if code == 429 {
				return fmt.Errorf("%s: the consent limit tripped before this case ran", c.name)
			}
			if code != c.want {
				return fmt.Errorf("%s: want %d, got %d: %s", c.name, c.want, code, b)
			}
			evidence("neg-consent-"+strings.ReplaceAll(c.name, " ", "-"), b)
			ran++
		}
		st := negEnvelope(id)
		if st.status != "sent" {
			return fmt.Errorf("request after %d refused consents: want sent, got %s", stop-from, st.status)
		}
		if s := st.partyStatus[a.email]; s != "claimed" && s != "invited" {
			return fmt.Errorf("a refused consent spent the party: %s", s)
		}
	}
	fmt.Printf("   consent rules: %d refusals, every request stayed ready and every party stayed open\n", ran)
	return nil
}

// negConsentLimit: the consent bucket is keyed on the envelope, not on the
// address. A party cannot escape it by coming from a different machine, which
// is the property that matters for an action that is irreversible.
// negNonPDF: the template must be a PDF, and the check is on the bytes, not the
// name. The upload is a PNG named template.pdf; the refusal names the field, and
// no request is created, so nothing is left half-built in storage.
func negNonPDF() error {
	negUseAddr(5)
	// A PNG body, in a file called .pdf. The create endpoint reads the first
	// bytes and refuses.
	png, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range [][2]string{{"title", "Negatives: not a PDF"},
		{"spec", `{"fill":{"values":{"Text1":"x"}}}`},
		{"parties", `[{"email":"neg1@e2e.test","name":"Neg 1","order":1}]`}} {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return err
		}
	}
	part, err := mw.CreateFormFile("template", "template.pdf")
	if err != nil {
		return err
	}
	part.Write(png)
	mw.Close()

	req, _ := http.NewRequest("POST", base+"/api/v1/envelopes", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+clientAccess)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode == 201 {
		return fmt.Errorf("a PNG uploaded as template.pdf was accepted as a template")
	}
	evidence("neg-not-pdf", body)
	if res.StatusCode != 400 {
		return fmt.Errorf("non-PDF template: want 400, got %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "template") {
		return fmt.Errorf("the non-PDF refusal does not name the template field: %s", body)
	}
	// Nothing was created. The refusal has to leave no half-built request: the
	// title of this upload appears in no row.
	code, b, _ := negRawWithAuth("GET", "/api/v1/envelopes?limit=100", "", "", adminTok)
	if code != 200 {
		return fmt.Errorf("envelope list after a refused upload: %d: %s", code, b)
	}
	if strings.Contains(string(b), "Negatives: not a PDF") {
		return fmt.Errorf("the refused upload left a request in the list")
	}
	fmt.Printf("   non-PDF upload refused with 400, naming the field\n")
	return nil
}

func negConsentLimit() error {
	negUseAddr(6)
	id, links, err := negCreate("Negatives: consent limit", "", 1)
	if err != nil {
		return err
	}
	a := links[0]
	if err := negClaimAgain(&a); err != nil {
		return err
	}
	var codes []int
	for i := 0; i < 11; i++ {
		c := negLimited(fmt.Sprintf("127.0.0.%d", 30+i))
		if err := negClaimWith(c, &a); err != nil {
			return err
		}
		code, _ := c.consent(a.token, a.cookie, `{"signature_text":"Too many","consent":true}`)
		codes = append(codes, code)
		if code == 429 {
			break
		}
	}
	if codes[len(codes)-1] != 429 {
		return fmt.Errorf("11 consents on one envelope from 11 addresses: no 429 (%v)", codes)
	}
	if st := negEnvelope(id); st.partyStatus[a.email] == "consented" {
		return fmt.Errorf("a refused consent still marked the party as consented")
	}
	fmt.Printf("   consent limit: the %dth consent on one envelope is a 429 whatever the address\n", len(codes))
	return nil
}

// ------------------------------------------------------------- limits --------

// negLoginLimit: five login attempts per minute per source address. The sixth
// from an address this run has not used is a 429 with a Retry-After. The address
// is changed by dialing from it, not by claiming it in a header: the service
// reads X-Forwarded-For only when trust_proxy is on, and here it is off, which
// is the honest way to be a new client.
func negLoginLimit() error {
	c := negLimited("127.0.0.21")
	var code int
	var body []byte
	for i := 0; i < 6; i++ {
		code, body = c.call("POST", "/api/v1/auth/login", `{"email":"nobody@e2e.test","password":"wrong"}`)
		if code == 429 {
			break
		}
	}
	if code != 429 {
		return fmt.Errorf("sixth login from a fresh address: want 429, got %d: %s", code, body)
	}
	evidence("neg-login-limit", body)
	fmt.Printf("   login limit: the 6th attempt from an address is a 429\n")
	return nil
}

// negLinkLimit: sixty link reads per minute per source address, which is what a
// forwarded link saturates.
func negLinkLimit() error {
	negUseAddr(8)
	id, links, err := negCreate("Negatives: link limit", "", 1)
	if err != nil {
		return err
	}
	c := negLimited("127.0.0.22")
	var code int
	for i := 0; i < 61; i++ {
		code, _ = c.call("GET", "/api/v1/sign/"+links[0].token+"/envelope", "")
		if code == 429 {
			break
		}
	}
	if code != 429 {
		return fmt.Errorf("61st link read from a fresh address: want 429, got %d", code)
	}
	if st := negEnvelope(id); st.status != "sent" {
		return fmt.Errorf("request after the limit tripped: want sent, got %s", st.status)
	}
	fmt.Printf("   link limit: the 61st read from an address is a 429\n")
	return nil
}

// ------------------------------------------------------------- plumbing ------

type negLink struct {
	email  string
	token  string
	cookie string
}

type negState struct {
	status      string
	documentSHA string
	partyStatus map[string]string
}

// negCreate builds a small request through the API: a template, a spec, and N
// parties. expires_in goes straight to the create endpoint, so a check can ask
// for a link that is already dead. The links are returned unclaimed: a claim is
// itself a rule, so each check performs it and can assert on it.
func negCreate(title, expiresIn string, parties int) (string, []negLink, error) {
	file, err := os.ReadFile(filepath.Join(root, "testdata", "sample2.pdf"))
	if err != nil {
		return "", nil, err
	}
	spec := `{"fill":{"values":{"Text1":"Negatives","Text2":"2026-11-06","Text3":"0","Text4":"n/a","Text5":"acceptance","Text6":"negative set"}}}`
	arr := make([]map[string]any, 0, parties)
	for i := 1; i <= parties; i++ {
		arr = append(arr, map[string]any{
			"email": fmt.Sprintf("neg%d@e2e.test", i), "name": fmt.Sprintf("Neg %d", i), "order": i,
		})
	}
	pb, _ := json.Marshal(arr)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range [][2]string{{"title", title}, {"spec", spec}, {"parties", string(pb)}, {"expires_in", expiresIn}} {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return "", nil, err
		}
	}
	part, err := mw.CreateFormFile("template", "template.pdf")
	if err != nil {
		return "", nil, err
	}
	if _, err := part.Write(file); err != nil {
		return "", nil, err
	}
	mw.Close()

	req, _ := http.NewRequest("POST", base+"/api/v1/envelopes", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+clientAccess)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 201 {
		return "", nil, fmt.Errorf("negative create %q: %s: %s", title, res.Status, body)
	}
	var out struct {
		Envelope struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"envelope"`
		Links []linkRec `json:"links"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", nil, fmt.Errorf("decode negative create: %v: %s", err, body)
	}
	if out.Envelope.ID == "" || len(out.Links) != parties {
		return "", nil, fmt.Errorf("negative create returned id %q and %d link(s)", out.Envelope.ID, len(out.Links))
	}
	if out.Envelope.Status != "ready" {
		return out.Envelope.ID, nil, fmt.Errorf("negative create %q: status %q, want ready", title, out.Envelope.Status)
	}
	// Create leaves the request **ready**, and that is the gate: a party may
	// not act on a request that has not been sent. Create mints the link
	// tokens, and Send reuses them — the plaintext is on the party row, so the
	// create's token and the send's are the same string in any process, before
	// or after a restart. The links handed back are the send's, because a
	// request being acted on in these checks has been sent. The send rides the same client key
	// the create did: sending is an envelope write, not an admin action.
	//
	// A request created with a deadline is the exception. The expired-link
	// check makes a link that is dead the instant it exists; that request is
	// left unsent, and the check reads the view, claim and consent of the
	// token the create returned — all three of which answer 410.
	if expiresIn == "" {
		code, b, _ := negRawWithAuth("POST", "/api/v1/envelopes/"+out.Envelope.ID+"/send", "", "", clientAccess)
		if code != http.StatusOK {
			return "", nil, fmt.Errorf("negative send %q: %d %s", title, code, b)
		}
		var sent struct {
			Links []linkRec `json:"links"`
		}
		if err := json.Unmarshal(b, &sent); err != nil {
			return "", nil, fmt.Errorf("decode negative send %q: %v", title, err)
		}
		if len(sent.Links) != parties {
			return "", nil, fmt.Errorf("negative send %q returned %d link(s), want %d", title, len(sent.Links), parties)
		}
		out.Links = sent.Links
	}

	links := make([]negLink, 0, len(out.Links))
	for _, l := range out.Links {
		links = append(links, negLink{email: l.Email, token: l.Token})
	}
	return out.Envelope.ID, links, nil
}

// negClaimAgain claims a link and stores the session cookie it mints. The
// consent sends that cookie by hand, so a check can withhold it.
func negClaimAgain(l *negLink) error {
	return negClaimWith(negSelf(), l)
}

func negClaimWith(c *negClient, l *negLink) error {
	code, b, cookies := c.raw("POST", "/api/v1/sign/"+l.token+"/claim", `{"email":"`+l.email+`"}`)
	if code != 200 {
		return fmt.Errorf("claim %s: %d %s", l.email, code, b)
	}
	if len(cookies) == 0 {
		return fmt.Errorf("the claim of %s set no session cookie", l.email)
	}
	l.cookie = cookies[len(cookies)-1]
	return nil
}

// negSign posts a consent as a party, sending the party's session cookie.
func negSign(l negLink, body string) (int, []byte) {
	code, b, _ := negRawWithAuth("POST", "/api/v1/sign/"+l.token+"/consent", body, l.cookie, "")
	return code, b
}

// negAdmin is an admin API call with the admin token.
func negAdmin(method, path, body string) (int, []byte) {
	code, b, _ := negRawWithAuth(method, path, body, "", adminTok)
	return code, b
}

func negRaw(method, path, body, cookie string) (int, []byte, []string) {
	return negRawWithAuth(method, path, body, cookie, "")
}

// negRawWithAuth is the plain HTTP path of the negative set. It returns the
// Set-Cookie values it saw, which is how a session cookie reaches a consent.
func negRawWithAuth(method, path, body, cookie, auth string) (int, []byte, []string) {
	return negSelf().rawFull(method, path, body, cookie, auth)
}

// negEnvelope reads the status, the document digest, and each party's status
// from the admin API.
func negEnvelope(id string) negState {
	st := negState{partyStatus: map[string]string{}}
	code, b, _ := negRawWithAuth("GET", "/api/v1/envelopes/"+id, "", "", adminTok)
	if code != 200 {
		st.status = fmt.Sprintf("read failed %d", code)
		return st
	}
	var out struct {
		Status      string `json:"status"`
		DocumentSHA string `json:"document_sha"`
		Parties     []struct {
			Email  string `json:"email"`
			Status string `json:"status"`
		} `json:"parties"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		st.status = "decode failed"
		return st
	}
	st.status = out.Status
	st.documentSHA = out.DocumentSHA
	for _, p := range out.Parties {
		st.partyStatus[p.Email] = p.Status
	}
	return st
}

func negCount(st negState, want string) int {
	n := 0
	for _, s := range st.partyStatus {
		if s == want {
			n++
		}
	}
	return n
}

// negWaitStatus polls the request until it reaches a status. The signing is a
// queued job, so a signed request appears a moment after the last consent.
func negWaitStatus(id, want string, timeout time.Duration) error {
	return negWaitReached(id, []string{want}, timeout)
}

// negWaitReached polls until the request carries one of the named statuses.
// Several are needed when the status is a step on the way to another: signing
// and delivery happen in one batch run, so a request can be past "signed" the
// first time it is read.
func negWaitReached(id string, want []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		st := negEnvelope(id)
		last = st.status
		for _, w := range want {
			if last == w {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("request %s never reached %v (last: %s)", id, want, last)
}

// negClient is an HTTP client that dials from a loopback address of its own. It
// is the only way to be a new client here: the service keys its limits on the
// peer address of the connection and ignores X-Forwarded-For unless trust_proxy
// is on, and in this run trust_proxy is off.
type negClient struct{ c *http.Client }

// negAddr is the source address the shared helpers dial from, and negSelf is
// the client for it. Each check sets negAddr to a loopback address of its own
// before it starts.
//
// The service keys its limits on the peer address of the connection, and the
// claim budget is ten a minute. Every check here claims — negCreate claims each
// party's link, and a replay test claims again — so checks that all speak from
// 127.0.0.1 spend one budget together, and the eleventh claim of the run is a
// 429 that says nothing about the rule the check was testing. 127.0.0.0/8 is
// entirely local, so a distinct address per check is free.
var negAddr = "127.0.0.1"

func negSelf() *negClient { return negLimited(negAddr) }

// negUseAddr gives the calling check its own address and returns a client for
// it. The index is the check's position in the file, so two checks never share
// an address.
func negUseAddr(i int) *negClient {
	negAddr = fmt.Sprintf("127.0.0.%d", 50+i)
	return negSelf()
}

func negLimited(ip string) *negClient {
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}}
	return &negClient{c: &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

func (n *negClient) call(method, path, body string) (int, []byte) {
	code, b, _ := n.rawFull(method, path, body, "", "")
	return code, b
}

func (n *negClient) consent(token, cookie, body string) (int, []byte) {
	code, b, _ := n.rawFull("POST", "/api/v1/sign/"+token+"/consent", body, cookie, "")
	return code, b
}

func (n *negClient) raw(method, path, body string) (int, []byte, []string) {
	return n.rawFull(method, path, body, "", "")
}

func (n *negClient) rawFull(method, path, body, cookie, auth string) (int, []byte, []string) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, r)
	if err != nil {
		return 0, nil, nil
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	res, err := n.c.Do(req)
	if err != nil {
		return 0, []byte(err.Error()), nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	cs := res.Cookies()
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name+"="+c.Value)
	}
	return res.StatusCode, b, names
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "\n"
	}
	return s + "\n"
}
