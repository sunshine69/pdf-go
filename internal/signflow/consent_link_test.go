package signflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signstore"
)

// The link token's life, and the consent image's label. These facts decide
// whether a test that signs a link is testing a delivered link at all, so they
// are pinned here rather than left to be inferred from send.go.
//
//	who mints the token       Create, for every party.
//	who can reuse it          Send, while the plaintext is still in this
//	                          process's memory (rawTokens); a process that
//	                          restarted mints a fresh token and re-hashes it.
//	                          Re-sending invalidates the old token.
//	when may a party act      only once the request is sent. The link exists at
//	                          create; the gate is the status.
//	the image's type          comes from the bytes, never from the label in the
//	                          data URL. The label is not consulted, so it
//	                          cannot name a file the way the client claims.

// linkFixture is one CREATED request, not sent: the state a request sits in
// between the create call and the dispatch.
type linkFixture struct {
	t     *testing.T
	deps  *Deps
	env   *signstore.Envelope
	token string // the plaintext link create returned
	party string // party id
	dsha  string
}

func newLinkFixture(t *testing.T) *linkFixture {
	t.Helper()
	d := newDeps(t)
	ctx := context.Background()
	created, err := d.Create(ctx, CreateRequest{
		Template:  sampleBytes(t),
		Fill:      fillSpecFor(t, sampleBytes(t)),
		Parties:   parties(1),
		Title:     "Link token unit test",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	env, err := d.Store.GetEnvelope(ctx, created.Envelope.ID)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if len(created.Links) != 1 {
		t.Fatalf("create returned %d links, want 1", len(created.Links))
	}
	return &linkFixture{
		t: t, deps: d, env: env,
		token: created.Links[0].Token,
		party: created.Links[0].PartyID,
		dsha:  env.CurrentSHA,
	}
}

// TestCreateMintsTheLinkToken pins the first fact: the create response carries
// a real, working token for every party. The ledger claim this corrects is that
// create's tokens are placeholders and send is what mints them.
func TestCreateMintsTheLinkToken(t *testing.T) {
	f := newLinkFixture(t)
	ctx := context.Background()
	created, err := f.deps.Create(ctx, CreateRequest{
		Template:  sampleBytes(t),
		Fill:      fillSpecFor(t, sampleBytes(t)),
		Parties:   parties(2),
		Title:     "Two parties",
		ExpiresIn: 48 * time.Hour,
		Actor:     "api:test",
		LinkBase:  "http://127.0.0.1:8090",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(created.Links) != 2 {
		t.Fatalf("links: %d want 2", len(created.Links))
	}
	seen := map[string]bool{}
	for _, l := range created.Links {
		if len(l.Token) < 32 {
			t.Fatalf("create returned a short token for %s: %q", l.Email, l.Token)
		}
		if seen[l.Token] {
			t.Fatalf("two parties share the token %q", l.Token)
		}
		seen[l.Token] = true
		if l.URL == "" || !strings.HasSuffix(l.URL, l.Token) {
			t.Fatalf("link url %q does not end with its token", l.URL)
		}
	}
	// The create's token resolves immediately: the link is real at create.
	// A party cannot ACT yet, and the next test pins that.
	p, err := LookupLink(ctx, f.deps.Store, created.Links[0].Token, time.Now())
	if err != nil {
		t.Fatalf("lookup of a created-but-unsent token: %v", err)
	}
	if p.Email != created.Links[0].Email {
		t.Fatalf("lookup resolved to %s, want %s", p.Email, created.Links[0].Email)
	}
}

// TestPartyCannotActOnAnUnsentRequest is the gate that stands in place of the
// "the tokens are placeholders" claim: an unsent request resolves its link,
// shows its page, and refuses to be signed.
func TestPartyCannotActOnAnUnsentRequest(t *testing.T) {
	f := newLinkFixture(t)
	ctx := context.Background()
	if tok := RawToken(f.party); tok != f.token {
		t.Fatalf("the create's plaintext is not the one in hand: %q vs %q", tok, f.token)
	}
	if f.env.Status != Ready {
		t.Fatalf("a created request is %s; this test is about a ready one", f.env.Status)
	}
	sg, err := ResolveSigner(ctx, f.deps.Store, f.token, time.Now())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The view a stranger gets from the link alone. Holding the link buys the
	// title and the deadline only: no status, no digest, no slot, no list.
	view, err := SignerViewFor(ctx, f.deps.Store, sg, false, time.Now())
	if err != nil {
		t.Fatalf("signer view on a ready request: %v", err)
	}
	if view.Status != "" || view.DocumentSHA != "" || view.My != nil || len(view.Parties) != 0 {
		t.Fatalf("an unclaimed view reveals state: %+v", view)
	}
	if view.Title != f.env.Title || view.ExpiresAt != f.env.ExpiresAt {
		t.Fatalf("an unclaimed view lost the title and deadline: %+v", view)
	}
	// Signing is what is refused, and it is the status that refuses: the
	// document is certified, the digest matches, the checkbox is ticked.
	if _, err := f.deps.Consent(ctx, f.token, ConsentInput{
		SignatureText: "Steve Kieu",
		Consent:       true,
		DocumentSHA:   f.dsha,
		IP:            "127.0.0.1",
		UserAgent:     "unit-test",
	}, time.Now()); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("consent on a ready request: %v, want %v", err, ErrStateConflict)
	}
}

// TestSendReusesTheTokenOfARunningProcess is the second fact, and the reason
// the create response's token is the one that ships in a dev run.
func TestSendReusesTheTokenOfARunningProcess(t *testing.T) {
	f := newLinkFixture(t)
	ctx := context.Background()
	links, err := f.deps.Send(ctx, f.env.ID, "api:test", time.Now())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("links: %d want 1", len(links))
	}
	if links[0].Token != f.token {
		t.Fatalf("send minted a fresh token while the create's plaintext was in hand:\n"+
			"create %q\nsend   %q", f.token, links[0].Token)
	}
	if _, err := ResolveSigner(ctx, f.deps.Store, links[0].Token, time.Now()); err != nil {
		t.Fatalf("the sent link does not resolve: %v", err)
	}
	// Re-sending is refused: a sent request is not re-dispatched by Send.
	if _, err := f.deps.Send(ctx, f.env.ID, "api:test", time.Now()); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("send on a sent request: %v, want %v", err, ErrStateConflict)
	}
	// Reissue is what replaces a link, and it invalidates the old one: the
	// party holding the first link is told it is dead, not served the request.
	re, err := f.deps.Reissue(ctx, f.env.ID, "api:test")
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if len(re.Reissued) != 1 {
		t.Fatalf("reissue reissued %d parties, want 1", len(re.Reissued))
	}
	newLink := re.Reissued[0].Link // a URL; the token is its last path segment
	newToken := newLink[strings.LastIndex(newLink, "/")+1:]
	if newToken == "" || newToken == links[0].Token {
		t.Fatalf("reissue did not mint a fresh link: %+v", re.Reissued)
	}
	if _, err := ResolveSigner(ctx, f.deps.Store, links[0].Token, time.Now()); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("the displaced link: %v, want %v", err, ErrTokenUnknown)
	}
	if _, err := ResolveSigner(ctx, f.deps.Store, newToken, time.Now()); err != nil {
		t.Fatalf("the new link does not resolve: %v", err)
	}
}

// pngDataURL returns a real, decodable PNG body under a png label.
func pngDataURL(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 40, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 40; x++ {
			img.Set(x, y, color.NRGBA{R: uint8(x * 6)})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png: %v", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func gifBytes() []byte {
	return []byte("GIF89a" + strings.Repeat("\x00", 60))
}

// TestConsentImageLabelIsIgnored is the third fact, and it is stronger than
// the one the ledger recorded. The label in the data URL is not validated,
// because it is not used at all: the type comes from the magic bytes, and the
// label cannot make the service store a file under a name that lies.
func TestConsentImageLabelIsIgnored(t *testing.T) {
	ctx := context.Background()
	body := ConsentInput{
		SignatureText: "Steve Kieu",
		Consent:       true,
		IP:            "127.0.0.1",
		UserAgent:     "unit-test",
	}

	pngBody := pngDataURL(t)
	jpeg := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(gifBytes())
	cases := []struct {
		name     string
		image    string
		wantErr  bool
		wantType string
	}{
		{name: "a PNG under a png label", image: pngBody, wantType: "image/png"},
		{name: "a PNG under a jpeg label",
			image:    strings.Replace(pngBody, "data:image/png;base64,", "data:image/jpeg;base64,", 1),
			wantType: "image/png"}, // the label is not what names the file
		{name: "a GIF body under a jpeg label", image: jpeg, wantErr: true},
		{name: "a GIF body with no label",
			image:   "data:base64," + base64.StdEncoding.EncodeToString(gifBytes()),
			wantErr: true},
		{name: "not base64", image: "data:image/png;base64,!!!!", wantErr: true},
		{name: "empty body", image: "data:image/png;base64,", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A fixture per case: consent moves state, and a case that signs
			// must not decide what the next case sees.
			f := newConsentFixture(t, 1)
			in := body
			in.DocumentSHA = f.dsha
			in.Image = c.image
			_, err := f.deps.Consent(ctx, f.tokens[0], in, time.Now())
			if c.wantErr {
				if !errors.Is(err, ErrConsentImage) {
					t.Fatalf("accepted a body the service must refuse: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a body the service accepts: %v", err)
			}
			cs, err := f.deps.Store.GetConsentByParty(ctx, f.partyID[0])
			if err != nil {
				t.Fatalf("consent row: %v", err)
			}
			if !strings.Contains(cs.Appearance, c.wantType) {
				t.Fatalf("stored appearance does not record %s: %s", c.wantType, cs.Appearance)
			}
			if !strings.Contains(cs.Appearance, `"has_image":true`) {
				t.Fatalf("stored appearance does not record the image: %s", cs.Appearance)
			}
		})
	}
}

// TestConsentImageIsStoredUnderTheExtensionOfItsLabel is the storage half of
// the same rule: the extension follows the label, which is why the label has to
// be checked first.
func TestConsentImageIsStoredUnderTheExtensionOfItsLabel(t *testing.T) {
	f := newConsentFixture(t, 1)
	ctx := context.Background()
	if _, err := f.deps.Consent(ctx, f.tokens[0], ConsentInput{
		SignatureText: "Steve Kieu",
		Consent:       true,
		DocumentSHA:   f.dsha,
		Image:         pngDataURL(t),
		IP:            "127.0.0.1",
		UserAgent:     "unit-test",
	}, time.Now()); err != nil {
		t.Fatalf("consent with a png: %v", err)
	}
	cs, err := f.deps.Store.GetConsentByParty(ctx, f.partyID[0])
	if err != nil {
		t.Fatalf("consent row: %v", err)
	}
	if cs.ImageSHA == "" {
		t.Fatalf("the consent recorded no image")
	}
	if !strings.Contains(cs.Appearance, "image/png") {
		t.Fatalf("a png consent recorded %s", cs.Appearance)
	}
	blob, err := f.deps.Store.GetBlob(cs.ImageSHA, "png")
	if err != nil {
		t.Fatalf("the blob of the consent image is not there: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(blob)); err != nil {
		t.Fatalf("the stored image is not the PNG that was submitted: %v", err)
	}
}
