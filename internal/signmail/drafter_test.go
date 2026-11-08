package signmail

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// The drafter's notices: a decline, and an invitation that never arrived. Both
// go to the person who asked for the signature rather than to a party, so the
// rules that matter are rules a party-facing message does not have: the body
// must carry the reason, and must carry nothing that reads as a link.

func drafterData(kind string) Data {
	return Data{
		Kind:     kind,
		Title:    "Lease 2026",
		Signer:   "Patrick",
		Email:    "patrick@example.test",
		Reason:   "the term sheet is not the one we discussed",
		From:     "signsrv@example.test",
		MailFrom: "signsrv@example.test",
	}
}

func renderText(t *testing.T, r *Renderer, d Data) string {
	t.Helper()
	text, html, err := r.Render(d)
	if err != nil {
		t.Fatalf("render %s: %v", d.Kind, err)
	}
	// Neither drafter message has an HTML part: no link to click means no
	// reason to ship a second MIME part.
	if html != "" {
		t.Fatalf("%s rendered an HTML body, want text only:\n%s", d.Kind, html)
	}
	return text
}

// A decline reads to the drafter as something other than a party who never
// opened the link, which is the whole reason the notice exists.
func TestDeclinedNamesThePartyAndCarriesTheReason(t *testing.T) {
	r := newRenderer(t)
	d := drafterData("declined")
	text := renderText(t, r, d)

	for _, want := range []string{"Patrick", "Lease 2026", "declined",
		"the term sheet is not the one we discussed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("declined body missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(SubjectFor(d), "declined") {
		t.Fatalf("subject does not say what happened: %q", SubjectFor(d))
	}
}

// A decline with no reason says so, rather than printing an empty line and
// leaving the drafter to invent a motive.
func TestDeclinedWithoutAReasonSaysSo(t *testing.T) {
	r := newRenderer(t)
	d := drafterData("declined")
	d.Reason = ""
	text := renderText(t, r, d)
	if !strings.Contains(text, "No reason was given") {
		t.Fatalf("a reasonless decline is not distinguished:\n%s", text)
	}
}

// The undeliverable notice quotes the transport's answer. "It failed" is not
// actionable; "the mailbox does not exist" is a call to the party.
func TestUndeliverableQuotesTheRejection(t *testing.T) {
	r := newRenderer(t)
	d := drafterData("undeliverable")
	d.Reason = "550 5.1.1 <patrick@example.test>: Recipient address rejected"
	text := renderText(t, r, d)

	for _, want := range []string{"patrick@example.test", "Lease 2026",
		"550 5.1.1", "four times"} {
		if !strings.Contains(text, want) {
			t.Fatalf("undeliverable body missing %q:\n%s", want, text)
		}
	}
}

// Neither notice may contain a URL. Neither recipient has a link to use — the
// request is closed in one case and never reached anyone in the other — and a
// line that looks like a link in a message about a failure is what phishing
// trains people to click.
func TestDrafterNoticesContainNoLink(t *testing.T) {
	r := newRenderer(t)
	for _, kind := range []string{"declined", "undeliverable"} {
		d := drafterData(kind)
		// Set the fields a party-facing kind would fill, to prove the template
		// does not reach for them.
		d.Link = "http://127.0.0.1:8090/s/mvt3qxgv2nq5kv3yt3dfwhdjuivn57dr35d6zdrbcyt6r3dftc7q"
		d.DownloadURL = "http://127.0.0.1:8090/d/abc"
		text := renderText(t, r, d)
		if re := regexp.MustCompile(`(?i)\bhttps?://|\bwww\.`); re.MatchString(text) {
			t.Fatalf("%s body contains a URL:\n%s", kind, text)
		}
	}
}

// The drafter's notices are addressed to the drafter, not to the party the
// message is about, and stay a single text part.
func TestDrafterNoticesBuildOnePartToTheRightAddress(t *testing.T) {
	r := newRenderer(t)
	for _, kind := range []string{"declined", "undeliverable"} {
		d := drafterData(kind)
		text, html, err := r.Render(d)
		if err != nil {
			t.Fatalf("render %s: %v", kind, err)
		}
		m := &Message{Kind: kind, EnvelopeID: "e1", PartyID: "p1",
			To: "drafter@example.test", From: "signsrv@example.test",
			Subject: SubjectFor(d), Text: text, HTML: html}
		raw := string(m.Build(time.Now().UTC()))
		if !strings.Contains(raw, "To: drafter@example.test") {
			t.Fatalf("%s is not addressed to the drafter:\n%s", kind, raw)
		}
		if strings.Contains(raw, "Content-Type: text/html") {
			t.Fatalf("%s message carries an HTML part:\n%s", kind, raw)
		}
	}
}

// A party's reason or address with markup in it cannot put markup in the
// drafter's body, and cannot break out of the address the notice prints.
func TestDrafterNoticesStayFreeOfMarkup(t *testing.T) {
	r := newRenderer(t)
	for _, kind := range []string{"declined", "undeliverable"} {
		d := drafterData(kind)
		d.Reason = "looks fine<a href=\"http://evil.test\">here</a> &amp; &nbsp"
		d.Email = "pat<@evil.test"
		text := renderText(t, r, d)
		// The tag and the entities are gone; the angle bracket that was part of
		// an email address is not markup and stays, which is why this checks the
		// patterns checkText checks rather than the character.
		for _, bad := range []string{"<a", "href", "&amp;", "&nbsp;", "&lt;"} {
			if strings.Contains(text, bad) {
				t.Fatalf("%s body carries %q:\n%s", kind, bad, text)
			}
		}
		// The reason survived as text, so the drafter can still read it.
		if !strings.Contains(text, "looks fine") {
			t.Fatalf("%s body dropped the reason text:\n%s", kind, text)
		}
	}
}
