package main

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/sunshine69/pdf-go/internal/signmail"
	"github.com/sunshine69/pdf-go/web"
)

// mail-test sends one message to one address. It is the operator's test that
// the mail path works: the templates, the sender, the config, the address. In
// dev mode the sender is the file sender, so the message lands as .eml in the
// outbox directory and the command says where. In production the message goes
// to the SMTP host.
//
// The message is an invitation with a test link. It is not tied to an
// envelope, so the command needs no store. The point is the delivery, not the
// state.
//
// The work is in runMailTest, so `signsrv mail-test` on the server and
// POST /api/v1/admin/mail-test from a desk send the same message through the
// same sender: a runbook step works whichever side of the network you are on.
func mailTestCmd(configPath string, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: signsrv mail-test <address>")
		return 2
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	result, err := runMailTest(cfg, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}
	for k, v := range result {
		fmt.Printf("%-14s %v\n", k+":", v)
	}
	return 0
}

// runMailTest renders and sends one test message, and describes what it did.
//
// The address is parsed before any work: a typo should fail immediately, not
// after the templates have been parsed and a connection opened. The answer
// names the transport, because "the mail path works" is only meaningful when
// you know which path was taken — the outbox in dev mode is not the relay.
func runMailTest(cfg *Config, addr string) (map[string]any, error) {
	if _, err := mail.ParseAddress(addr); err != nil {
		return nil, fmt.Errorf("%q is not a mail address", addr)
	}
	r, err := signmail.NewRenderer(web.Templates())
	if err != nil {
		return nil, err
	}
	sender := mailSenderFor(cfg)
	if sender == nil {
		return nil, fmt.Errorf("no mail sender configured: set dev mode, or smtp_host (and smtp_port)")
	}

	now := time.Now().UTC()
	d := signmail.Data{
		Kind:     "invite",
		Title:    "Mail test",
		Sender:   cfg.MailFrom,
		Signer:   strings.SplitN(addr, "@", 2)[0],
		Link:     cfg.PublicURL + "/s/mailtest",
		Reason:   "This is a test of the mail path. No document is attached.",
		From:     cfg.MailFrom,
		MailFrom: cfg.MailFrom,
		Order:    1,
		N:        1,
		Email:    addr,
	}
	d = signmail.Prepare(d, now.Format(time.RFC3339))
	d.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339)
	d.DaysLeft = 1

	text, html, err := r.Render(d)
	if err != nil {
		return nil, err
	}
	m := &signmail.Message{
		Kind:    "invite",
		To:      addr,
		From:    cfg.MailFrom,
		Subject: d.Subject,
		Text:    text,
		HTML:    html,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sender.Send(ctx, m); err != nil {
		return nil, fmt.Errorf("the sender refused the message: %w", err)
	}

	if cfg.Dev {
		return map[string]any{
			"sent":       true,
			"to":         addr,
			"transport":  "outbox",
			"outbox_dir": cfg.Outbox,
			"subject":    d.Subject,
			"note":       "dev mode: the message is a .eml file in the outbox, not a delivery",
		}, nil
	}
	return map[string]any{
		"sent":      true,
		"to":        addr,
		"transport": "smtp",
		"host":      cfg.SMTPHost,
		"port":      cfg.SMTPPort,
		"subject":   d.Subject,
	}, nil
}

// mailSenderFor picks the sender from the config: the file sender in dev mode,
// SMTP otherwise. nil when the config has no transport, which the command
// reports as a config error.
func mailSenderFor(cfg *Config) signmail.Sender {
	if cfg.Dev {
		return &signmail.FileSender{Dir: cfg.Outbox}
	}
	if cfg.SMTPHost == "" {
		return nil
	}
	return &signmail.SMTPSender{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		StartTLS: cfg.SMTPStartTLS,
		User:     cfg.SMTPUser,
		Password: cfg.SMTPPassword(),
	}
}
