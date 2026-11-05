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
func mailTestCmd(configPath string, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: signsrv mail-test <address>")
		return 2
	}
	addr := args[0]
	if _, err := mail.ParseAddress(addr); err != nil {
		fmt.Fprintf(os.Stderr, "signsrv: %q is not a mail address\n", addr)
		return 2
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}

	r, err := signmail.NewRenderer(web.Templates())
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}

	sender := mailSenderFor(cfg)
	if sender == nil {
		fmt.Fprintln(os.Stderr, "signsrv: no mail sender configured")
		fmt.Fprintln(os.Stderr, "  set dev mode, or smtp_host (and smtp_port)")
		return 1
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
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
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
		fmt.Fprintln(os.Stderr, "signsrv:", err)
		return 1
	}

	if cfg.Dev {
		fmt.Printf("mail test written to %s\n", cfg.Outbox)
		return 0
	}
	fmt.Printf("mail test sent to %s via %s:%d\n", addr, cfg.SMTPHost, cfg.SMTPPort)
	return 0
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
