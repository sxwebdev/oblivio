package email

import (
	"context"
	"crypto/tls"
	"fmt"

	mail "github.com/wneessen/go-mail"
)

// SMTPConfig captures the dial parameters needed to talk to an SMTP relay.
// Mirrors config.SMTPConfig + From; we keep the field set local so this
// package doesn't import the application config struct.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// AllowInsecure short-circuits StartTLS when talking to mailhog/dev
	// servers that don't speak TLS at all. NEVER set in prod.
	AllowInsecure bool
}

// SMTPSender is the production-ready Sender. Each Send opens a fresh
// connection — for the verification-email volume we expect (a handful per
// new user per day) the connection-pooling complexity is not worth it.
type SMTPSender struct{ cfg SMTPConfig }

// NewSMTPSender returns an SMTPSender from the supplied config. It does
// not open a connection at construction time; the first Send dials.
func NewSMTPSender(cfg SMTPConfig) *SMTPSender { return &SMTPSender{cfg: cfg} }

// Send composes a MIME multipart/alternative message and ships it via
// SMTP STARTTLS (or plain when AllowInsecure is set, e.g. mailhog dev).
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	m := mail.NewMsg()
	if err := m.From(s.cfg.From); err != nil {
		return fmt.Errorf("smtp: from: %w", err)
	}
	if err := m.To(msg.To); err != nil {
		return fmt.Errorf("smtp: to: %w", err)
	}
	m.Subject(msg.Subject)
	m.SetBodyString(mail.TypeTextPlain, msg.TextBody)
	if msg.HTMLBody != "" {
		m.AddAlternativeString(mail.TypeTextHTML, msg.HTMLBody)
	}

	opts := []mail.Option{
		mail.WithPort(s.cfg.Port),
		mail.WithTLSPolicy(mail.TLSOpportunistic),
	}
	if s.cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(s.cfg.Password),
		)
	}
	if s.cfg.AllowInsecure {
		// mailhog accepts plain SMTP on 1025 with no auth, no TLS.
		opts = append(opts,
			mail.WithTLSPolicy(mail.NoTLS),
			mail.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec
		)
	}

	c, err := mail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("smtp: client: %w", err)
	}
	if err := c.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("smtp: send: %w", err)
	}
	return nil
}
