package email

import (
	"context"

	"github.com/tkcrm/mx/logger"
)

// LogSender pretends to send by writing the message to the logger. Useful
// in dev (with mailhog turned off) and in CI/tests where we just want to
// see the would-be content of the message.
type LogSender struct{ log logger.ExtendedLogger }

// NewLogSender constructs a LogSender bound to the given logger.
func NewLogSender(log logger.ExtendedLogger) *LogSender { return &LogSender{log: log} }

// Send writes a structured INFO line. Returns nil — by definition the
// stub never fails.
func (s *LogSender) Send(_ context.Context, msg Message) error {
	s.log.Infow("email send (log-sender stub)",
		"to", msg.To,
		"subject", msg.Subject,
		"text_len", len(msg.TextBody),
		"html_len", len(msg.HTMLBody),
		"text", msg.TextBody,
	)
	return nil
}
