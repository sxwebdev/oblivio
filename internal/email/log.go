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
//
// The full text body is intentionally NOT logged (M-11). Verification
// and recovery emails contain raw single-use tokens; if an operator
// accidentally leaves provider="log" in production or staging, anyone
// who can read the log stream could verify any address that signs up
// or hijack a recovery flow. We log only the envelope metadata; for
// debugging in dev, prefer the SMTP provider pointed at mailhog.
func (s *LogSender) Send(_ context.Context, msg Message) error {
	s.log.Infow(
		"email send (log-sender stub)",
		"to", msg.To,
		"subject", msg.Subject,
		"text_len", len(msg.TextBody),
		"html_len", len(msg.HTMLBody),
	)
	return nil
}
