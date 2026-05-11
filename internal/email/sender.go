// Package email provides transactional email delivery for verification
// flows (Sprint F). The Sender interface is satisfied by three concrete
// implementations:
//
//   - SMTPSender   — production via wneessen/go-mail.
//   - LogSender    — dev/CI: writes the message to the structured logger.
//   - NoopSender   — explicit "feature disabled" stub.
//
// The selection lives in cmd/oblivio/start.go so this package stays
// import-cycle-free.
package email

import "context"

// Sender is the minimal contract every backend implementation honours.
// It is intentionally small — we only need text + HTML transactional mail
// for now; richer features (attachments, templating loops, queues) belong
// in a richer layer if and when they're needed.
type Sender interface {
	// Send delivers a single message. Implementations MUST return an error
	// when the message could not be queued/transmitted; the AuthService
	// caller surfaces the failure as a 5xx but keeps the user_row written
	// (the verification flow will retry on ResendVerification).
	Send(ctx context.Context, msg Message) error
}

// Message is the canonical transactional email shape: To/Subject/Body.
// HTMLBody is optional — when empty the Text body is used as the only
// part. From/ReplyTo come from EmailConfig and are added by the concrete
// Sender implementation.
type Message struct {
	To       string
	Subject  string
	TextBody string
	HTMLBody string
}
