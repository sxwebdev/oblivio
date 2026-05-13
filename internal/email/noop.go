package email

import "context"

// NoopSender is the explicit "email feature disabled" stub. AuthService
// detects it via type-switch (or simply observes that no Provider is
// configured) and skips the verification-token generation entirely.
type NoopSender struct{}

// NewNoopSender returns the singleton no-op sender.
func NewNoopSender() *NoopSender { return &NoopSender{} }

// Send is a no-op that returns nil.
func (NoopSender) Send(_ context.Context, _ Message) error { return nil }
