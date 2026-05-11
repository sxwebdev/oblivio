package email

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
)

// VerifyEmailParams parameterises the rendered verification message.
type VerifyEmailParams struct {
	// VerifyURL is the click-through URL the user opens to confirm. Built
	// from {server.public_url}/verify-email?token=<raw>. Token must be raw
	// (not the SHA-256) — the server checks the SHA-256 of what arrives.
	VerifyURL string
	// AppName is the product display name. Defaults to "Oblivio".
	AppName string
}

// RenderVerifyEmail returns the (subject, text, html) tuple for the
// verification message. Subject is intentionally plain so spam filters
// don't burn the link; the HTML body is a single CTA button.
func RenderVerifyEmail(p VerifyEmailParams) (subject, textBody, htmlBody string, err error) { //nolint:nonamedreturns
	if p.AppName == "" {
		p.AppName = "Oblivio"
	}
	if p.VerifyURL == "" {
		return "", "", "", fmt.Errorf("verify_url required")
	}
	if _, err := url.ParseRequestURI(p.VerifyURL); err != nil {
		return "", "", "", fmt.Errorf("verify_url invalid: %w", err)
	}

	subject = fmt.Sprintf("Confirm your %s email address", p.AppName)
	textBody = fmt.Sprintf(
		"Welcome to %s. To confirm this is your email address, open the link below.\n\n%s\n\nThe link expires in 24 hours. If you did not register an account, ignore this message.\n",
		p.AppName, p.VerifyURL,
	)

	tmpl, err := template.New("verify").Parse(verifyHTML)
	if err != nil {
		return "", "", "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", "", "", err
	}
	htmlBody = buf.String()
	return subject, textBody, htmlBody, nil
}

// verifyHTML is intentionally minimal — no remote assets, no inline JS.
// Looks fine in every modern client and won't trip spam filters.
const verifyHTML = `<!DOCTYPE html>
<html>
  <body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#111;line-height:1.5;">
    <p>Welcome to <strong>{{.AppName}}</strong>.</p>
    <p>Confirm your email address by clicking the button below.</p>
    <p>
      <a href="{{.VerifyURL}}"
         style="display:inline-block;padding:10px 16px;background:#111;color:#fff;text-decoration:none;border-radius:6px;">
        Confirm email
      </a>
    </p>
    <p>Or copy this link into your browser:</p>
    <p style="word-break:break-all;color:#444;">{{.VerifyURL}}</p>
    <p style="color:#777;font-size:12px;">The link expires in 24 hours. If you did not register an account, ignore this email.</p>
  </body>
</html>`
