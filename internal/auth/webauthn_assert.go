// Shared WebAuthn-assertion validation. Used by every endpoint that
// requires the user to re-prove passkey possession via a previously
// seeded BeginAssertion challenge (LoginTOTPService.Disable,
// VaultService.DeleteMe, WebAuthnService.UnlockWithPasskey).

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sxwebdev/oblivio/internal/auth/wauser"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_webauthn_credentials"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_users"
)

// ConsumeWebAuthnAssertion validates `assertion` against the BeginAssertion
// challenge identified by `sessionID`, then bumps sign_count + flags on the
// matched DB row. Returns the credential row so callers that need its
// stored unlock_wrapped_vault_key / prf_salt do not have to re-look-up.
//
// All errors are returned as fully-formed connect.Errors so the caller
// can simply propagate.
func ConsumeWebAuthnAssertion(
	ctx context.Context,
	tx pgx.Tx,
	wAuthn *wa.WebAuthn,
	mfa *MFAStore,
	userID uuid.UUID,
	sessionID string,
	assertion []byte,
) (*models.UserWebauthnCredential, error) {
	if wAuthn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn not configured"))
	}
	if mfa == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("mfa store not configured"))
	}
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid mfa_session_id"))
	}
	ch, err := mfa.Take(ctx, sid)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("mfa challenge expired"))
	}
	if ch.UserID != userID || ch.WebAuthnState == nil {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("session does not belong to caller"))
	}

	u, err := repo_users.New(tx).GetUserByID(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("load user: %w", err))
	}
	creds, err := repo_user_webauthn_credentials.New(tx).ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("list credentials: %w", err))
	}
	wuser := wauser.FromIdentity(u.ID, u.Email, creds)

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertion))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse assertion: %w", err))
	}
	credential, err := wAuthn.ValidateLogin(wuser, *ch.WebAuthnState, parsed)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("webauthn validate: %w", err))
	}

	matched, err := repo_user_webauthn_credentials.New(tx).GetWebAuthnCredentialByCredID(ctx, credential.ID)
	if err != nil {
		// The assertion validated, but the DB row vanished between
		// BeginAssertion and now. Treat as unauthenticated rather than
		// 500: the credential effectively does not exist for us.
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("credential row missing"))
	}
	if matched.UserID != userID {
		// Defence in depth: ValidateLogin already constrains by the
		// allowCredentials list on the challenge, but a future change
		// could weaken that. Refuse cross-user matches outright.
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("credential belongs to a different user"))
	}
	if err := repo_user_webauthn_credentials.New(tx).TouchWebAuthnCredential(ctx, repo_user_webauthn_credentials.TouchWebAuthnCredentialParams{
		ID:        matched.ID,
		SignCount: int64(credential.Authenticator.SignCount),
		Flags:     int16(credential.Flags.ProtocolValue()), //nolint:gosec
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("touch credential: %w", err))
	}
	return matched, nil
}
