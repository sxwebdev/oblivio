//go:build integration

// Integration coverage for the auth_key + 2FA gates added to
// VaultService.DeleteMe and WebAuthnService.{RemoveCredential,
// EnablePasskeyUnlock, DisablePasskeyUnlock, UnlockWithPasskey}.
//
// These tests go through the real Connect handler stack against a live
// Postgres so the auth middleware, RLS interceptor and audit interceptor
// are all in the loop. Where producing a valid WebAuthn assertion would
// require a fake authenticator we assert on the "factor missing →
// InvalidArgument" boundary instead; the happy-path crypto is covered
// by the existing TOTP/WebAuthn ceremony tests at the unit level.
package api_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1 for authenticator-app interop.
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/auth"
	srvcrypto "github.com/sxwebdev/oblivio/internal/crypto"
)

// TestE2E_DeleteMe_RequiresAuthKey covers the three boundary conditions
// of the auth_key gate: missing, wrong, correct. Only the third should
// actually delete the user. We use a freshly-registered account with no
// 2FA enrolled, so the auth_key check is the only required factor.
func TestE2E_DeleteMe_RequiresAuthKey(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access := registerUserWithAuthKey(t, authClient, "deleteme-authkey@example.com")

	// Missing auth_key → InvalidArgument (the proto field is required).
	_, err := vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{Reason: "test"}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	// Wrong auth_key → Unauthenticated.
	_, err = vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{AuthKey: randBytes(t, 32)}, access))
	requireConnectCode(t, err, connect.CodeUnauthenticated)

	// Correct auth_key, no 2FA enrolled → success.
	if _, err := vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{AuthKey: authKey}, access)); err != nil {
		t.Fatalf("DeleteMe(correct auth_key): %v", err)
	}

	// Calling GetMe with the same token must now fail — the user is gone,
	// the session row was cascaded.
	_, err = vaultClient.GetMe(ctx, bearer(&pb.GetMeRequest{}, access))
	if err == nil {
		t.Fatal("GetMe after DeleteMe should fail")
	}
}

// TestE2E_DeleteMe_RequiresTotpWhenEnabled validates that the second
// factor is mandatory once a user enables login TOTP. We don't generate
// a valid code here — that's covered by the happy-path test below —
// just assert that omission produces a clean InvalidArgument.
func TestE2E_DeleteMe_RequiresTotpWhenEnabled(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")
	totpClient := obliviov1connect.NewLoginTOTPServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access := registerUserWithAuthKey(t, authClient, "deleteme-totp@example.com")
	enableLoginTOTP(t, ctx, totpClient, authKey, access)

	// TOTP enabled, no totp_code supplied — must reject before deletion.
	_, err := vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{AuthKey: authKey}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "totp_code") {
		t.Fatalf("DeleteMe missing totp_code: error should mention totp_code, got %v", err)
	}
}

// TestE2E_DeleteMe_WithTotpHappyPath verifies the full TOTP factor path
// when a valid current code is supplied. The user is actually deleted.
func TestE2E_DeleteMe_WithTotpHappyPath(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")
	totpClient := obliviov1connect.NewLoginTOTPServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access := registerUserWithAuthKey(t, authClient, "deleteme-totp-ok@example.com")
	secretBase32 := enableLoginTOTP(t, ctx, totpClient, authKey, access)

	code := computeTOTPCode(t, secretBase32, time.Now().UTC())
	if _, err := vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{
		AuthKey:  authKey,
		TotpCode: code,
	}, access)); err != nil {
		t.Fatalf("DeleteMe with valid totp: %v", err)
	}
}

// TestE2E_DeleteMe_RequiresPasskeyAssertionWhenEnrolled checks that an
// enrolled passkey forces the caller to provide a WebAuthn assertion at
// account deletion. We can't produce a real assertion without a software
// authenticator stack, but the "missing factor" error path is enough to
// pin the contract.
func TestE2E_DeleteMe_RequiresPasskeyAssertionWhenEnrolled(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access, userID := registerUserReturnIDs(t, authClient, "deleteme-passkey@example.com")
	insertFakeWebAuthnCredential(t, ctx, srv, userID, "primary")

	_, err := vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{AuthKey: authKey}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "webauthn_assertion_json") {
		t.Fatalf("DeleteMe missing assertion: error should mention webauthn_assertion_json, got %v", err)
	}
}

// TestE2E_RemoveCredential_RequiresAuthKey pins the new auth_key gate on
// passkey removal. Empty / wrong / right is asserted in that order; the
// row must still exist after the first two attempts and be gone after
// the third.
func TestE2E_RemoveCredential_RequiresAuthKey(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	waClient := obliviov1connect.NewWebAuthnServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access, userID := registerUserReturnIDs(t, authClient, "remove-cred@example.com")
	credID := insertFakeWebAuthnCredential(t, ctx, srv, userID, "yubikey")

	// Empty auth_key.
	_, err := waClient.RemoveCredential(ctx, bearer(&pb.RemoveCredentialRequest{
		CredentialId: credID.String(),
	}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	// Wrong auth_key.
	_, err = waClient.RemoveCredential(ctx, bearer(&pb.RemoveCredentialRequest{
		CredentialId: credID.String(),
		AuthKey:      randBytes(t, 32),
	}, access))
	requireConnectCode(t, err, connect.CodeUnauthenticated)

	assertCredentialExists(t, ctx, srv, credID, true)

	// Correct auth_key.
	if _, err := waClient.RemoveCredential(ctx, bearer(&pb.RemoveCredentialRequest{
		CredentialId: credID.String(),
		AuthKey:      authKey,
	}, access)); err != nil {
		t.Fatalf("RemoveCredential(correct): %v", err)
	}
	assertCredentialExists(t, ctx, srv, credID, false)
}

// TestE2E_EnableDisablePasskeyUnlock exercises the full bundle lifecycle.
// Enable stores the wrapped blob + salt; ListCredentials surfaces the
// unlock_enabled flag; Disable clears both columns; ListCredentials
// reports the credential as no longer unlock-capable.
func TestE2E_EnableDisablePasskeyUnlock(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	waClient := obliviov1connect.NewWebAuthnServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access, userID := registerUserReturnIDs(t, authClient, "passkey-unlock@example.com")
	credID := insertFakeWebAuthnCredential(t, ctx, srv, userID, "main")

	prfSalt := randBytes(t, 32)
	wrapped := randBytes(t, 60) // arbitrary blob — server just stores it.

	// Missing auth_key.
	_, err := waClient.EnablePasskeyUnlock(ctx, bearer(&pb.EnablePasskeyUnlockRequest{
		CredentialId:    credID.String(),
		WrappedVaultKey: wrapped,
		PrfSalt:         prfSalt,
	}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	// Wrong-length salt.
	_, err = waClient.EnablePasskeyUnlock(ctx, bearer(&pb.EnablePasskeyUnlockRequest{
		CredentialId:    credID.String(),
		WrappedVaultKey: wrapped,
		PrfSalt:         randBytes(t, 16),
		AuthKey:         authKey,
	}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	// Right shape, right key.
	if _, err := waClient.EnablePasskeyUnlock(ctx, bearer(&pb.EnablePasskeyUnlockRequest{
		CredentialId:    credID.String(),
		WrappedVaultKey: wrapped,
		PrfSalt:         prfSalt,
		AuthKey:         authKey,
	}, access)); err != nil {
		t.Fatalf("EnablePasskeyUnlock: %v", err)
	}

	list, err := waClient.ListCredentials(ctx, bearer(&pb.ListCredentialsRequest{}, access))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(list.Msg.GetCredentials()) != 1 {
		t.Fatalf("ListCredentials: got %d credentials, want 1", len(list.Msg.GetCredentials()))
	}
	c := list.Msg.GetCredentials()[0]
	if !c.GetUnlockEnabled() {
		t.Fatal("ListCredentials: UnlockEnabled should be true after EnablePasskeyUnlock")
	}
	if string(c.GetPrfSalt()) != string(prfSalt) {
		t.Fatalf("ListCredentials: PrfSalt mismatch (got %d bytes, want %d)", len(c.GetPrfSalt()), len(prfSalt))
	}

	// Disable clears the bundle.
	if _, err := waClient.DisablePasskeyUnlock(ctx, bearer(&pb.DisablePasskeyUnlockRequest{
		CredentialId: credID.String(),
		AuthKey:      authKey,
	}, access)); err != nil {
		t.Fatalf("DisablePasskeyUnlock: %v", err)
	}
	list, err = waClient.ListCredentials(ctx, bearer(&pb.ListCredentialsRequest{}, access))
	if err != nil {
		t.Fatalf("ListCredentials after disable: %v", err)
	}
	c = list.Msg.GetCredentials()[0]
	if c.GetUnlockEnabled() {
		t.Fatal("ListCredentials: UnlockEnabled should be false after DisablePasskeyUnlock")
	}
	if len(c.GetPrfSalt()) != 0 {
		t.Fatalf("ListCredentials: PrfSalt should be empty after disable, got %d bytes", len(c.GetPrfSalt()))
	}
}

// TestE2E_DeleteMe_FailedAttempt_AppendsAuditRow asserts the audit chain
// now records failed crypto-shred probes. Both a wrong auth_key (the
// earliest gate) and a missing assertion (after auth_key passes) must
// emit an `account_delete_attempt_failed` row with stage + reason set.
func TestE2E_DeleteMe_FailedAttempt_AppendsAuditRow(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")
	auditClient := obliviov1connect.NewAuditServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access, userID := registerUserReturnIDs(t, authClient, "deleteme-audit@example.com")

	// 1) Wrong auth_key → expect a failed-attempt audit row at stage=auth_key.
	_, err := vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{AuthKey: randBytes(t, 32)}, access))
	requireConnectCode(t, err, connect.CodeUnauthenticated)

	// 2) Right auth_key + enrolled passkey but no assertion → stage=passkey.
	insertFakeWebAuthnCredential(t, ctx, srv, userID, "phone")
	_, err = vaultClient.DeleteMe(ctx, bearer(&pb.DeleteMeRequest{AuthKey: authKey}, access))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	// The audit writer uses its own system tx, so failed-attempt rows
	// survive the outer request-tx rollback. Two rows expected.
	resp, err := auditClient.ListAudit(ctx, bearer(&pb.ListAuditRequest{
		Action: ptr(pb.AuditAction_AUDIT_ACTION_ACCOUNT_DELETE_ATTEMPT_FAILED),
		Limit:  50,
	}, access))
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(resp.Msg.GetEntries()) != 2 {
		t.Fatalf("expected 2 failed-delete audit rows, got %d", len(resp.Msg.GetEntries()))
	}
	stages := map[string]bool{}
	for _, e := range resp.Msg.GetEntries() {
		var meta map[string]any
		if len(e.GetMetadataJson()) > 0 {
			_ = jsonUnmarshal(e.GetMetadataJson(), &meta)
		}
		if s, ok := meta["stage"].(string); ok {
			stages[s] = true
		}
	}
	if !stages["auth_key"] || !stages["passkey"] {
		t.Fatalf("expected stages {auth_key, passkey}, got %v", stages)
	}
}

// TestE2E_ChangeMasterPassword_RevokesPasskeyUnlocks confirms the
// revoke_passkey_unlocks flag clears every stored unlock bundle for
// the user while leaving the credentials themselves intact (they can
// still serve as a 2FA at sign-in).
func TestE2E_ChangeMasterPassword_RevokesPasskeyUnlocks(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	waClient := obliviov1connect.NewWebAuthnServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access, userID := registerUserReturnIDs(t, authClient, "rotate-revoke@example.com")
	credID := insertFakeWebAuthnCredential(t, ctx, srv, userID, "k")

	// Enable unlock so there's a bundle to revoke.
	prfSalt := randBytes(t, 32)
	wrapped := randBytes(t, 60)
	if _, err := waClient.EnablePasskeyUnlock(ctx, bearer(&pb.EnablePasskeyUnlockRequest{
		CredentialId:    credID.String(),
		WrappedVaultKey: wrapped,
		PrfSalt:         prfSalt,
		AuthKey:         authKey,
	}, access)); err != nil {
		t.Fatalf("EnablePasskeyUnlock: %v", err)
	}

	// Sanity: unlock_enabled=true before rotation.
	list, err := waClient.ListCredentials(ctx, bearer(&pb.ListCredentialsRequest{}, access))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if !list.Msg.GetCredentials()[0].GetUnlockEnabled() {
		t.Fatal("setup precondition: unlock should be enabled before rotation")
	}

	// Rotate master password with the revoke flag. We do NOT need the
	// vault_key path to be valid for this test — the server only writes
	// the new artefacts and clears the unlock bundles; it does not
	// decrypt anything. Random new artefacts suffice.
	newAuthKey := randBytes(t, 32)
	if _, err := authClient.ChangeMasterPassword(ctx, bearer(&pb.ChangeMasterPasswordRequest{
		OldAuthKey:           authKey,
		NewAuthKey:           newAuthKey,
		NewSaltUser:          randBytes(t, 16),
		NewKdfParams:         clientKDFParams(),
		NewVerifier:          randBytes(t, 32),
		NewWrappedVaultKey:   randBytes(t, 60),
		RevokePasskeyUnlocks: true,
	}, access)); err != nil {
		t.Fatalf("ChangeMasterPassword: %v", err)
	}

	// Credential row is still there.
	assertCredentialExists(t, ctx, srv, credID, true)
	// But its unlock bundle is gone.
	list, err = waClient.ListCredentials(ctx, bearer(&pb.ListCredentialsRequest{}, access))
	if err != nil {
		t.Fatalf("ListCredentials after rotate: %v", err)
	}
	if len(list.Msg.GetCredentials()) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list.Msg.GetCredentials()))
	}
	c := list.Msg.GetCredentials()[0]
	if c.GetUnlockEnabled() {
		t.Fatal("unlock should be revoked after rotate with revoke_passkey_unlocks=true")
	}
	if len(c.GetPrfSalt()) != 0 {
		t.Fatalf("prf_salt should be cleared, got %d bytes", len(c.GetPrfSalt()))
	}
}

// TestE2E_ChangeMasterPassword_PreservesPasskeyUnlocksByDefault is the
// counterpart: without the revoke flag, the bundle survives the
// rotation (vault_key is unchanged, the PRF-derived key still
// decrypts the blob). This pins the default behaviour.
func TestE2E_ChangeMasterPassword_PreservesPasskeyUnlocksByDefault(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	waClient := obliviov1connect.NewWebAuthnServiceClient(srv.Client(), srv.URL+"/api")

	authKey, access, userID := registerUserReturnIDs(t, authClient, "rotate-keep@example.com")
	credID := insertFakeWebAuthnCredential(t, ctx, srv, userID, "k")
	if _, err := waClient.EnablePasskeyUnlock(ctx, bearer(&pb.EnablePasskeyUnlockRequest{
		CredentialId:    credID.String(),
		WrappedVaultKey: randBytes(t, 60),
		PrfSalt:         randBytes(t, 32),
		AuthKey:         authKey,
	}, access)); err != nil {
		t.Fatalf("EnablePasskeyUnlock: %v", err)
	}

	if _, err := authClient.ChangeMasterPassword(ctx, bearer(&pb.ChangeMasterPasswordRequest{
		OldAuthKey:         authKey,
		NewAuthKey:         randBytes(t, 32),
		NewSaltUser:        randBytes(t, 16),
		NewKdfParams:       clientKDFParams(),
		NewVerifier:        randBytes(t, 32),
		NewWrappedVaultKey: randBytes(t, 60),
		// RevokePasskeyUnlocks defaults to false.
	}, access)); err != nil {
		t.Fatalf("ChangeMasterPassword: %v", err)
	}
	list, err := waClient.ListCredentials(ctx, bearer(&pb.ListCredentialsRequest{}, access))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if !list.Msg.GetCredentials()[0].GetUnlockEnabled() {
		t.Fatal("default rotation should preserve passkey unlock bundles")
	}
}

// TestE2E_DisablePasskeyUnlock_RequiresAuthKey isolates the auth_key gate
// on the disable side — the enable gate is covered above.
func TestE2E_DisablePasskeyUnlock_RequiresAuthKey(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	waClient := obliviov1connect.NewWebAuthnServiceClient(srv.Client(), srv.URL+"/api")

	_, access, userID := registerUserReturnIDs(t, authClient, "passkey-disable@example.com")
	credID := insertFakeWebAuthnCredential(t, ctx, srv, userID, "main")

	_, err := waClient.DisablePasskeyUnlock(ctx, bearer(&pb.DisablePasskeyUnlockRequest{
		CredentialId: credID.String(),
		AuthKey:      randBytes(t, 32),
	}, access))
	requireConnectCode(t, err, connect.CodeUnauthenticated)
}

// --- helpers --------------------------------------------------------------

// registerUserWithAuthKey is registerUser but also returns the random
// authKey the test minted, so the test can later re-prove it.
func registerUserWithAuthKey(t *testing.T, c obliviov1connect.AuthServiceClient, email string) (authKey []byte, accessToken string) {
	t.Helper()
	authKey = randBytes(t, 32)
	resp, err := c.Register(context.Background(), connect.NewRequest(&pb.RegisterRequest{
		Email:                   email,
		SaltUser:                randBytes(t, 16),
		KdfParams:               clientKDFParams(),
		AuthKey:                 authKey,
		Verifier:                randBytes(t, 32),
		WrappedVaultKey:         randBytes(t, 60),
		RecoverySalt:            randBytes(t, 16),
		RecoveryWrappedVaultKey: randBytes(t, 60),
		RecoveryProof:           randBytes(t, 32),
		BlindPepper:             randBytes(t, 32),
		DeviceInfo: &pb.DeviceInfo{
			DeviceId:   "device-e2e",
			DeviceType: "web",
			DeviceName: "e2e",
		},
	}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	accessToken = resp.Msg.GetAuthPayload().GetAccessToken()
	if accessToken == "" {
		t.Fatal("Register returned empty access token")
	}
	return authKey, accessToken
}

// registerUserReturnIDs is the same plus the parsed user UUID. Useful for
// direct DB writes (insertFakeWebAuthnCredential).
func registerUserReturnIDs(t *testing.T, c obliviov1connect.AuthServiceClient, email string) (authKey []byte, accessToken string, userID uuid.UUID) {
	t.Helper()
	authKey = randBytes(t, 32)
	resp, err := c.Register(context.Background(), connect.NewRequest(&pb.RegisterRequest{
		Email:                   email,
		SaltUser:                randBytes(t, 16),
		KdfParams:               clientKDFParams(),
		AuthKey:                 authKey,
		Verifier:                randBytes(t, 32),
		WrappedVaultKey:         randBytes(t, 60),
		RecoverySalt:            randBytes(t, 16),
		RecoveryWrappedVaultKey: randBytes(t, 60),
		RecoveryProof:           randBytes(t, 32),
		BlindPepper:             randBytes(t, 32),
		DeviceInfo: &pb.DeviceInfo{
			DeviceId:   "device-e2e",
			DeviceType: "web",
			DeviceName: "e2e",
		},
	}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	accessToken = resp.Msg.GetAuthPayload().GetAccessToken()
	if accessToken == "" {
		t.Fatal("Register returned empty access token")
	}
	userID, err = uuid.Parse(resp.Msg.GetUserId())
	if err != nil {
		t.Fatalf("parse user id: %v", err)
	}
	return authKey, accessToken, userID
}

// enableLoginTOTP runs the Setup→Enable RPC sequence and returns the
// plaintext base32 secret so the caller can compute valid codes.
func enableLoginTOTP(t *testing.T, ctx context.Context, c obliviov1connect.LoginTOTPServiceClient, authKey []byte, access string) (secretBase32 string) {
	t.Helper()
	// A small, deterministic, base32-clean secret. Real apps generate ≥
	// 16 random bytes; 20 bytes (160 bits) here is the RFC 4226 sweet spot.
	rawSecret := randBytes(t, 20)
	secretBase32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecret)

	envelope, nonce, err := encryptLoginTOTPSecret(authKey, []byte(secretBase32))
	if err != nil {
		t.Fatalf("seal login_totp secret: %v", err)
	}

	// Setup wants a *current* code as proof the client can read the
	// secret it's uploading.
	setupCode := computeTOTPCode(t, secretBase32, time.Now().UTC())
	if _, err := c.Setup(ctx, bearer(&pb.LoginTOTPServiceSetupRequest{
		EncryptedSecret: envelope,
		Nonce:           nonce,
		AuthKey:         authKey,
		TotpCode:        setupCode,
	}, access)); err != nil {
		t.Fatalf("LoginTOTP.Setup: %v", err)
	}

	enableCode := computeTOTPCode(t, secretBase32, time.Now().UTC())
	if _, err := c.Enable(ctx, bearer(&pb.LoginTOTPServiceEnableRequest{
		AuthKey:  authKey,
		TotpCode: enableCode,
	}, access)); err != nil {
		t.Fatalf("LoginTOTP.Enable: %v", err)
	}
	return secretBase32
}

// encryptLoginTOTPSecret mirrors what the frontend produces — AES-GCM
// under K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1"). The
// envelope shape is version(1) || nonce(12) || ct+tag (see
// internal/crypto/aead.go), matching the storage layout.
func encryptLoginTOTPSecret(authKey []byte, plaintext []byte) (envelope, nonce []byte, err error) {
	buf, err := auth.DeriveLoginTOTPKey(authKey)
	if err != nil {
		return nil, nil, err
	}
	defer buf.Destroy()
	nonce = make([]byte, 12)
	if _, err := readFullRandom(nonce); err != nil {
		return nil, nil, err
	}
	envelope, err = srvcrypto.AESGCMSeal(buf.Bytes(), nonce, plaintext, []byte(auth.LoginTOTPAAD))
	if err != nil {
		return nil, nil, err
	}
	return envelope, nonce, nil
}

// computeTOTPCode is a tiny, self-contained RFC-6238 generator. We can't
// reach the package-private generator in internal/auth from this test
// binary; reimplementing it is cheaper than re-exporting a test-only
// helper, and the RFC math is short.
func computeTOTPCode(t *testing.T, secretBase32 string, now time.Time) string {
	t.Helper()
	cleaned := strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secretBase32)
	cleaned = strings.ToUpper(cleaned)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		t.Fatalf("decode base32 secret: %v", err)
	}
	counter := uint64(now.Unix() / 30)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]&0xff) << 16) |
		(uint32(sum[off+2]&0xff) << 8) |
		uint32(sum[off+3]&0xff)
	v %= 1_000_000
	return fmt.Sprintf("%06d", v)
}

// readFullRandom fills b with cryptographically-random bytes. Wrapped so
// each test doesn't have to import crypto/rand.
func readFullRandom(b []byte) (int, error) {
	return rand.Read(b) //nolint:gosec
}

// poolFor returns the pgxpool the test server was wired with. We bypass
// RLS via app.bypass_rls so fixture rows can be inserted under the
// caller's user_id without first running through the auth middleware.
func poolFor(t *testing.T, srv *httptest.Server) *pgxpool.Pool {
	t.Helper()
	v, ok := testServerPools.Load(srv)
	if !ok {
		t.Fatal("test server pool not registered — was startTestServer used?")
	}
	return v.(*pgxpool.Pool)
}

// insertFakeWebAuthnCredential seeds a row in user_webauthn_credentials
// for `userID`. We don't go through a real WebAuthn ceremony — the tests
// that need this helper only care about row presence (RemoveCredential,
// EnablePasskeyUnlock, DeleteMe assertion-required path).
func insertFakeWebAuthnCredential(t *testing.T, ctx context.Context, srv *httptest.Server, userID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	pool := poolFor(t, srv)
	id := uuid.New()
	credID := randBytes(t, 32)
	publicKey := randBytes(t, 64)
	aaguid := randBytes(t, 16)
	if _, err := pool.Exec(ctx, `SET LOCAL app.bypass_rls = 'true'`); err != nil {
		// SET LOCAL outside an explicit tx is a no-op on some pool
		// configurations — fall back to a plain INSERT which is allowed
		// because the seed runs as the DB owner.
		_ = err
	}
	_, err := pool.Exec(ctx, `
INSERT INTO user_webauthn_credentials (id, user_id, name, credential_id, public_key, aaguid, sign_count, transports, flags)
VALUES ($1, $2, $3, $4, $5, $6, 0, '{}', 0)`, id, userID, name, credID, publicKey, aaguid)
	if err != nil {
		t.Fatalf("seed webauthn credential: %v", err)
	}
	return id
}

// assertCredentialExists asserts on the existence (or absence) of a
// credential row by UUID. Bypasses RLS for the read.
func assertCredentialExists(t *testing.T, ctx context.Context, srv *httptest.Server, id uuid.UUID, want bool) {
	t.Helper()
	pool := poolFor(t, srv)
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_webauthn_credentials WHERE id = $1`, id).Scan(&count); err != nil {
		t.Fatalf("count credential: %v", err)
	}
	if want && count != 1 {
		t.Fatalf("credential %s should still exist (count=%d)", id, count)
	}
	if !want && count != 0 {
		t.Fatalf("credential %s should be gone (count=%d)", id, count)
	}
}

// ptr is a tiny helper for taking the address of a literal (proto optional fields).
func ptr[T any](v T) *T { return &v }

// jsonUnmarshal is a no-import-bloat helper for the audit metadata parse.
func jsonUnmarshal(data []byte, dst any) error { return json.Unmarshal(data, dst) }

// requireConnectCode fails the test if err is nil or its Connect code
// doesn't match the expected value.
func requireConnectCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected connect.Error with code %s, got %T (%v)", want, err, err)
	}
	if cerr.Code() != want {
		t.Fatalf("expected code %s, got %s (%v)", want, cerr.Code(), err)
	}
}
