//go:build integration

// End-to-end tests for the API server. They boot the real handler stack
// (auth middleware, RLS interceptor, audit interceptor, idempotency,
// rate-limit, Connect handlers) over a real Postgres container and drive
// it through the generated Connect client. Anything that only fires at
// the SQL layer — for instance the RLS interceptor's SET LOCAL — is
// exercised here and not in any pure unit test.
//
// Run with:
//
//	go test -tags=integration ./internal/api/...
package api_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/tkcrm/mx/logger"

	obliviocrypto "github.com/sxwebdev/oblivio/internal/crypto"

	"github.com/sxwebdev/oblivio/internal/api"
	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/email"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/testutil"
)

// TestE2E_RegisterAuthorizeUnlock exercises the full unlock flow a real
// browser client walks through: Register issues tokens, GetKDFParams /
// GetMyKeys / VaultService.GetMe return the encrypted material under the
// access token. The latter three go through the RLS interceptor — the
// $1 placeholder bug in SET LOCAL would surface as SQLSTATE 42601 here.
func TestE2E_RegisterAuthorizeUnlock(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()

	ctx := context.Background()
	httpClient := srv.Client()

	authClient := obliviov1connect.NewAuthServiceClient(httpClient, srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(httpClient, srv.URL+"/api")

	const emailAddr = "e2e-user@example.com"
	authKey := randBytes(t, 32)

	regResp, err := authClient.Register(ctx, connect.NewRequest(&pb.RegisterRequest{
		Email:                   emailAddr,
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
	access := regResp.Msg.GetAuthPayload().GetAccessToken()
	if access == "" {
		t.Fatal("Register returned empty access token")
	}

	// Anonymous — must work without bearer.
	kdfResp, err := authClient.GetKDFParams(ctx, connect.NewRequest(&pb.GetKDFParamsRequest{Email: emailAddr}))
	if err != nil {
		t.Fatalf("GetKDFParams: %v", err)
	}
	if len(kdfResp.Msg.GetSaltUser()) != 16 {
		t.Fatalf("GetKDFParams returned salt of unexpected length: %d", len(kdfResp.Msg.GetSaltUser()))
	}

	// Authenticated — these route through the RLS interceptor, which is
	// where the SET LOCAL ... = $1 syntax-error bug lived. A regression
	// surfaces as a "syntax error at or near $1" SQLSTATE 42601 here.
	keysResp, err := authClient.GetMyKeys(ctx, bearer(&pb.GetMyKeysRequest{}, access))
	if err != nil {
		t.Fatalf("GetMyKeys: %v", err)
	}
	if len(keysResp.Msg.GetWrappedVaultKey()) == 0 {
		t.Fatal("GetMyKeys returned empty wrapped_vault_key")
	}

	meResp, err := vaultClient.GetMe(ctx, bearer(&pb.GetMeRequest{}, access))
	if err != nil {
		t.Fatalf("VaultService.GetMe: %v", err)
	}
	if meResp.Msg.GetEmail() != emailAddr {
		t.Fatalf("GetMe email = %q, want %q", meResp.Msg.GetEmail(), emailAddr)
	}

	// Sanity: Authorize after Register also returns a usable token.
	authResp, err := authClient.Authorize(ctx, connect.NewRequest(&pb.AuthorizeRequest{
		Email:   emailAddr,
		AuthKey: authKey,
		DeviceInfo: &pb.DeviceInfo{
			DeviceId:   "device-e2e",
			DeviceType: "web",
		},
	}))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authResp.Msg.GetMfaChallenge() != nil {
		t.Fatal("Authorize unexpectedly returned an MFA challenge")
	}
	if authResp.Msg.GetAuthPayload().GetAccessToken() == "" {
		t.Fatal("Authorize returned empty access token")
	}
}

// TestE2E_CreateProjectAndIdempotency drives the full mutating path:
// Register to get a bearer, then CreateProject through auth → idempotency
// → RLS → handler → PG. Same-key replay must succeed; same-key + different
// payload must 409. Covers everything the original CLAUDE-fixed RLS bug
// touched plus the idempotency middleware that sits in front of it.
func TestE2E_CreateProjectAndIdempotency(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()

	ctx := context.Background()
	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	projectsClient := obliviov1connect.NewProjectsServiceClient(srv.Client(), srv.URL+"/api")

	access := registerUser(t, authClient, "projects-e2e@example.com")

	projectID := uuid.NewString()
	blob := randBytes(t, 64)
	wrapped := randBytes(t, 60)
	nameHash := randBytes(t, 32)

	createReq := func() *pb.CreateProjectRequest {
		return &pb.CreateProjectRequest{
			Id:             projectID,
			EncryptedBlob:  blob,
			WrappedItemKey: wrapped,
			NameHash:       nameHash,
			SortOrder:      0,
		}
	}

	idemKey := "11111111-1111-1111-1111-111111111111"

	req1 := connect.NewRequest(createReq())
	req1.Header().Set("Authorization", "Bearer "+access)
	req1.Header().Set("Idempotency-Key", idemKey)
	resp1, err := projectsClient.CreateProject(ctx, req1)
	if err != nil {
		t.Fatalf("CreateProject(initial): %v", err)
	}
	if resp1.Msg.GetProject().GetId() == "" {
		t.Fatal("CreateProject returned project without id")
	}

	// Same key + same body — must replay the cached response, not error
	// and not create a second row.
	req2 := connect.NewRequest(createReq())
	req2.Header().Set("Authorization", "Bearer "+access)
	req2.Header().Set("Idempotency-Key", idemKey)
	resp2, err := projectsClient.CreateProject(ctx, req2)
	if err != nil {
		t.Fatalf("CreateProject(replay): %v", err)
	}
	if resp2.Msg.GetProject().GetId() != resp1.Msg.GetProject().GetId() {
		t.Fatalf("replay returned different project id: %s vs %s",
			resp2.Msg.GetProject().GetId(), resp1.Msg.GetProject().GetId())
	}

	// Same key + different body — middleware must reject with 409.
	mutated := createReq()
	mutated.EncryptedBlob = randBytes(t, 64)
	req3 := connect.NewRequest(mutated)
	req3.Header().Set("Authorization", "Bearer "+access)
	req3.Header().Set("Idempotency-Key", idemKey)
	_, err = projectsClient.CreateProject(ctx, req3)
	if err == nil {
		t.Fatal("CreateProject with reused key + different body should fail")
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeAlreadyExists && cerr.Code() != connect.CodeAborted && cerr.Code() != connect.CodeInternal && cerr.Code() != connect.CodeUnknown {
		// The middleware writes a plain http.StatusConflict (409) which
		// Connect surfaces as one of the above codes depending on framing.
		// We just want a non-nil error; the body assertion below pins the
		// concrete signal.
		t.Logf("CreateProject(conflict) error code: %s", cerr.Code())
	}
	if !strings.Contains(err.Error(), "idempotency") && !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "different payload") {
		t.Fatalf("CreateProject(conflict) error does not mention idempotency: %v", err)
	}

	// Fresh key, fresh id, fresh body — should succeed and produce a different row.
	req4 := connect.NewRequest(&pb.CreateProjectRequest{
		Id:             uuid.NewString(),
		EncryptedBlob:  randBytes(t, 64),
		WrappedItemKey: randBytes(t, 60),
		NameHash:       randBytes(t, 32),
	})
	req4.Header().Set("Authorization", "Bearer "+access)
	req4.Header().Set("Idempotency-Key", "22222222-2222-2222-2222-222222222222")
	resp4, err := projectsClient.CreateProject(ctx, req4)
	if err != nil {
		t.Fatalf("CreateProject(fresh): %v", err)
	}
	if resp4.Msg.GetProject().GetId() == resp1.Msg.GetProject().GetId() {
		t.Fatal("fresh idempotency key produced the same project id")
	}
}

// TestE2E_ProjectSealRoundTrip exercises the AAD-bound seal → CreateProject
// → ListProjects → open round-trip. The id the client uses in the AAD
// must come back unchanged from the server — otherwise the AEAD on
// encrypted_blob can never be authenticated and the row shows up as
// "(unreadable)" in the UI. Regression test for that bug.
func TestE2E_ProjectSealRoundTrip(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()

	ctx := context.Background()
	authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
	projectsClient := obliviov1connect.NewProjectsServiceClient(srv.Client(), srv.URL+"/api")
	vaultClient := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")

	access := registerUser(t, authClient, "seal-e2e@example.com")

	// vaultId is the user_id per vault-crypto.ts:vaultIdScope.
	meReq := connect.NewRequest(&pb.GetMeRequest{})
	meReq.Header().Set("Authorization", "Bearer "+access)
	me, err := vaultClient.GetMe(ctx, meReq)
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	vaultID := me.Msg.GetUserId()

	vaultKey := randBytes(t, 32)
	itemKey := randBytes(t, 32)
	projectID := uuid.NewString()
	const version = 1

	plaintext := []byte(`{"name":"E2E project","description":"round-trip"}`)
	itemAAD := []byte(fmt.Sprintf("%s|%d|%s|item", projectID, version, vaultID))
	wrapAAD := []byte(fmt.Sprintf("%s|%s|%d|wrap", vaultID, projectID, version))

	blob, err := obliviocrypto.AESGCMSeal(itemKey, randBytes(t, 12), plaintext, itemAAD)
	if err != nil {
		t.Fatalf("seal blob: %v", err)
	}
	wrapped, err := obliviocrypto.AESGCMSeal(vaultKey, randBytes(t, 12), itemKey, wrapAAD)
	if err != nil {
		t.Fatalf("seal wrapped_item_key: %v", err)
	}

	createReq := connect.NewRequest(&pb.CreateProjectRequest{
		Id:             projectID,
		EncryptedBlob:  blob,
		WrappedItemKey: wrapped,
		NameHash:       randBytes(t, 32),
		SortOrder:      0,
	})
	createReq.Header().Set("Authorization", "Bearer "+access)
	createResp, err := projectsClient.CreateProject(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if got := createResp.Msg.GetProject().GetId(); got != projectID {
		t.Fatalf("CreateProject returned id %s, want client-minted %s", got, projectID)
	}

	listReq := connect.NewRequest(&pb.ListProjectsRequest{})
	listReq.Header().Set("Authorization", "Bearer "+access)
	listResp, err := projectsClient.ListProjects(ctx, listReq)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(listResp.Msg.GetProjects()) != 1 {
		t.Fatalf("ListProjects returned %d rows, want 1", len(listResp.Msg.GetProjects()))
	}
	got := listResp.Msg.GetProjects()[0]
	if got.GetId() != projectID {
		t.Fatalf("ListProjects id = %s, want %s", got.GetId(), projectID)
	}

	// Decrypt with the SAME AAD the client baked in. If the server had
	// re-minted the id, this Open would fail and reproduce the UI bug.
	openAAD := []byte(fmt.Sprintf("%s|%d|%s|item", got.GetId(), got.GetVersion(), vaultID))
	pt, err := obliviocrypto.AESGCMOpen(itemKey, got.GetEncryptedBlob(), openAAD)
	if err != nil {
		t.Fatalf("decrypt round-trip failed (the very bug this test guards): %v", err)
	}
	var roundTrip struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(pt, &roundTrip); err != nil {
		t.Fatalf("plaintext is not JSON: %v (raw=%q)", err, pt)
	}
	if roundTrip.Name != "E2E project" {
		t.Fatalf("plaintext.name = %q, want %q", roundTrip.Name, "E2E project")
	}
}

// TestE2E_AuthRequiredOnVaultService asserts the auth middleware is wired:
// hitting an authenticated procedure without a bearer must fail with
// Unauthenticated.
func TestE2E_AuthRequiredOnVaultService(t *testing.T) {
	srv, cleanup := startTestServer(t)
	defer cleanup()

	vc := obliviov1connect.NewVaultServiceClient(srv.Client(), srv.URL+"/api")
	_, err := vc.GetMe(context.Background(), connect.NewRequest(&pb.GetMeRequest{}))
	if err == nil {
		t.Fatal("GetMe without bearer should fail")
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeUnauthenticated {
		t.Fatalf("GetMe without bearer: got %v, want Unauthenticated", err)
	}
}

// --- helpers --------------------------------------------------------------

// startTestServer boots the API handler stack against a fresh Postgres
// container and exposes it via httptest. Returned cleanup tears down
// everything; t.Cleanup is fine but we want callers to control ordering
// against the context.
func startTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	pg := testutil.NewPostgres(t)
	st := store.NewForTest(pg.Pool)

	secrets, err := auth.LoadSecrets(nil, t.TempDir(), randHex(t, 32), randHex(t, 32))
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	t.Cleanup(secrets.Close)

	tokenStore := auth.NewPGTokenStore(pg.Pool)
	authManager := auth.NewManager(secrets, st, tokenStore, time.Minute, time.Hour)

	mfaKEK, err := auth.NewMFAKEK(nil)
	if err != nil {
		t.Fatalf("NewMFAKEK: %v", err)
	}
	t.Cleanup(mfaKEK.Close)

	mfaStore, err := auth.NewMFAStore(st.MFAChallenges(), mfaKEK, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewMFAStore: %v", err)
	}
	t.Cleanup(mfaStore.Close)

	recoveryStore, err := auth.NewRecoveryStore(st.RecoverySessions(), 15*time.Minute)
	if err != nil {
		t.Fatalf("NewRecoveryStore: %v", err)
	}
	t.Cleanup(recoveryStore.Close)

	apiServer := api.New(api.Deps{
		Log:           logger.NewExtended(),
		Cfg:           config.ServerConfig{Addr: ":0"},
		Auth:          testAuthConfig(),
		Store:         st,
		AuthManager:   authManager,
		MFAStore:      mfaStore,
		RecoveryStore: recoveryStore,
		Email:         email.NewNoopSender(),
		AppName:       "OblivioTest",
	})

	srv := httptest.NewServer(apiServer.Handler())
	cleanup := func() { srv.Close() }
	return srv, cleanup
}

// testAuthConfig keeps Argon2 cheap (still RFC-9106 compliant: t≥1, p≥1,
// m ≥ 8*p) so test runtime stays in the seconds, not minutes.
func testAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
		Argon2Server: config.Argon2Params{
			T:    1,
			MKiB: 8 * 1024,
			P:    1,
		},
		RateLimits: config.RateLimits{
			AuthLoginPerEmailPerMin: 100,
			AuthLoginPerIPPerMin:    100,
			KDFParamsPerIPPerMin:    100,
			RegisterPerIPPerHour:    100,
		},
	}
}

func clientKDFParams() *pb.Argon2Params {
	return &pb.Argon2Params{T: 1, MKib: 8 * 1024, P: 1, Algo: "argon2id"}
}

// bearer wraps a Connect request with the Authorization header. Connect
// strips it from req.Msg, so we can't smuggle it through the message.
func bearer[T any](msg *T, token string) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer "+token)
	return r
}

// registerUser registers a user via the public Register RPC and returns
// the issued access token.
func registerUser(t *testing.T, c obliviov1connect.AuthServiceClient, email string) string {
	t.Helper()
	resp, err := c.Register(context.Background(), connect.NewRequest(&pb.RegisterRequest{
		Email:                   email,
		SaltUser:                randBytes(t, 16),
		KdfParams:               clientKDFParams(),
		AuthKey:                 randBytes(t, 32),
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
	tok := resp.Msg.GetAuthPayload().GetAccessToken()
	if tok == "" {
		t.Fatal("Register returned empty access token")
	}
	return tok
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := randBytes(t, n)
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, by := range b {
		out[i*2] = hex[by>>4]
		out[i*2+1] = hex[by&0xf]
	}
	return string(out)
}

