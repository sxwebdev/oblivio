# End-to-end tests

This document explains how to run the existing API end-to-end tests and how
to add new ones without regressing the harness.

## What an e2e test is here

Files in `internal/api/server_e2e_test.go` boot the **real** API handler
stack:

- A short-lived Postgres container (testcontainers-go, `postgres:18-alpine`)
  with every embedded migration applied.
- The full middleware chain: rate-limit → auth (Bearer) → idempotency →
  Connect interceptors (RLS, audit) → service handlers.
- A `httptest.Server` mounting `apiServer.Handler()`.
- The official generated Connect clients
  (`obliviov1connect.NewAuthServiceClient`, …) driving the server over
  HTTP, just like the browser does.

Anything that only surfaces at the SQL layer — RLS `set_config`,
idempotency `Content-Encoding` framing, AAD-bound seal/open round-trips,
unique-key violations — is meant to be exercised here rather than in a
pure unit test.

## Prerequisites

- Go 1.22+ (whatever `go.mod` pins).
- A running Docker daemon. Testcontainers reaches it via:
  - `DOCKER_HOST` env var, or
  - the default UNIX socket at `/var/run/docker.sock`.

  On Docker Desktop for macOS the socket path differs; export
  `DOCKER_HOST=unix:///var/run/docker.sock` (with the platform-specific
  path your install uses) before running tests. The harness pre-probes
  this and skips cleanly if neither is reachable.

## Build tag

All e2e tests are gated by `//go:build integration`. They are excluded
from a plain `go test ./...` so they don't slow down or fail unit-only
runs.

## Running the tests

```bash
# Everything in the package
go test -tags=integration ./internal/api/...

# One test
go test -tags=integration -run TestE2E_ProjectSealRoundTrip ./internal/api/

# Verbose, with container lifecycle logs
go test -tags=integration -v -count=1 -run TestE2E ./internal/api/

# Skip even when Docker is available (e.g. flaky CI runner)
OBLIVIO_SKIP_INTEGRATION=1 go test -tags=integration ./...

# If Ryuk (testcontainers' cleanup container) is blocked by your sandbox
TESTCONTAINERS_RYUK_DISABLED=true go test -tags=integration ./internal/api/
```

`-count=1` defeats Go's test result cache — useful when you change
behaviour but not the test body.

A first run pulls the Postgres image; subsequent runs reuse it. Each
test gets its own fresh container, so tests are isolated by default and
can run in parallel (the harness already takes care of cleanup via
`t.Cleanup`).

## File layout

```
internal/api/server_e2e_test.go    # all e2e tests + helpers
internal/testutil/pg.go            # testcontainers wrapper, migrations
internal/api/server.go             # Server.Handler() — entrypoint
```

`Server.Handler()` is the seam: it returns the same `http.Handler`
production binds to a TCP listener via `Server.Start`. Tests mount it
under `httptest` to avoid binding a real socket.

## Anatomy of an e2e test

The existing tests follow a common shape. Use them as templates.

### 1. Boot the server

```go
srv, cleanup := startTestServer(t)
defer cleanup()
```

`startTestServer` (in the same file) wires:

- a fresh PG container via `testutil.NewPostgres`,
- `auth.LoadSecrets(nil, …)` (nil logger — no warnings on stderr),
- `auth.NewManager` with cheap-but-spec-compliant Argon2 params
  (`testAuthConfig`),
- `MFAStore`, `RecoveryStore`, NoopSender for email,
- `api.New(…).Handler()` mounted on `httptest.NewServer`.

It returns the `*httptest.Server` and a `cleanup` closure. Always defer
the cleanup — it closes the HTTP server and (via `t.Cleanup`) tears the
container down.

### 2. Construct generated Connect clients

```go
authClient := obliviov1connect.NewAuthServiceClient(srv.Client(), srv.URL+"/api")
projectsClient := obliviov1connect.NewProjectsServiceClient(srv.Client(), srv.URL+"/api")
```

`srv.Client()` is an `*http.Client` already configured to talk to the
test server. The `/api` suffix matches the production `http.StripPrefix`
mount.

### 3. Register a user and capture a bearer

Most authenticated flows need a token. Use the `registerUser` helper:

```go
access := registerUser(t, authClient, "my-test@example.com")
```

It calls `Register` with valid-but-random crypto material and returns
the access token from the response's `AuthPayload`.

### 4. Issue authenticated calls

The Connect client doesn't take per-call headers in its options; attach
them on the `Request`:

```go
req := connect.NewRequest(&pb.GetMeRequest{})
req.Header().Set("Authorization", "Bearer "+access)
resp, err := vaultClient.GetMe(ctx, req)
```

For mutating idempotent procedures also set `Idempotency-Key`. There is
a `bearer[T]` generic helper in the file for the common "just attach a
bearer" case.

### 5. Assert against the response

Prefer concrete, behavioural assertions over surface checks. `t.Fatalf`
on the first divergence (later assertions usually rely on prior state).
For Connect error codes, unwrap with `errors.As(err, &cerr)` and check
`cerr.Code()`.

### 6. Decrypt round-trips when crypto is in scope

For any AAD-binding regression, do a real seal in Go using
`internal/crypto.AESGCMSeal`, send the ciphertext, fetch it back, and
open with the **same AAD** the client baked in. This is the only way
to catch bugs like the server re-minting an id and silently breaking
authentication. See `TestE2E_ProjectSealRoundTrip` for the pattern.

## Adding a new test

1. **Pick a flow that crosses ≥ 2 layers.** Pure handler logic belongs
   in a unit test; pure SQL belongs near the repo. E2E earns its keep
   when the bug only appears after the request walks the middleware
   chain plus the database.

2. **Add it to `internal/api/server_e2e_test.go`.** Keep one file for
   the API e2e suite — shared helpers (`startTestServer`,
   `registerUser`, `randBytes`, `clientKDFParams`, etc.) live there and
   splitting causes drift.

3. **Use `TestE2E_<Subject>` naming.** It makes filtering by
   `-run TestE2E` reliable.

4. **Open the file with a doc comment** stating which bug class the
   test guards. The team scans these to decide whether to extend or
   replace a test. Example:

   ```go
   // TestE2E_FooBar exercises X going through Y so that regression of
   // the Z bug (see PR #NNN) fails loudly here.
   ```

5. **Verify the test actually catches the regression.** Temporarily
   reintroduce the bug, run the test, confirm it fails with a useful
   message, then restore the fix. This is the single best signal that
   the test is non-trivial.

6. **No `t.Parallel` for now.** Each test owns a container; running
   them in parallel risks Docker resource pressure on small CI workers.
   Sequential is fine — the suite finishes in seconds.

7. **Clean up explicitly only when ordering matters.** `t.Cleanup`
   already tears down the pool and the container; the explicit
   `cleanup()` returned by `startTestServer` is there so callers can
   close the HTTP server before any pending `context`s leak. Most tests
   are fine with the deferred `cleanup()` and don't need anything else.

## What NOT to put here

- Argon2-heavy flows with production params. Cap them via
  `testAuthConfig` so test wall-clock stays in the seconds.
- Browser-only behaviour (WebAuthn ceremonies requiring a real
  authenticator). Unit-test the parsing, leave the ceremony to manual
  QA.
- Anything depending on real SMTP / external HTTP. The harness wires a
  `email.NewNoopSender`; keep it that way.
- Per-test schema mutations. The migration set is the contract; if the
  test needs a new table, that's a migration, not a test fixture.

## Troubleshooting

- **`docker not available — skipping integration test`** — start Docker
  Desktop / your daemon. The pre-probe checks for the socket; export
  `DOCKER_HOST` if your install uses a non-default path.

- **`testcontainers-go: reaper failure`** — the Ryuk container couldn't
  start (sandbox, restrictive network). Set
  `TESTCONTAINERS_RYUK_DISABLED=true`. Containers will still be cleaned
  up by `t.Cleanup`; only the safety-net post-process reaper is
  disabled.

- **`SQLSTATE 42601 syntax error at or near "$1"`** — the RLS
  interceptor regressed and is using `SET LOCAL … = $1` again instead
  of `SELECT set_config(…)`. See `internal/api/middleware/rls.go`.

- **`Backup Eligible flag inconsistency detected during login validation`**
  — a WebAuthn credential was created before migration 012 and still
  has `flags=0`. Re-register the passkey, or accept that the row is
  unusable.

- **`invalid wire-format data` on idempotency replay** — the cached
  response is missing `Content-Type` / `Content-Encoding`. The
  middleware now frames both headers into `response_body`; see
  `internal/api/middleware/idempotency.go`.

- **First test run takes 30+ seconds** — image pull. Subsequent runs
  reuse the cached image and complete in a few seconds.
