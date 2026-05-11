// Package api wires HTTP transport, ConnectRPC handlers and middleware.
package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"connectrpc.com/connect"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/tkcrm/mx/launcher/ops"
	"github.com/tkcrm/mx/logger"

	oblivio "github.com/sxwebdev/oblivio"
	emailpkg "github.com/sxwebdev/oblivio/internal/email"
	apiaudit "github.com/sxwebdev/oblivio/internal/api/audit"
	apiauth "github.com/sxwebdev/oblivio/internal/api/auth"
	apientries "github.com/sxwebdev/oblivio/internal/api/entries"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	apilogintotp "github.com/sxwebdev/oblivio/internal/api/login_totp"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	apiprojects "github.com/sxwebdev/oblivio/internal/api/projects"
	apisessions "github.com/sxwebdev/oblivio/internal/api/sessions"
	apivault "github.com/sxwebdev/oblivio/internal/api/vault"
	apiwebauthn "github.com/sxwebdev/oblivio/internal/api/webauthn"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/store"
)

// Server hosts the ConnectRPC API and the embedded WebUI on a single port.
type Server struct {
	log       logger.ExtendedLogger
	cfg       config.ServerConfig
	auth      config.AuthConfig
	store     *store.Store
	am        *auth.Manager
	wa        *wa.WebAuthn
	mfaStore  *auth.MFAStore
	recovery  *auth.RecoveryStore
	emailer   emailpkg.Sender
	publicURL string
	appName   string
	srv       *http.Server
	errCh     chan error
}

// Deps groups the constructor arguments. mfaStore and recovery may be nil —
// in that case the server starts the 2FA / recovery features in a degraded
// state (Authorize will still work for users without 2FA). Email is a
// noop sender by default; configure provider="smtp" or "log" in EmailConfig
// to enable verification emails.
type Deps struct {
	Log           logger.ExtendedLogger
	Cfg           config.ServerConfig
	Auth          config.AuthConfig
	Store         *store.Store
	AuthManager   *auth.Manager
	WebAuthn      *wa.WebAuthn
	MFAStore      *auth.MFAStore
	RecoveryStore *auth.RecoveryStore
	Email         emailpkg.Sender
	PublicURL     string
	AppName       string
}

// New constructs the API server. It does not start listening — call Start.
func New(d Deps) *Server {
	emailer := d.Email
	if emailer == nil {
		emailer = emailpkg.NewNoopSender()
	}
	return &Server{
		log:       d.Log,
		cfg:       d.Cfg,
		auth:      d.Auth,
		store:     d.Store,
		am:        d.AuthManager,
		wa:        d.WebAuthn,
		mfaStore:  d.MFAStore,
		recovery:  d.RecoveryStore,
		emailer:   emailer,
		publicURL: d.PublicURL,
		appName:   d.AppName,
		errCh:     make(chan error, 1),
	}
}

// Name returns the service name for the launcher.
func (s *Server) Name() string { return "api" }

// idempotentProcedures lists the procedures that respect the
// Idempotency-Key header (mutating endpoints).
var idempotentProcedures = map[string]struct{}{
	"/oblivio.v1.ProjectsService/CreateProject":             {},
	"/oblivio.v1.ProjectsService/UpdateProject":             {},
	"/oblivio.v1.ProjectsService/DeleteProject":             {},
	"/oblivio.v1.ProjectsService/ReorderProjects":           {},
	"/oblivio.v1.EntriesService/CreateEntry":                {},
	"/oblivio.v1.EntriesService/UpdateEntry":                {},
	"/oblivio.v1.EntriesService/DeleteEntry":                {},
	"/oblivio.v1.SessionsService/TerminateSession":          {},
	"/oblivio.v1.SessionsService/TerminateAllExceptCurrent": {},
	"/oblivio.v1.VaultService/DeleteMe":                     {},
}

// Start binds the HTTP listener and serves until Stop is called.
func (s *Server) Start(ctx context.Context) error {
	auditWriter := audit.NewWriter(s.store.Pool(), s.log)

	rlsInterceptor := middleware.NewRLSInterceptor(s.store.Pool())
	auditInterceptor := middleware.NewAuditInterceptor(auditWriter, middleware.DefaultAuditProcedures)
	interceptors := connect.WithInterceptors(rlsInterceptor, auditInterceptor)

	// Email-side rate limiter for AuthService — runs after deserialisation
	// so it can read req.Email regardless of content-type framing.
	rateLimitMW := middleware.NewRateLimitMiddleware(s.auth.RateLimits)
	emailRateInterceptor := middleware.NewEmailRateLimitInterceptor(rateLimitMW)
	authInterceptors := connect.WithInterceptors(emailRateInterceptor)

	rpcMux := http.NewServeMux()

	authSvc := apiauth.NewService(apiauth.Deps{
		Store:         s.store,
		AuthManager:   s.am,
		Cfg:           s.auth,
		AuditWriter:   auditWriter,
		WebAuthn:      s.wa,
		MFAStore:      s.mfaStore,
		RecoveryStore: s.recovery,
		Email:         s.emailer,
		PublicURL:     s.publicURL,
		AppName:       s.appName,
	})
	rpcMux.Handle(obliviov1connect.NewAuthServiceHandler(authSvc, authInterceptors))

	projectsSvc := apiprojects.NewService()
	rpcMux.Handle(obliviov1connect.NewProjectsServiceHandler(projectsSvc, interceptors))

	entriesSvc := apientries.NewService()
	rpcMux.Handle(obliviov1connect.NewEntriesServiceHandler(entriesSvc, interceptors))

	auditSvc := apiaudit.NewService()
	rpcMux.Handle(obliviov1connect.NewAuditServiceHandler(auditSvc, interceptors))

	vaultSvc := apivault.NewService(apivault.Deps{
		AuthManager: s.am,
		AuditWriter: auditWriter,
	})
	rpcMux.Handle(obliviov1connect.NewVaultServiceHandler(vaultSvc, interceptors))

	sessionsSvc := apisessions.NewService(auditWriter, s.am)
	rpcMux.Handle(obliviov1connect.NewSessionsServiceHandler(sessionsSvc, interceptors))

	loginTOTPSvc := apilogintotp.NewService(s.wa, s.mfaStore)
	rpcMux.Handle(obliviov1connect.NewLoginTOTPServiceHandler(loginTOTPSvc, interceptors))

	if s.wa != nil {
		webauthnSvc := apiwebauthn.NewService(s.wa, s.mfaStore, auditWriter)
		rpcMux.Handle(obliviov1connect.NewWebAuthnServiceHandler(webauthnSvc, interceptors))
	} else {
		s.log.Warnf("webauthn relying party not configured; passkeys disabled")
	}

	authMW := middleware.NewAuthMiddleware(s.am)
	idempotencyMW := middleware.NewIdempotencyMiddleware(s.store, middleware.IdempotencyConfig{
		Procedures: idempotentProcedures,
	})

	// Order matters:
	//   rate-limit (outer)   — kill abusive traffic before any work.
	//   auth                 — populate UserContext.
	//   idempotency          — needs UserContext to scope keys per user.
	//   rpcMux (innermost)   — runs interceptors then handler.
	wrappedRPC := rateLimitMW.Wrap(authMW.Wrap(idempotencyMW.Wrap(rpcMux)))

	apiHandler := http.StripPrefix("/api", wrappedRPC)
	root := http.NewServeMux()
	root.Handle("/api/oblivio.v1.AuthService/", apiHandler)
	root.Handle("/api/oblivio.v1.ProjectsService/", apiHandler)
	root.Handle("/api/oblivio.v1.EntriesService/", apiHandler)
	root.Handle("/api/oblivio.v1.AuditService/", apiHandler)
	root.Handle("/api/oblivio.v1.VaultService/", apiHandler)
	root.Handle("/api/oblivio.v1.SessionsService/", apiHandler)
	root.Handle("/api/oblivio.v1.LoginTOTPService/", apiHandler)
	root.Handle("/api/oblivio.v1.WebAuthnService/", apiHandler)
	root.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if sub, err := fs.Sub(oblivio.FrontendFS, "frontend/dist"); err == nil {
		root.Handle("/", http.FileServer(http.FS(sub)))
	} else {
		s.log.Warnf("frontend/dist not embedded: %v", err)
	}

	handler := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		HSTS: s.cfg.TLS.CertFile != "" && s.cfg.TLS.KeyFile != "",
	}, root)

	s.srv = &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	s.log.Infof("api listening on %s", s.cfg.Addr)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.errCh <- fmt.Errorf("api listen: %w", err)
		}
		close(s.errCh)
	}()

	select {
	case err := <-s.errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.srv.Shutdown(shutdownCtx)
}

// Interval is the launcher health-poll interval.
func (s *Server) Interval() time.Duration { return time.Second }

// Healthy reports readiness. Once Start binds the listener the server is healthy.
func (s *Server) Healthy(_ context.Context) error {
	if s.srv == nil {
		return fmt.Errorf("api server not started: %w", ops.ErrHealthCheckServiceStarting)
	}
	return nil
}
