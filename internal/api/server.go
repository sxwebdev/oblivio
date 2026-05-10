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
	"github.com/tkcrm/mx/launcher/ops"
	"github.com/tkcrm/mx/logger"

	oblivio "github.com/sxwebdev/oblivio"
	apiaudit "github.com/sxwebdev/oblivio/internal/api/audit"
	apiauth "github.com/sxwebdev/oblivio/internal/api/auth"
	apientries "github.com/sxwebdev/oblivio/internal/api/entries"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	apiprojects "github.com/sxwebdev/oblivio/internal/api/projects"
	apivault "github.com/sxwebdev/oblivio/internal/api/vault"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/store"
)

// Server hosts the ConnectRPC API and the embedded WebUI on a single port.
type Server struct {
	log   logger.ExtendedLogger
	cfg   config.ServerConfig
	auth  config.AuthConfig
	store *store.Store
	am    *auth.Manager
	srv   *http.Server
	errCh chan error
}

// New constructs the API server. It does not start listening — call Start.
func New(log logger.ExtendedLogger, cfg config.ServerConfig, authCfg config.AuthConfig, am *auth.Manager, st *store.Store) *Server {
	return &Server{
		log:   log,
		cfg:   cfg,
		auth:  authCfg,
		store: st,
		am:    am,
		errCh: make(chan error, 1),
	}
}

// Name returns the service name for the launcher.
func (s *Server) Name() string { return "api" }

// idempotentProcedures lists the procedures that respect the
// Idempotency-Key header (mutating endpoints).
var idempotentProcedures = map[string]struct{}{
	"/oblivio.v1.ProjectsService/CreateProject":   {},
	"/oblivio.v1.ProjectsService/UpdateProject":   {},
	"/oblivio.v1.ProjectsService/DeleteProject":   {},
	"/oblivio.v1.ProjectsService/ReorderProjects": {},
	"/oblivio.v1.EntriesService/CreateEntry":      {},
	"/oblivio.v1.EntriesService/UpdateEntry":      {},
	"/oblivio.v1.EntriesService/DeleteEntry":      {},
}

// Start binds the HTTP listener and serves until Stop is called.
func (s *Server) Start(ctx context.Context) error {
	auditWriter := audit.NewWriter(s.store.Pool())

	rlsInterceptor := middleware.NewRLSInterceptor(s.store.Pool())
	auditInterceptor := middleware.NewAuditInterceptor(auditWriter, middleware.DefaultAuditProcedures)
	interceptors := connect.WithInterceptors(rlsInterceptor, auditInterceptor)

	rpcMux := http.NewServeMux()

	authSvc := apiauth.NewService(s.store, s.am, s.auth, auditWriter)
	rpcMux.Handle(obliviov1connect.NewAuthServiceHandler(authSvc))

	projectsSvc := apiprojects.NewService()
	rpcMux.Handle(obliviov1connect.NewProjectsServiceHandler(projectsSvc, interceptors))

	entriesSvc := apientries.NewService()
	rpcMux.Handle(obliviov1connect.NewEntriesServiceHandler(entriesSvc, interceptors))

	auditSvc := apiaudit.NewService()
	rpcMux.Handle(obliviov1connect.NewAuditServiceHandler(auditSvc, interceptors))

	vaultSvc := apivault.NewService()
	rpcMux.Handle(obliviov1connect.NewVaultServiceHandler(vaultSvc, interceptors))

	authMW := middleware.NewAuthMiddleware(s.am)
	idempotencyMW := middleware.NewIdempotencyMiddleware(s.store, middleware.IdempotencyConfig{
		Procedures: idempotentProcedures,
	})

	// Outer-to-inner: authn → idempotency → rpcMux. authn populates the
	// user_id; idempotency reads it; the connect handlers run last with the
	// RLS interceptor opening a tx per call.
	wrappedRPC := authMW.Wrap(idempotencyMW.Wrap(rpcMux))

	// All ConnectRPC procedures are served under the `/api` prefix so the
	// Vite dev proxy (`/api` → :8080) and the embedded prod UI share a
	// single same-origin contract. StripPrefix keeps the inner mux and
	// middleware procedure keys as the canonical `/oblivio.v1.*` paths.
	apiHandler := http.StripPrefix("/api", wrappedRPC)
	root := http.NewServeMux()
	root.Handle("/api/oblivio.v1.AuthService/", apiHandler)
	root.Handle("/api/oblivio.v1.ProjectsService/", apiHandler)
	root.Handle("/api/oblivio.v1.EntriesService/", apiHandler)
	root.Handle("/api/oblivio.v1.AuditService/", apiHandler)
	root.Handle("/api/oblivio.v1.VaultService/", apiHandler)
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

	handler := http.Handler(root)

	s.srv = &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           securityHeaders(handler),
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

// securityHeaders applies a baseline set of safety headers to every response.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; img-src 'self' data:; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "+
				"form-action 'self'; object-src 'none'")
		hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
		hdr.Set("Cross-Origin-Embedder-Policy", "require-corp")
		hdr.Set("Cross-Origin-Resource-Policy", "same-origin")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("Permissions-Policy", "clipboard-read=(self), clipboard-write=(self), interest-cohort=()")
		h.ServeHTTP(w, r)
	})
}
