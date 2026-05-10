// Package api wires HTTP transport, ConnectRPC handlers and middleware.
package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	oblivio "github.com/sxwebdev/oblivio"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/tkcrm/mx/launcher/ops"
	"github.com/tkcrm/mx/logger"

	apiauth "github.com/sxwebdev/oblivio/internal/api/auth"
)

// Server hosts the ConnectRPC API and the embedded WebUI on a single port.
type Server struct {
	log    logger.ExtendedLogger
	cfg    config.ServerConfig
	auth   config.AuthConfig
	store  *store.Store
	am     *auth.Manager
	srv    *http.Server
	errCh  chan error
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

// Start binds the HTTP listener and serves until Stop is called.
func (s *Server) Start(ctx context.Context) error {
	// ConnectRPC mux is wrapped by the authn middleware. Non-RPC paths
	// (healthz, static WebUI) are mounted on a parent mux that bypasses authn.
	rpcMux := http.NewServeMux()
	authSvc := apiauth.NewService(s.store, s.am, s.auth)
	rpcMux.Handle(obliviov1connect.NewAuthServiceHandler(authSvc))

	authMW := middleware.NewAuthMiddleware(s.am)
	wrappedRPC := authMW.Wrap(rpcMux)

	root := http.NewServeMux()
	root.Handle("/oblivio.v1.AuthService/", wrappedRPC)
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
