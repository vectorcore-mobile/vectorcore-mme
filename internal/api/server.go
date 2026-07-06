// Package api implements the OAM HTTP API for the MME.
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/buildinfo"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/uecontext"
)

// appVersion is set at build time via -ldflags; see internal/buildinfo.
var appVersion = buildinfo.Version

var startTime = time.Now()

// DiamStatus is a narrow interface for querying Diameter connection state.
type DiamStatus interface {
	Connected() bool
}

// Pager is implemented by the S1AP server to trigger network-initiated paging.
type Pager interface {
	PageUE(imsi string) error
}

// Server is the OAM API server.
type Server struct {
	cfg        config.APIConfig
	nfCfg      config.NFConfig
	operCfg    config.OperatorConfig
	store      repository.Repository
	enbTracker *peertracker.Tracker
	ueManager  *uecontext.Manager
	s6a        DiamStatus
	pager      Pager
	log        *zap.Logger
}

// SetPager wires the S1AP paging implementation into the API server.
func (s *Server) SetPager(p Pager) { s.pager = p }

// New creates a new API Server.
func New(
	cfg config.APIConfig,
	nfCfg config.NFConfig,
	operCfg config.OperatorConfig,
	store repository.Repository,
	enbTracker *peertracker.Tracker,
	ueManager *uecontext.Manager,
	s6a DiamStatus,
	log *zap.Logger,
) *Server {
	return &Server{
		cfg:        cfg,
		nfCfg:      nfCfg,
		operCfg:    operCfg,
		store:      store,
		enbTracker: enbTracker,
		ueManager:  ueManager,
		s6a:        s6a,
		log:        log,
	}
}

// Handler builds and returns the HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// Prometheus metrics
	r.Handle("/metrics", promhttp.Handler())

	// Liveness probe
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Redirect root to UI
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/ui/", http.StatusFound)
	})

	// Embedded React SPA — use Handle (not Mount) so /ui prefix is NOT stripped,
	// which lets uiHandler's StripPrefix work correctly for asset paths.
	r.Handle("/ui", http.RedirectHandler("/ui/", http.StatusMovedPermanently))
	ui := uiHandler()
	r.Handle("/ui/", ui)
	r.Handle("/ui/*", ui)

	// JSON API under /api/v1
	humaConfig := huma.DefaultConfig("VectorCore MME OAM API", appVersion)
	humaConfig.OpenAPIPath = "/api/v1/openapi.json"
	humaConfig.DocsPath = "/api/v1/docs"
	humaConfig.SchemasPath = "/api/v1/schemas"
	r.Route("/api/v1", func(sub chi.Router) {
		api := humachi.New(sub, humaConfig)
		registerENBHandlers(api, s)
		registerUEHandlers(api, s)
		registerOAMHandlers(api, s)
		registerOperatorHandlers(api, s)
	})

	return r
}

// Start runs the HTTP server until it errors. Blocking.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.BindPort)
	s.log.Info("api: listening", zap.String("addr", addr))

	srv := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		return srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

// StartWithContext runs the HTTP server and shuts down gracefully when ctx is cancelled.
func (s *Server) StartWithContext(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.BindPort)
	s.log.Info("api: listening", zap.String("addr", addr))

	srv := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	errCh := make(chan error, 1)
	go func() {
		if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
			errCh <- srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
