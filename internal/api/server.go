// Package api implements the OAM HTTP API for the MME.
package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/buildinfo"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/uecontext"
)

// appVersion is set at build time via -ldflags; see internal/buildinfo.
var appVersion = buildinfo.Version

var startTime = time.Now()

const apiPrefix = "/api/v1"

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
	gatewaySel *gateway.Selector
	log        *zap.Logger

	mu      sync.Mutex
	httpSrv *http.Server
}

// SetPager wires the S1AP paging implementation into the API server.
func (s *Server) SetPager(p Pager) { s.pager = p }

// SetGatewaySelector wires gateway DNS cache inspection and control into the API server.
func (s *Server) SetGatewaySelector(selector *gateway.Selector) { s.gatewaySel = selector }

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

	// JSON API under /api/v1, with interactive docs mounted at /docs.
	humaConfig := huma.DefaultConfig("VectorCore MME OAM API", appVersion)
	humaConfig.OpenAPIPath = "/openapi"
	humaConfig.DocsPath = "/docs"
	humaConfig.SchemasPath = "/schemas"
	api := humachi.New(r, humaConfig)
	registerENBHandlers(api, s)
	registerUEHandlers(api, s)
	registerOAMHandlers(api, s)
	registerOperatorHandlers(api, s)
	registerRecoveryHandlers(api, s)

	return r
}

// Start runs the HTTP server until it errors or Shutdown is called. Blocking.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.BindPort)
	s.log.Info("api: listening", zap.String("addr", addr))

	srv := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}
	s.mu.Lock()
	s.httpSrv = srv
	s.mu.Unlock()

	var err error
	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		err = srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	} else {
		err = srv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown gracefully stops the HTTP server, waiting for in-flight requests
// to drain until ctx is done. Safe to call even if Start hasn't run yet.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.httpSrv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
