package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/vectorcore/mme/internal/api"
	"github.com/vectorcore/mme/internal/buildinfo"
	"github.com/vectorcore/mme/internal/config"
	s6a "github.com/vectorcore/mme/internal/diameter/s6a"
	"github.com/vectorcore/mme/internal/gateway"
	s10server "github.com/vectorcore/mme/internal/gtpv2/s10"
	s11client "github.com/vectorcore/mme/internal/gtpv2/s11"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	dbstore "github.com/vectorcore/mme/internal/repository/postgres"
	"github.com/vectorcore/mme/internal/s1ap"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/sbcap"
	"github.com/vectorcore/mme/internal/sls"
	smsservice "github.com/vectorcore/mme/internal/sms"
	"github.com/vectorcore/mme/internal/uecontext"
	"github.com/vectorcore/mme/internal/vlr"
)

func main() {
	cfgPath := flag.String("c", "config/mme.yaml", "path to config file")
	showVersion := flag.Bool("v", false, "print version information and exit")
	debugConsole := flag.Bool("d", false, "enable debug logging on the console")
	flag.Parse()

	if *showVersion {
		fmt.Printf("VectorCore-MME %s\n", buildinfo.Version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log := buildLogger(cfg.Logging, *debugConsole)
	defer func() { _ = log.Sync() }()

	fmt.Println("Starting VectorCore-MME")
	log.Info("VectorCore MME starting",
		zap.String("version", buildinfo.Version),
		zap.String("origin_host", cfg.NF.OriginHost),
		zap.String("origin_realm", cfg.NF.OriginRealm))
	log.Info("nas feature configuration",
		zap.Bool("ims_voice_over_ps", cfg.NAS.EPSNetworkFeatureSupport.IMSVoiceOverPS))

	restartEpoch := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	store, err := buildRepository(cfg.Database, log, restartEpoch)
	if err != nil {
		log.Fatal("database init failed", zap.Error(err))
	}

	if databaseMode(cfg.Database) == "memory" {
		log.Info("database disabled; using in-memory repository mode")
	} else {
		if n, err := store.MarkRecoveryRecordsStaleAfterRestart(context.Background(), restartEpoch); err != nil {
			log.Warn("database recovery stale marking failed", zap.Error(err))
		} else {
			log.Info("database recovery records marked stale",
				zap.String("restart_epoch", restartEpoch),
				zap.Int64("records_marked", n))
		}
	}
	ueManager := uecontext.NewManager()
	enbTracker := peertracker.New()

	errCh := make(chan error, 4)

	// S6a Diameter client (connects to HSS)
	s6aHandlers := s6a.NewHandlers(cfg.S6a, cfg.Diameter, cfg.NF, ueManager, nil, log)
	s6aHandlers.SetS13Enabled(cfg.S13.Enabled)
	s6aHandlers.SetS13Config(cfg.S13)
	s6aHandlers.SetSGdEnabled(cfg.SGd.Enabled)
	s6aHandlers.SetSGdConfig(cfg.SGd)
	s6aHandlers.SetSLgEnabled(cfg.SLg.Enabled)
	s6aHandlers.SetSLgConfig(cfg.SLg)
	var slsTransport *sls.SCTPTransport
	var slsProvider *sls.Provider
	var slsCancel context.CancelFunc
	if cfg.SLs.Enabled {
		slsCtx, cancelSLs := context.WithCancel(context.Background())
		slsCancel = cancelSLs
		slsTransport = sls.NewSCTPTransport(cfg.SLs, log)
		slsProvider = sls.NewProvider(cfg.SLs.RequestTimeout, cfg.SLs.MaxTransactions, slsTransport, log)
		slsTransport.SetHandlers(func(b []byte) {
			if err := slsProvider.HandleInbound(b); err != nil {
				log.Warn("sls: inbound PDU rejected", zap.Error(err))
			}
		}, slsProvider.AssociationLost)
		s6aHandlers.SetSLsProvider(slsProvider)
		slsTransport.Start(slsCtx)
	}
	var s6aClient s1ap.S6aClient = s6aHandlers

	// S11 GTPv2-C client (connects to S-GW)
	c, err := s11client.NewClient(cfg.S11, log)
	if err != nil {
		log.Fatal("s11: init failed", zap.Error(err))
	}
	var s11c s1ap.S11Client = c
	var s11LocalIP []byte = net.ParseIP("127.0.0.1").To4()
	var pgwIP []byte
	if ip := net.ParseIP(cfg.S11.BindAddress).To4(); ip != nil {
		s11LocalIP = ip
	}
	if ip := net.ParseIP(strings.Split(cfg.GatewaySelection.PGW.PGWAddress, ":")[0]).To4(); ip != nil {
		pgwIP = ip
	}
	go func() { errCh <- c.Start() }()
	// Wire s11 → s1ap result callbacks after s1apSrv is created below.

	// S10 GTPv2-C server (inter-MME context transfer)
	var s10c s1ap.S10Client = s1ap.NoopS10Client{}
	var s10Srv *s10server.Server
	if cfg.S10.Enabled {
		srv, err := s10server.NewServer(cfg.S10, log)
		if err != nil {
			log.Fatal("s10: init failed", zap.Error(err))
		}
		s10Srv = srv
		s10c = srv
		// Handler is wired after s1apSrv is created below.
		go func() { errCh <- srv.Start() }()
	}

	// S1AP server (accepts eNB SCTP connections)
	gatewaySelector := gateway.NewSelector(*cfg, log)
	s1apSrv := s1ap.NewServer(cfg.S1AP, cfg.NF, cfg.Security, cfg.S10, cfg.NAS, cfg.EMMTimers, cfg.Paging, cfg.Operator, store, ueManager, enbTracker, s6aClient, s10c, s11c, s11LocalIP, pgwIP, log)
	s1apSrv.SetRecoveryEpoch(restartEpoch)
	s1apSrv.SetPersistentRecovery(databaseMode(cfg.Database) != "memory")
	s1apSrv.SetGatewaySelector(gatewaySelector)
	s1apSrv.SetSGdConfig(cfg.SGd)
	s1apSrv.SetSGsConfig(cfg.SGs)
	s1apSrv.SetSMSConfig(cfg.SMS)
	var vlrMgr *vlr.Manager
	var vlrCancel context.CancelFunc
	if cfg.SGs.Enabled {
		vlrCtx, cancelVLR := context.WithCancel(context.Background())
		vlrCancel = cancelVLR
		vlrMgr = vlr.New(cfg.SGs, s1apSrv.MMEFQDNForSGs(), s1apSrv, log)
		s1apSrv.SetVLRManager(vlrMgr)
		vlrMgr.Start(vlrCtx)
	}
	s1apSrv.SetRoamingConfig(cfg.Roaming)
	if slsProvider != nil {
		slsProvider.SetLPPaRelay(s1apSrv)
		s1apSrv.SetLPPaSink(slsProvider)
		s1apSrv.SetLPPSink(slsProvider)
	}
	if cfg.SGd.Enabled {
		s1apSrv.SetSMSService(smsservice.New(s6aHandlers))
		s1apSrv.SetSMSTransactionTimeout(cfg.SGd.TransactionTimeout)
	}

	// Wire result callbacks
	s6aHandlers.SetResultHandler(s1apSrv)
	s6aHandlers.SetDetachFn(s1apSrv.HandleNetworkDetach)
	c.SetHandler(s1apSrv)
	if cfg.S10.Enabled {
		if srv, ok := s10c.(*s10server.Server); ok {
			srv.SetHandler(s1apSrv)
		}
	}

	go func() { errCh <- s1apSrv.Start() }()
	var sbcapSrv *sbcap.Server
	if cfg.SBcAP.Enabled {
		sbcapSrv = sbcap.NewServer(cfg.SBcAP, log, func(peer string, data []byte) {
			decision := sbcap.DecideInbound(data)
			p, decodeErr := sbcap.Decode(data)
			if decodeErr != nil {
				metrics.SBcAPDecodeFailuresTotal.Inc()
				log.Warn("sbcap: rejected malformed PDU", zap.String("peer", peer), zap.Error(decodeErr))
				if response, buildErr := sbcap.BuildErrorIndication(13); buildErr == nil {
					_ = sbcapSrv.Send(peer, response)
				}
				return
			}
			metrics.SBcAPMessagesTotal.WithLabelValues("rx", fmt.Sprintf("%d", p.ProcedureCode), "received").Inc()
			if !decision.Continue {
				metrics.SBcAPValidationFailuresTotal.WithLabelValues("warning-request").Inc()
				if decision.Response == sbcap.ResponseClass1 {
					if messageID, serial, ok := sbcap.WarningIdentity(p); ok {
						if response, buildErr := sbcap.BuildWarningResponseWithDiagnostics(p.ProcedureCode, messageID, serial, decision.Cause, *decision.Diagnostics); buildErr == nil {
							_ = sbcapSrv.Send(peer, response)
						}
					}
				} else if decision.Response == sbcap.ResponseErrorIndication {
					if response, buildErr := sbcap.BuildErrorIndicationWithDiagnostics(decision.Cause, decision.Diagnostics); buildErr == nil {
						_ = sbcapSrv.Send(peer, response)
					}
				}
				return
			}
			req := decision.Request
			cause := uint8(0) // message-accepted
			if _, err := s1apSrv.SendSBcAPWarningForPeer(peer, p.ProcedureCode, req, cfg.SBcAP.TransactionTimeout); err != nil {
				cause = 4 // tracking-area-not-valid / no routable target
				log.Warn("sbcap: warning request not routed", zap.String("peer", peer), zap.Error(err))
			}
			var response []byte
			var buildErr error
			if decision.Diagnostics != nil {
				response, buildErr = sbcap.BuildWarningResponseWithDiagnostics(p.ProcedureCode, req.MessageIdentifier, req.SerialNumber, cause, *decision.Diagnostics)
			} else {
				response, buildErr = sbcap.BuildWarningResponse(p.ProcedureCode, req.MessageIdentifier, req.SerialNumber, cause, nil)
			}
			if buildErr != nil {
				log.Error("sbcap: response encode failed", zap.Error(buildErr))
				return
			}
			if err := sbcapSrv.Send(peer, response); err != nil {
				log.Warn("sbcap: response send failed", zap.String("peer", peer), zap.Error(err))
			}
		})
		s1apSrv.SetPWSIndicationSender(func(peer string, payload []byte) {
			if err := sbcapSrv.Send(peer, payload); err != nil {
				log.Warn("sbcap: indication send failed", zap.String("peer", peer), zap.Error(err))
			}
		})
		s1apSrv.SetPWSForwarder(func(procedure uint8, ies []pdu.ProtocolIE) {
			values := make(map[uint16][]byte, len(ies))
			for _, ie := range ies {
				values[ie.ID] = ie.Value
			}
			payload, err := sbcap.BuildPWSNetworkIndication(procedure, values)
			if err != nil {
				fields := []zap.Field{zap.Error(err), zap.Uint8("s1ap_procedure", procedure)}
				// PWS Restart/Failure contain only network identity and cell/area
				// state, not warning content. Preserve their raw IE encodings at
				// debug level so future interoperability failures are reproducible.
				if procedure == pdu.ProcPWSRestartIndication || procedure == pdu.ProcPWSFailureIndication {
					for _, ie := range ies {
						fields = append(fields, zap.String(fmt.Sprintf("ie_%d_hex", ie.ID), fmt.Sprintf("%x", ie.Value)))
					}
				}
				log.Warn("sbcap: PWS indication translation failed", fields...)
				return
			}
			sbcapSrv.Broadcast(payload)
		})
		go func() { errCh <- sbcapSrv.Listen() }()
	}
	go func() { errCh <- s6aHandlers.Start() }()

	var apiSrv *api.Server
	if cfg.API.Enabled {
		apiSrv = api.New(cfg.API, cfg.NF, cfg.Operator, store, enbTracker, ueManager, s6aHandlers, log)
		apiSrv.SetPager(s1apSrv)
		apiSrv.SetGatewaySelector(gatewaySelector)
		if vlrMgr != nil {
			apiSrv.SetVLRStatus(vlrMgr)
		}
		if sbcapSrv != nil {
			apiSrv.SetSBcAPStatus(sbcapSrv)
		}
		if slsTransport != nil {
			apiSrv.SetSLsStatus(slsTransport, cfg.SLs)
		}
		go func() { errCh <- apiSrv.Start() }()
	}

	// Wait for fatal error or OS signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatal("component exited", zap.Error(err))
	case sig := <-sigCh:
		log.Info("mme: shutting down", zap.String("signal", sig.String()))
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if apiSrv != nil {
			if err := apiSrv.Shutdown(shutCtx); err != nil {
				log.Warn("mme: API server shutdown error", zap.Error(err))
			}
		}
		if slsCancel != nil {
			slsCancel()
		}
		if slsProvider != nil {
			slsProvider.Close()
		}
		if slsTransport != nil {
			_ = slsTransport.Close()
		}
		if vlrCancel != nil {
			vlrCancel()
		}
		if vlrMgr != nil {
			vlrMgr.Close()
		}
		s6aHandlers.ShutdownSLg()
		s1apSrv.Shutdown(shutCtx)
		if s10Srv != nil {
			if err := s10Srv.Close(); err != nil {
				log.Warn("mme: S10 close error", zap.Error(err))
			}
		}
		if err := s6aHandlers.Close(); err != nil {
			log.Warn("mme: diameter peer manager close error", zap.Error(err))
		}
		if sbcapSrv != nil {
			if err := sbcapSrv.Close(); err != nil {
				log.Warn("mme: SBc-AP close error", zap.Error(err))
			}
		}
		if err := c.Close(); err != nil {
			log.Warn("mme: s11 close error", zap.Error(err))
		}
		log.Info("mme: shutdown complete")
	}
}

func buildLogger(cfg config.LoggingConfig, debugConsole bool) *zap.Logger {
	fileLevel := zapcore.InfoLevel
	if err := fileLevel.UnmarshalText([]byte(cfg.Level)); err != nil {
		fileLevel = zapcore.InfoLevel
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	cores := make([]zapcore.Core, 0, 3)

	if cfg.File != "" {
		fileSink, _, err := zap.Open(cfg.File)
		if err != nil {
			panic(fmt.Sprintf("failed to open log file: %v", err))
		}
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), fileSink, zap.LevelEnablerFunc(func(level zapcore.Level) bool {
			return level >= fileLevel
		})))
	}

	if debugConsole {
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.Lock(os.Stdout), zap.DebugLevel))
	} else {
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.Lock(os.Stderr), zap.FatalLevel))
	}

	return zap.New(zapcore.NewTee(cores...), zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}

func openDB(cfg config.DatabaseConfig) (*gorm.DB, error) {
	dialector, err := databaseDialector(cfg)
	if err != nil {
		return nil, err
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("gorm sql.DB: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)
	}

	return db, nil
}

func buildRepository(cfg config.DatabaseConfig, log *zap.Logger, restartEpoch string) (repository.Repository, error) {
	if databaseMode(cfg) == "memory" {
		return noopRepository{}, nil
	}
	db, err := openDB(cfg)
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		return nil, fmt.Errorf("database migrate failed: %w", err)
	}
	log.Info("database persistent mode enabled",
		zap.String("mode", databaseMode(cfg)),
		zap.String("db_type", strings.ToLower(strings.TrimSpace(cfg.Type))),
		zap.String("restart_epoch", restartEpoch))
	return dbstore.New(db), nil
}

func databaseMode(cfg config.DatabaseConfig) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		return "persistent"
	}
	return mode
}

func databaseDialector(cfg config.DatabaseConfig) (gorm.Dialector, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Type)) {
	case "", "postgres", "postgresql":
		dsn := fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database,
		)
		return postgres.Open(dsn), nil
	case "sqlite", "sqlite3":
		dsn := cfg.Database
		if dsn == "" {
			dsn = "mme.db"
		}
		return sqlite.Open(dsn), nil
	default:
		return nil, fmt.Errorf("unsupported database db_type %q", cfg.Type)
	}
}

type noopRepository struct{}

func (noopRepository) UpsertUERecoveryRecord(_ context.Context, _ *models.UERecoveryRecord) error {
	return nil
}
func (noopRepository) GetUERecoveryByIMSI(_ context.Context, _ string) (*models.UERecoveryRecord, error) {
	return nil, repository.ErrNotFound
}
func (noopRepository) GetUERecoveryByGUTI(_ context.Context, _ string) (*models.UERecoveryRecord, error) {
	return nil, repository.ErrNotFound
}
func (noopRepository) ListUERecoveryRecords(_ context.Context, _ repository.UERecoveryFilter) ([]models.UERecoveryRecord, error) {
	return nil, nil
}
func (noopRepository) DeleteUERecoveryRecordsByIMSI(_ context.Context, _ []string) error { return nil }
func (noopRepository) MarkRecoveryRecordsStaleAfterRestart(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (noopRepository) UpsertSessionRecoveryRecord(_ context.Context, _ *models.SessionRecoveryRecord) error {
	return nil
}
func (noopRepository) ListSessionRecoveryRecords(_ context.Context, _ string) ([]models.SessionRecoveryRecord, error) {
	return nil, nil
}
func (noopRepository) AppendRecoveryEvent(_ context.Context, _ *models.RecoveryEvent) error {
	return nil
}
func (noopRepository) ListRecoveryEvents(_ context.Context, _ string, _ int) ([]models.RecoveryEvent, error) {
	return nil, nil
}
func (noopRepository) UpsertENBRegistration(_ context.Context, _ *models.ENBRegistration) error {
	return nil
}
func (noopRepository) DeleteENBRegistration(_ context.Context, _ string) error { return nil }
func (noopRepository) ListENBRegistrations(_ context.Context) ([]models.ENBRegistration, error) {
	return nil, nil
}
