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
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	dbstore "github.com/vectorcore/mme/internal/repository/postgres"
	"github.com/vectorcore/mme/internal/s1ap"
	"github.com/vectorcore/mme/internal/uecontext"
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
	if cfg.S10.Enabled {
		srv, err := s10server.NewServer(cfg.S10, log)
		if err != nil {
			log.Fatal("s10: init failed", zap.Error(err))
		}
		s10c = srv
		// Handler is wired after s1apSrv is created below.
		go func() { errCh <- srv.Start() }()
	}

	// S1AP server (accepts eNB SCTP connections)
	gatewaySelector := gateway.NewSelector(*cfg, log)
	s1apSrv := s1ap.NewServer(cfg.S1AP, cfg.NF, cfg.Security, cfg.S10, cfg.NAS, cfg.Paging, cfg.Operator, store, ueManager, enbTracker, s6aClient, s10c, s11c, s11LocalIP, pgwIP, log)
	s1apSrv.SetRecoveryEpoch(restartEpoch)
	s1apSrv.SetGatewaySelector(gatewaySelector)

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
	go func() { errCh <- s6aHandlers.Start() }()

	if cfg.API.Enabled {
		apiSrv := api.New(cfg.API, cfg.NF, cfg.Operator, store, enbTracker, ueManager, s6aHandlers, log)
		apiSrv.SetPager(s1apSrv)
		apiSrv.SetGatewaySelector(gatewaySelector)
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
		s1apSrv.Shutdown(shutCtx)
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
