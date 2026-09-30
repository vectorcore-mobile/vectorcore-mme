package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/vectorcore/mme/internal/config"
	s11client "github.com/vectorcore/mme/internal/gtpv2/s11"
	"github.com/vectorcore/mme/internal/models"
)

func TestOpenDBSQLite(t *testing.T) {
	db, err := openDB(config.DatabaseConfig{
		Database: filepath.Join(t.TempDir(), "mme.db"),
	})
	if err != nil {
		t.Fatalf("openDB sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
}

func TestDatabaseDialectorDefaultsFilename(t *testing.T) {
	if got := databaseDialector(config.DatabaseConfig{}); got == nil {
		t.Fatal("expected a non-nil sqlite dialector for an empty database path")
	}
}

// An install that never used a database (formerly memory mode) may not have
// the database directory yet; openDB creates it.
func TestOpenDBCreatesMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "var", "lib", "mme.db")
	db, err := openDB(config.DatabaseConfig{Database: path})
	if err != nil {
		t.Fatalf("openDB with missing directory: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file not created: %v", err)
	}
}

// database.mode is deprecated: any value is ignored with one warning, and
// "memory" no longer selects an in-memory store.
func TestDeprecatedDatabaseModeWarnsAndUsesSQLite(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		wantWarn bool
		wantText string
	}{
		{mode: "", wantWarn: false},
		{mode: "persistent", wantWarn: true, wantText: "deprecated and ignored"},
		{mode: "memory", wantWarn: true, wantText: "no longer supported"},
		{mode: " Memory ", wantWarn: true, wantText: "no longer supported"},
	} {
		t.Run(fmt.Sprintf("mode=%q", tc.mode), func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			log := zap.New(core)
			dbCfg := config.DatabaseConfig{Mode: tc.mode, Database: filepath.Join(t.TempDir(), "mme.db")}

			warnDeprecatedDatabaseMode(dbCfg, log)
			if got := logs.Len(); (got == 1) != tc.wantWarn || got > 1 {
				t.Fatalf("warnings logged = %d, want warning %v", got, tc.wantWarn)
			}
			if tc.wantWarn && !strings.Contains(logs.All()[0].Message, tc.wantText) {
				t.Fatalf("warning %q does not contain %q", logs.All()[0].Message, tc.wantText)
			}

			store, err := buildRepository(dbCfg, log, "test-epoch")
			if err != nil {
				t.Fatalf("buildRepository: %v", err)
			}
			if _, ok := store.(mmeStateStore); !ok {
				t.Fatalf("repository type %T is not the SQLite store", store)
			}
			cfg := &config.Config{Database: dbCfg}
			cfg.S11.RecoveryRestartCounter = 7
			initS11Restart(cfg, store, zap.NewNop())
			saved, err := store.(mmeStateStore).GetMMEState(context.Background(), models.MMEStateGTPCRestartCounter)
			if err != nil || saved != "7" {
				t.Fatalf("restart counter in database = %q err %v, want \"7\"", saved, err)
			}
		})
	}
}

// Bug #7: after an MME-only restart, new sessions must not get the TEIDs of
// recovered sessions (the counter used to restart at 1), and the restart
// counter is kept in the database so the S-GW keeps the sessions the MME
// recovers.
func TestInitS11RestartSeedsAboveRecoveredTEIDs(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Database = config.DatabaseConfig{Database: filepath.Join(dir, "mme.db")}
	cfg.S11.RecoveryRestartCounter = 3

	store, err := buildRepository(cfg.Database, zap.NewNop(), "epoch-1")
	if err != nil {
		t.Fatalf("buildRepository: %v", err)
	}
	for i, teid := range []uint32{1, 2, 900} {
		rec := &models.SessionRecoveryRecord{IMSI: fmt.Sprintf("00101000000000%d", i), APN: "internet", MMES11TEID: teid}
		if err := store.UpsertSessionRecoveryRecord(context.Background(), rec); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}

	for start := 1; start <= 2; start++ {
		c := *cfg
		if start == 2 {
			c.S11.RecoveryRestartCounter = 99 // config edited: the saved value wins
		}
		initS11Restart(&c, store, zap.NewNop())
		if c.S11.RecoveryRestartCounter != 3 {
			t.Fatalf("persistent start %d: restart counter %d, want 3 (kept)", start, c.S11.RecoveryRestartCounter)
		}
		if teid := s11client.AllocateTEID(); teid <= 900 {
			t.Fatalf("persistent start %d: first new TEID %d collides with recovered range (max 900)", start, teid)
		}
	}
	saved, err := store.(mmeStateStore).GetMMEState(context.Background(), models.MMEStateGTPCRestartCounter)
	if err != nil || saved != "3" {
		t.Fatalf("restart counter in database = %q err %v, want \"3\"", saved, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("files next to the database: %v, want only mme.db", entries)
	}
}
