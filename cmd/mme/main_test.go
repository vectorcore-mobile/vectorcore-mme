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
		Mode:     "persistent",
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

func TestDatabaseModeDefaultsToPersistent(t *testing.T) {
	if got := databaseMode(config.DatabaseConfig{}); got != "persistent" {
		t.Fatalf("databaseMode default got %q, want persistent", got)
	}
}

func TestBuildRepositoryMemoryMode(t *testing.T) {
	repo, err := buildRepository(config.DatabaseConfig{Mode: "memory"}, zap.NewNop(), "test-epoch")
	if err != nil {
		t.Fatalf("buildRepository memory: %v", err)
	}
	if _, ok := repo.(noopRepository); !ok {
		t.Fatalf("repository type got %T, want noopRepository", repo)
	}
}

// Bug #7: after an MME-only restart in persistent mode, new sessions must not
// get the TEIDs of recovered sessions (the counter used to restart at 1),
// and the restart counter is kept in the database so the S-GW keeps the
// sessions the MME recovers. Memory mode uses the configured counter as is.
func TestInitS11RestartSeedsAboveRecoveredTEIDs(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Database = config.DatabaseConfig{Mode: "persistent", Database: filepath.Join(dir, "mme.db")}
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

	mem := &config.Config{}
	mem.Database = config.DatabaseConfig{Mode: "memory"}
	mem.S11.RecoveryRestartCounter = 3
	for start := 0; start < 3; start++ {
		c := *mem
		initS11Restart(&c, noopRepository{}, zap.NewNop())
		if c.S11.RecoveryRestartCounter != 3 {
			t.Fatalf("memory-mode restart counter %d, want configured 3", c.S11.RecoveryRestartCounter)
		}
	}
}

func TestWarnDeprecatedNFOrigin(t *testing.T) {
	diameter := config.DiameterConfig{OriginHost: "mme.example", OriginRealm: "example"}
	for _, tc := range []struct {
		name    string
		nf      config.NFConfig
		want    int
		differs bool
	}{
		{name: "absent", nf: config.NFConfig{}, want: 0},
		{name: "same", nf: config.NFConfig{LegacyOriginHost: "mme.example", LegacyOriginRealm: "example"}, want: 1},
		{name: "host only same", nf: config.NFConfig{LegacyOriginHost: "mme.example"}, want: 1},
		{name: "different", nf: config.NFConfig{LegacyOriginHost: "old.example", LegacyOriginRealm: "example"}, want: 1, differs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			warnDeprecatedNFOrigin(config.Config{NF: tc.nf, Diameter: diameter}, zap.New(core))
			if got := logs.Len(); got != tc.want {
				t.Fatalf("warnings = %d, want %d", got, tc.want)
			}
			if tc.want == 0 {
				return
			}
			msg := logs.All()[0].Message
			if got := strings.Contains(msg, "differ"); got != tc.differs {
				t.Fatalf("message %q: mentions differ = %v, want %v", msg, got, tc.differs)
			}
		})
	}
}
