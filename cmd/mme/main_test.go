package main

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
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
