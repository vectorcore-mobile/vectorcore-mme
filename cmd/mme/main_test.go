package main

import (
	"path/filepath"
	"testing"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/models"
)

func TestOpenDBSQLite(t *testing.T) {
	db, err := openDB(config.DatabaseConfig{
		Type:     "sqlite",
		Database: filepath.Join(t.TempDir(), "mme.db"),
	})
	if err != nil {
		t.Fatalf("openDB sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
}

func TestDatabaseDialectorRejectsUnsupportedType(t *testing.T) {
	if _, err := databaseDialector(config.DatabaseConfig{Type: "mysql"}); err == nil {
		t.Fatal("expected unsupported database type error")
	}
}
