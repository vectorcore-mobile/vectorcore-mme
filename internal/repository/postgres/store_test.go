package postgres_test

import (
	"context"
	"os"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vectorcore/mme/internal/models"
	store "github.com/vectorcore/mme/internal/repository/postgres"
)

// openTestDB opens a Postgres connection using TEST_POSTGRES_DSN.
// Skips the test if the env var is not set or the connection fails.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("could not connect to Postgres (%v); skipping", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	db.Where("imsi LIKE ?", "204950000000%").Delete(&models.SessionRecoveryRecord{})
	db.Where("imsi LIKE ?", "204950000000%").Delete(&models.UERecoveryRecord{})
	return db
}

func TestPostgresUERecoveryUpsert(t *testing.T) {
	db := openTestDB(t)
	s := store.New(db)
	ctx := context.Background()

	rec := &models.UERecoveryRecord{
		IMSI:          "204950000000099",
		CallID:        1001,
		CurrentGUTI:   "20495000010100000001",
		RecoveryState: models.RecoveryStateActiveSnapshot,
		RestartEpoch:  "epoch-a",
	}
	if err := s.UpsertUERecoveryRecord(ctx, rec); err != nil {
		t.Fatalf("UpsertUERecoveryRecord: %v", err)
	}
	rec.CallID = 1002
	rec.RecoveryState = models.RecoveryStateRecovered
	if err := s.UpsertUERecoveryRecord(ctx, rec); err != nil {
		t.Fatalf("second UpsertUERecoveryRecord: %v", err)
	}
	got, err := s.GetUERecoveryByIMSI(ctx, rec.IMSI)
	if err != nil {
		t.Fatalf("GetUERecoveryByIMSI: %v", err)
	}
	if got.CallID != 1002 || got.RecoveryState != models.RecoveryStateRecovered {
		t.Fatalf("got %+v", got)
	}
}
