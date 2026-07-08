package postgres_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vectorcore/mme/internal/models"
	store "github.com/vectorcore/mme/internal/repository/postgres"
)

func openSQLiteTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "mme.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return db
}

func TestSQLiteStoreUpsertUEContextReattach(t *testing.T) {
	db := openSQLiteTestDB(t)
	s := store.New(db)
	ctx := context.Background()

	now := time.Now().UTC().Format(time.RFC3339)
	guti := "20495-0-1-DEADBEEF"

	first := &models.UEContext{
		MMEUES1APID:  1001,
		IMSI:         "204950000000099",
		GUTI:         &guti,
		EMMState:     "REGISTERED",
		LastModified: now,
	}
	if err := s.UpsertUEContext(ctx, first); err != nil {
		t.Fatalf("first UpsertUEContext: %v", err)
	}

	second := &models.UEContext{
		MMEUES1APID:  1002,
		IMSI:         "204950000000099",
		GUTI:         &guti,
		EMMState:     "REGISTERED",
		LastModified: now,
	}
	if err := s.UpsertUEContext(ctx, second); err != nil {
		t.Fatalf("second UpsertUEContext: %v", err)
	}

	got, err := s.GetUEContextByIMSI(ctx, "204950000000099")
	if err != nil {
		t.Fatalf("GetUEContextByIMSI: %v", err)
	}
	if got.MMEUES1APID != 1002 {
		t.Fatalf("expected MMEUES1APID=1002, got %d", got.MMEUES1APID)
	}

	ues, err := s.ListUEContexts(ctx)
	if err != nil {
		t.Fatalf("ListUEContexts: %v", err)
	}
	if len(ues) != 1 {
		t.Fatalf("expected 1 UE row, got %d", len(ues))
	}
}

func TestSQLiteStoreENBRegistration(t *testing.T) {
	db := openSQLiteTestDB(t)
	s := store.New(db)
	ctx := context.Background()

	enb := &models.ENBRegistration{
		GlobalENBID:  "001-01-000001",
		ENBName:      "test-enb",
		SupportedTAs: `[{"mcc":"001","mnc":"01","tac":1}]`,
		RemoteAddr:   "127.0.0.1:36412",
		LastSeen:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.UpsertENBRegistration(ctx, enb); err != nil {
		t.Fatalf("UpsertENBRegistration: %v", err)
	}

	enbs, err := s.ListENBRegistrations(ctx)
	if err != nil {
		t.Fatalf("ListENBRegistrations: %v", err)
	}
	if len(enbs) != 1 || enbs[0].GlobalENBID != enb.GlobalENBID {
		t.Fatalf("unexpected eNB registrations: %+v", enbs)
	}
}
