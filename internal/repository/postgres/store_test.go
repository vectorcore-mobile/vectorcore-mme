package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

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
	if err := db.AutoMigrate(&models.UEContext{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	// Clean slate for this test.
	db.Where("imsi LIKE ?", "204950000000%").Delete(&models.UEContext{})
	return db
}

// TestUpsertUEContextReattach verifies that a second attach for the same IMSI
// succeeds cleanly (no unique constraint violation) even when the MME restarts
// and allocates a new MMEUES1APID.
func TestUpsertUEContextReattach(t *testing.T) {
	db := openTestDB(t)
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

	// Simulate MME restart: same IMSI, new MMEUES1APID, same GUTI reallocated.
	second := &models.UEContext{
		MMEUES1APID:  1002,
		IMSI:         "204950000000099",
		GUTI:         &guti,
		EMMState:     "REGISTERED",
		LastModified: now,
	}
	if err := s.UpsertUEContext(ctx, second); err != nil {
		t.Fatalf("second UpsertUEContext (re-attach): %v", err)
	}

	// Verify only one row for this IMSI.
	var count int64
	db.Model(&models.UEContext{}).Where("imsi = ?", "204950000000099").Count(&count)
	if count != 1 {
		t.Errorf("expected 1 row after re-attach, got %d", count)
	}

	// Verify the active row is the new one.
	var got models.UEContext
	db.Where("imsi = ?", "204950000000099").First(&got)
	if got.MMEUES1APID != 1002 {
		t.Errorf("expected MMEUES1APID=1002, got %d", got.MMEUES1APID)
	}
}

// TestUpsertUEContextGUTICollision verifies that when two different IMSIs end up
// with the same GUTI (e.g., GUTI counter reset after MME restart), the second
// upsert cleanly evicts the stale row for the other IMSI.
func TestUpsertUEContextGUTICollision(t *testing.T) {
	db := openTestDB(t)
	s := store.New(db)
	ctx := context.Background()

	now := time.Now().UTC().Format(time.RFC3339)
	sharedGUTI := "20495-0-1-AABBCCDD"

	// IMSI A holds the GUTI from a previous session.
	imsiA := &models.UEContext{
		MMEUES1APID:  2001,
		IMSI:         "204950000000097",
		GUTI:         &sharedGUTI,
		EMMState:     "REGISTERED",
		LastModified: now,
	}
	if err := s.UpsertUEContext(ctx, imsiA); err != nil {
		t.Fatalf("insert IMSI A: %v", err)
	}

	// After MME restart, GUTI counter resets and the same GUTI is issued to IMSI B.
	imsiB := &models.UEContext{
		MMEUES1APID:  2002,
		IMSI:         "204950000000098",
		GUTI:         &sharedGUTI,
		EMMState:     "REGISTERED",
		LastModified: now,
	}
	if err := s.UpsertUEContext(ctx, imsiB); err != nil {
		t.Fatalf("insert IMSI B with colliding GUTI: %v", err)
	}

	// IMSI A's stale row must be gone.
	var countA int64
	db.Model(&models.UEContext{}).Where("imsi = ?", "204950000000097").Count(&countA)
	if countA != 0 {
		t.Errorf("expected stale IMSI A row to be evicted, got %d rows", countA)
	}

	// IMSI B's row must exist with the new MMEUES1APID.
	var got models.UEContext
	if err := db.Where("imsi = ?", "204950000000098").First(&got).Error; err != nil {
		t.Fatalf("get IMSI B: %v", err)
	}
	if got.MMEUES1APID != 2002 {
		t.Errorf("expected MMEUES1APID=2002, got %d", got.MMEUES1APID)
	}
}
