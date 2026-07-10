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
	"github.com/vectorcore/mme/internal/repository"
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

func TestSQLiteStoreUERecoveryUpsertAndGUTILookup(t *testing.T) {
	db := openSQLiteTestDB(t)
	s := store.New(db)
	ctx := context.Background()

	first := &models.UERecoveryRecord{
		IMSI:          "204950000000099",
		CallID:        1001,
		CurrentGUTI:   "20495000010100000001",
		RecoveryState: models.RecoveryStateActiveSnapshot,
		RestartEpoch:  "epoch-a",
	}
	if err := s.UpsertUERecoveryRecord(ctx, first); err != nil {
		t.Fatalf("first UpsertUERecoveryRecord: %v", err)
	}

	second := &models.UERecoveryRecord{
		IMSI:          "204950000000099",
		CallID:        1002,
		CurrentGUTI:   "20495000010100000002",
		OldGUTI:       "20495000010100000001",
		RecoveryState: models.RecoveryStateRecovered,
		RestartEpoch:  "epoch-b",
	}
	if err := s.UpsertUERecoveryRecord(ctx, second); err != nil {
		t.Fatalf("second UpsertUERecoveryRecord: %v", err)
	}

	got, err := s.GetUERecoveryByIMSI(ctx, "204950000000099")
	if err != nil {
		t.Fatalf("GetUERecoveryByIMSI: %v", err)
	}
	if got.CallID != 1002 || got.OldGUTI == "" {
		t.Fatalf("recovery row = %+v, want updated call ID and old GUTI", got)
	}
	byOldGUTI, err := s.GetUERecoveryByGUTI(ctx, "20495000010100000001")
	if err != nil {
		t.Fatalf("GetUERecoveryByGUTI old: %v", err)
	}
	if byOldGUTI.IMSI != "204950000000099" {
		t.Fatalf("old GUTI lookup IMSI = %q", byOldGUTI.IMSI)
	}
}

func TestSQLiteStoreMarksOldRecoveryRowsStale(t *testing.T) {
	db := openSQLiteTestDB(t)
	s := store.New(db)
	ctx := context.Background()

	if err := s.UpsertUERecoveryRecord(ctx, &models.UERecoveryRecord{
		IMSI: "204950000000100", RestartEpoch: "old", RecoveryState: models.RecoveryStateActiveSnapshot,
	}); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if err := s.UpsertUERecoveryRecord(ctx, &models.UERecoveryRecord{
		IMSI: "204950000000101", RestartEpoch: "new", RecoveryState: models.RecoveryStateActiveSnapshot,
	}); err != nil {
		t.Fatalf("insert new: %v", err)
	}

	n, err := s.MarkRecoveryRecordsStaleAfterRestart(ctx, "new")
	if err != nil {
		t.Fatalf("MarkRecoveryRecordsStaleAfterRestart: %v", err)
	}
	if n != 1 {
		t.Fatalf("rows marked = %d, want 1", n)
	}
	old, _ := s.GetUERecoveryByIMSI(ctx, "204950000000100")
	if old.RecoveryState != models.RecoveryStateStaleAfterRestart || old.StaleAt == nil {
		t.Fatalf("old row = %+v, want stale with stale_at", old)
	}
}

func TestSQLiteStoreDeleteRecoveryByIMSI(t *testing.T) {
	db := openSQLiteTestDB(t)
	s := store.New(db)
	ctx := context.Background()
	imsi := "204950000000102"
	if err := s.UpsertUERecoveryRecord(ctx, &models.UERecoveryRecord{
		IMSI: imsi, RecoveryState: models.RecoveryStateDetached,
	}); err != nil {
		t.Fatalf("insert UE: %v", err)
	}
	if err := s.UpsertSessionRecoveryRecord(ctx, &models.SessionRecoveryRecord{
		IMSI: imsi, APN: "internet", RecoveryState: models.RecoveryStateDetached,
	}); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := s.DeleteUERecoveryRecordsByIMSI(ctx, []string{imsi}); err != nil {
		t.Fatalf("DeleteUERecoveryRecordsByIMSI: %v", err)
	}
	if _, err := s.GetUERecoveryByIMSI(ctx, imsi); err != repository.ErrNotFound {
		t.Fatalf("GetUERecoveryByIMSI after delete err = %v, want ErrNotFound", err)
	}
	sessions, err := s.ListSessionRecoveryRecords(ctx, imsi)
	if err != nil {
		t.Fatalf("ListSessionRecoveryRecords: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions after delete = %+v", sessions)
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
