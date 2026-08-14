package sqlite

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/repository"
)

// Store is the GORM-backed repository implementation.
type Store struct{ db *gorm.DB }

func New(db *gorm.DB) *Store { return &Store{db: db} }

// ── UE recovery records ─────────────────────────────────────────────────────

func (s *Store) UpsertUERecoveryRecord(ctx context.Context, ue *models.UERecoveryRecord) error {
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "imsi"}},
		UpdateAll: true,
	}).Create(ue).Error
}

func (s *Store) GetUERecoveryByIMSI(ctx context.Context, imsi string) (*models.UERecoveryRecord, error) {
	var ue models.UERecoveryRecord
	err := s.db.WithContext(ctx).First(&ue, "imsi = ?", imsi).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, repository.ErrNotFound
	}
	return &ue, err
}

func (s *Store) GetUERecoveryByGUTI(ctx context.Context, guti string) (*models.UERecoveryRecord, error) {
	var ue models.UERecoveryRecord
	err := s.db.WithContext(ctx).Where(
		"current_guti = ? OR old_guti = ? OR reallocated_guti = ?",
		guti, guti, guti,
	).First(&ue).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, repository.ErrNotFound
	}
	return &ue, err
}

func (s *Store) ListUERecoveryRecords(ctx context.Context, filter repository.UERecoveryFilter) ([]models.UERecoveryRecord, error) {
	q := s.db.WithContext(ctx).Model(&models.UERecoveryRecord{}).Order("updated_at DESC")
	if filter.IMSI != "" {
		q = q.Where("imsi = ?", filter.IMSI)
	}
	if filter.GUTI != "" {
		q = q.Where("current_guti = ? OR old_guti = ? OR reallocated_guti = ?", filter.GUTI, filter.GUTI, filter.GUTI)
	}
	if filter.RecoveryState != "" {
		q = q.Where("recovery_state = ?", filter.RecoveryState)
	}
	if filter.StaleOnly {
		q = q.Where("recovery_state = ?", models.RecoveryStateStaleAfterRestart)
	}
	if filter.DisconnectedOnly {
		q = q.Where("recovery_state IN ?", disconnectedRecoveryStates())
	}
	if filter.Limit > 0 {
		q = q.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}
	var ues []models.UERecoveryRecord
	err := q.Find(&ues).Error
	return ues, err
}

func (s *Store) DeleteUERecoveryRecordsByIMSI(ctx context.Context, imsis []string) error {
	if len(imsis) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("imsi IN ?", imsis).Delete(&models.SessionRecoveryRecord{}).Error; err != nil {
			return err
		}
		if err := tx.Where("imsi IN ?", imsis).Delete(&models.UERecoveryRecord{}).Error; err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) MarkRecoveryRecordsStaleAfterRestart(ctx context.Context, restartEpoch string) (int64, error) {
	now := time.Now().UTC()
	states := []string{
		models.RecoveryStateActiveSnapshot,
		models.RecoveryStateReturnedForRecovery,
		models.RecoveryStateRecovered,
		models.RecoveryStateDisconnected,
	}
	res := s.db.WithContext(ctx).Model(&models.UERecoveryRecord{}).
		Where("restart_epoch <> ? AND recovery_state IN ?", restartEpoch, states).
		Updates(map[string]interface{}{
			"recovery_state": models.RecoveryStateStaleAfterRestart,
			"stale_at":       now,
			"updated_at":     now,
		})
	if res.Error != nil {
		return 0, res.Error
	}
	if err := s.db.WithContext(ctx).Model(&models.SessionRecoveryRecord{}).
		Where("restart_epoch <> ? AND recovery_state IN ?", restartEpoch, states).
		Updates(map[string]interface{}{
			"recovery_state": models.RecoveryStateStaleAfterRestart,
			"stale_at":       now,
			"updated_at":     now,
		}).Error; err != nil {
		return res.RowsAffected, err
	}
	return res.RowsAffected, nil
}

// ── Session recovery records ────────────────────────────────────────────────

func (s *Store) UpsertSessionRecoveryRecord(ctx context.Context, session *models.SessionRecoveryRecord) error {
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "imsi"}, {Name: "apn"}},
		UpdateAll: true,
	}).Create(session).Error
}

func (s *Store) ListSessionRecoveryRecords(ctx context.Context, imsi string) ([]models.SessionRecoveryRecord, error) {
	var sessions []models.SessionRecoveryRecord
	q := s.db.WithContext(ctx).Order("updated_at DESC")
	if imsi != "" {
		q = q.Where("imsi = ?", imsi)
	}
	err := q.Find(&sessions).Error
	return sessions, err
}

// ── Recovery events ─────────────────────────────────────────────────────────

func (s *Store) AppendRecoveryEvent(ctx context.Context, event *models.RecoveryEvent) error {
	return s.db.WithContext(ctx).Create(event).Error
}

func (s *Store) ListRecoveryEvents(ctx context.Context, imsi string, limit int) ([]models.RecoveryEvent, error) {
	var events []models.RecoveryEvent
	q := s.db.WithContext(ctx).Order("created_at DESC")
	if imsi != "" {
		q = q.Where("imsi = ?", imsi)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	err := q.Find(&events).Error
	return events, err
}

// ── eNB Registrations ────────────────────────────────────────────────────────

func (s *Store) UpsertENBRegistration(ctx context.Context, enb *models.ENBRegistration) error {
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(enb).Error
}

func (s *Store) DeleteENBRegistration(ctx context.Context, globalENBID string) error {
	return s.db.WithContext(ctx).Delete(&models.ENBRegistration{}, "global_enb_id = ?", globalENBID).Error
}

func (s *Store) ListENBRegistrations(ctx context.Context) ([]models.ENBRegistration, error) {
	var enbs []models.ENBRegistration
	err := s.db.WithContext(ctx).Find(&enbs).Error
	return enbs, err
}

func disconnectedRecoveryStates() []string {
	return []string{
		models.RecoveryStateDetached,
		models.RecoveryStateDisconnected,
		models.RecoveryStateExpired,
		models.RecoveryStateCleanedUp,
		models.RecoveryStateStaleAfterRestart,
	}
}
