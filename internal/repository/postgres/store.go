package postgres

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/repository"
)

// Store is the GORM-backed repository implementation.
type Store struct{ db *gorm.DB }

func New(db *gorm.DB) *Store { return &Store{db: db} }

// ── UE Contexts ──────────────────────────────────────────────────────────────

func (s *Store) UpsertUEContext(ctx context.Context, ue *models.UEContext) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Evict stale row for same IMSI with different PK (re-attach after restart).
		if err := tx.Where("imsi = ? AND mme_ue_s1ap_id != ?", ue.IMSI, ue.MMEUES1APID).
			Delete(&models.UEContext{}).Error; err != nil {
			return err
		}
		// Evict stale row for same GUTI assigned to a different IMSI (GUTI counter reset
		// after MME restart can re-issue an MTMSI that's still in the DB for another IMSI).
		if ue.GUTI != nil && *ue.GUTI != "" {
			if err := tx.Where("guti = ? AND mme_ue_s1ap_id != ?", *ue.GUTI, ue.MMEUES1APID).
				Delete(&models.UEContext{}).Error; err != nil {
				return err
			}
		}
		return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(ue).Error
	})
}

func (s *Store) GetUEContextByMMEID(ctx context.Context, mmeS1APID uint32) (*models.UEContext, error) {
	var ue models.UEContext
	err := s.db.WithContext(ctx).First(&ue, "mme_ue_s1ap_id = ?", mmeS1APID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, repository.ErrNotFound
	}
	return &ue, err
}

func (s *Store) GetUEContextByIMSI(ctx context.Context, imsi string) (*models.UEContext, error) {
	var ue models.UEContext
	err := s.db.WithContext(ctx).First(&ue, "imsi = ?", imsi).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, repository.ErrNotFound
	}
	return &ue, err
}

func (s *Store) GetUEContextByGUTI(ctx context.Context, guti string) (*models.UEContext, error) {
	var ue models.UEContext
	err := s.db.WithContext(ctx).First(&ue, "guti = ?", guti).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, repository.ErrNotFound
	}
	return &ue, err
}

func (s *Store) DeleteUEContext(ctx context.Context, mmeS1APID uint32) error {
	return s.db.WithContext(ctx).Delete(&models.UEContext{}, "mme_ue_s1ap_id = ?", mmeS1APID).Error
}

func (s *Store) ListUEContexts(ctx context.Context) ([]models.UEContext, error) {
	var ues []models.UEContext
	err := s.db.WithContext(ctx).Find(&ues).Error
	return ues, err
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
