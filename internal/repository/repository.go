package repository

import (
	"context"

	"github.com/vectorcore/mme/internal/models"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errString("not found")

type errString string

func (e errString) Error() string { return string(e) }

// Repository is the only way handlers touch the database.
// Handlers import repository, never gorm.
type Repository interface {
	// UE contexts
	UpsertUEContext(ctx context.Context, ue *models.UEContext) error
	GetUEContextByMMEID(ctx context.Context, mmeS1APID uint32) (*models.UEContext, error)
	GetUEContextByIMSI(ctx context.Context, imsi string) (*models.UEContext, error)
	GetUEContextByGUTI(ctx context.Context, guti string) (*models.UEContext, error)
	DeleteUEContext(ctx context.Context, mmeS1APID uint32) error
	ListUEContexts(ctx context.Context) ([]models.UEContext, error)

	// eNB registrations
	UpsertENBRegistration(ctx context.Context, enb *models.ENBRegistration) error
	DeleteENBRegistration(ctx context.Context, globalENBID string) error
	ListENBRegistrations(ctx context.Context) ([]models.ENBRegistration, error)
}
