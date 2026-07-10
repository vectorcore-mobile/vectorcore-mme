package repository

import (
	"context"

	"github.com/vectorcore/mme/internal/models"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errString("not found")

type errString string

func (e errString) Error() string { return string(e) }

// UERecoveryFilter restricts recovery record list queries.
type UERecoveryFilter struct {
	IMSI             string
	GUTI             string
	RecoveryState    string
	StaleOnly        bool
	DisconnectedOnly bool
	Limit            int
	Offset           int
}

// Repository is the only way handlers touch the database.
// Handlers import repository, never gorm. Runtime UE state remains in memory;
// repository methods expose recovery/correlation snapshots only.
type Repository interface {
	// UE recovery records
	UpsertUERecoveryRecord(ctx context.Context, ue *models.UERecoveryRecord) error
	GetUERecoveryByIMSI(ctx context.Context, imsi string) (*models.UERecoveryRecord, error)
	GetUERecoveryByGUTI(ctx context.Context, guti string) (*models.UERecoveryRecord, error)
	ListUERecoveryRecords(ctx context.Context, filter UERecoveryFilter) ([]models.UERecoveryRecord, error)
	DeleteUERecoveryRecordsByIMSI(ctx context.Context, imsis []string) error
	MarkRecoveryRecordsStaleAfterRestart(ctx context.Context, restartEpoch string) (int64, error)

	// Session recovery records
	UpsertSessionRecoveryRecord(ctx context.Context, session *models.SessionRecoveryRecord) error
	ListSessionRecoveryRecords(ctx context.Context, imsi string) ([]models.SessionRecoveryRecord, error)

	// Recovery audit events
	AppendRecoveryEvent(ctx context.Context, event *models.RecoveryEvent) error
	ListRecoveryEvents(ctx context.Context, imsi string, limit int) ([]models.RecoveryEvent, error)

	// eNB registrations
	UpsertENBRegistration(ctx context.Context, enb *models.ENBRegistration) error
	DeleteENBRegistration(ctx context.Context, globalENBID string) error
	ListENBRegistrations(ctx context.Context) ([]models.ENBRegistration, error)
}
