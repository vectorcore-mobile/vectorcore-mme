package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/repository"
)

type recoveryUEEntry struct {
	models.UERecoveryRecord
	ActiveInMemory bool                           `json:"active_in_memory"`
	Sessions       []models.SessionRecoveryRecord `json:"sessions,omitempty"`
}

type listRecoveryUEsInput struct {
	IMSI             string `query:"imsi"`
	GUTI             string `query:"guti"`
	RecoveryState    string `query:"recovery_state"`
	StaleOnly        bool   `query:"stale_only"`
	DisconnectedOnly bool   `query:"disconnected_only"`
	Limit            int    `query:"limit"`
	Offset           int    `query:"offset"`
}

type listRecoveryUEsOutput struct {
	Body struct {
		UEs   []recoveryUEEntry `json:"ues"`
		Count int               `json:"count"`
	}
}

type getRecoveryUEInput struct {
	IMSI string `path:"imsi"`
}

type getRecoveryUEOutput struct {
	Body struct {
		recoveryUEEntry
		Events []models.RecoveryEvent `json:"events,omitempty"`
	}
}

type clearDisconnectedInput struct {
	DryRun bool `query:"dry_run"`
}

type clearDisconnectedOutput struct {
	Body struct {
		DeletedCount          int      `json:"deleted_count"`
		SkippedActiveCount    int      `json:"skipped_active_count"`
		SkippedOtherCount     int      `json:"skipped_other_count"`
		DryRun                bool     `json:"dry_run"`
		RecordsDeleted        []string `json:"records_deleted,omitempty"`
		RecordsWouldBeDeleted []string `json:"records_that_would_be_deleted,omitempty"`
	}
}

func registerRecoveryHandlers(api huma.API, s *Server) {
	huma.Register(api, huma.Operation{
		OperationID: "list-mme-ue-recovery-records",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/mme/recovery/ues",
		Summary:     "List MME UE recovery records",
		Tags:        []string{"Recovery"},
	}, s.listRecoveryUEs)

	huma.Register(api, huma.Operation{
		OperationID: "get-mme-ue-recovery-record",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/mme/recovery/ues/{imsi}",
		Summary:     "Get one MME UE recovery record",
		Tags:        []string{"Recovery"},
	}, s.getRecoveryUE)

	huma.Register(api, huma.Operation{
		OperationID: "clear-disconnected-mme-ue-recovery-records",
		Method:      http.MethodDelete,
		Path:        apiPrefix + "/mme/recovery/ues/disconnected",
		Summary:     "Clear disconnected/stale UE recovery records",
		Tags:        []string{"Recovery"},
	}, s.clearDisconnectedRecoveryUEs)
}

func (s *Server) listRecoveryUEs(ctx context.Context, input *listRecoveryUEsInput) (*listRecoveryUEsOutput, error) {
	if s.store == nil {
		return nil, huma.Error503ServiceUnavailable("recovery store not available")
	}
	records, err := s.store.ListUERecoveryRecords(ctx, repository.UERecoveryFilter{
		IMSI:             input.IMSI,
		GUTI:             input.GUTI,
		RecoveryState:    input.RecoveryState,
		StaleOnly:        input.StaleOnly,
		DisconnectedOnly: input.DisconnectedOnly,
		Limit:            input.Limit,
		Offset:           input.Offset,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	out := &listRecoveryUEsOutput{}
	for _, rec := range records {
		out.Body.UEs = append(out.Body.UEs, recoveryUEEntry{
			UERecoveryRecord: rec,
			ActiveInMemory:   s.isRecoveryRecordActive(rec),
		})
	}
	out.Body.Count = len(out.Body.UEs)
	return out, nil
}

func (s *Server) getRecoveryUE(ctx context.Context, input *getRecoveryUEInput) (*getRecoveryUEOutput, error) {
	if s.store == nil {
		return nil, huma.Error503ServiceUnavailable("recovery store not available")
	}
	rec, err := s.store.GetUERecoveryByIMSI(ctx, input.IMSI)
	if err != nil {
		if err == repository.ErrNotFound {
			return nil, huma.Error404NotFound("UE recovery record not found")
		}
		return nil, huma.Error500InternalServerError(err.Error())
	}
	sessions, err := s.store.ListSessionRecoveryRecords(ctx, input.IMSI)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	events, err := s.store.ListRecoveryEvents(ctx, input.IMSI, 25)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	out := &getRecoveryUEOutput{}
	out.Body.recoveryUEEntry = recoveryUEEntry{
		UERecoveryRecord: *rec,
		ActiveInMemory:   s.isRecoveryRecordActive(*rec),
		Sessions:         sessions,
	}
	out.Body.Events = events
	return out, nil
}

func (s *Server) clearDisconnectedRecoveryUEs(ctx context.Context, input *clearDisconnectedInput) (*clearDisconnectedOutput, error) {
	if s.store == nil {
		return nil, huma.Error503ServiceUnavailable("recovery store not available")
	}
	records, err := s.store.ListUERecoveryRecords(ctx, repository.UERecoveryFilter{DisconnectedOnly: true})
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	var deleteIMSIs []string
	out := &clearDisconnectedOutput{}
	out.Body.DryRun = input.DryRun
	for _, rec := range records {
		if s.isRecoveryRecordActive(rec) {
			out.Body.SkippedActiveCount++
			continue
		}
		if !isClearEligible(rec.RecoveryState) {
			out.Body.SkippedOtherCount++
			continue
		}
		deleteIMSIs = append(deleteIMSIs, rec.IMSI)
		if input.DryRun {
			out.Body.RecordsWouldBeDeleted = append(out.Body.RecordsWouldBeDeleted, rec.IMSI)
		} else {
			out.Body.RecordsDeleted = append(out.Body.RecordsDeleted, rec.IMSI)
		}
	}
	if !input.DryRun {
		if err := s.store.DeleteUERecoveryRecordsByIMSI(ctx, deleteIMSIs); err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
		out.Body.DeletedCount = len(deleteIMSIs)
	}
	return out, nil
}

func (s *Server) isRecoveryRecordActive(rec models.UERecoveryRecord) bool {
	if s.ueManager == nil {
		return false
	}
	if rec.IMSI != "" {
		if _, ok := s.ueManager.GetByIMSI(rec.IMSI); ok {
			return true
		}
	}
	if rec.CallID != 0 {
		if _, ok := s.ueManager.GetByMMEID(rec.CallID); ok {
			return true
		}
	}
	if rec.CurrentGUTI != "" {
		if _, ok := s.ueManager.GetByGUTI(rec.CurrentGUTI); ok {
			return true
		}
	}
	if rec.ContextID != 0 && rec.ContextID != rec.CallID {
		if _, ok := s.ueManager.GetByMMEID(rec.ContextID); ok {
			return true
		}
	}
	return false
}

func isClearEligible(state string) bool {
	switch state {
	case models.RecoveryStateDetached,
		models.RecoveryStateDisconnected,
		models.RecoveryStateExpired,
		models.RecoveryStateCleanedUp,
		models.RecoveryStateStaleAfterRestart:
		return true
	default:
		return false
	}
}
