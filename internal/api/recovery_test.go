package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/api"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/uecontext"
)

type memoryRecoveryStore struct {
	mu       sync.Mutex
	ues      map[string]models.UERecoveryRecord
	sessions map[string][]models.SessionRecoveryRecord
	events   map[string][]models.RecoveryEvent
}

func newMemoryRecoveryStore(records ...models.UERecoveryRecord) *memoryRecoveryStore {
	s := &memoryRecoveryStore{
		ues:      map[string]models.UERecoveryRecord{},
		sessions: map[string][]models.SessionRecoveryRecord{},
		events:   map[string][]models.RecoveryEvent{},
	}
	for _, r := range records {
		s.ues[r.IMSI] = r
	}
	return s
}

func (s *memoryRecoveryStore) UpsertUERecoveryRecord(_ context.Context, ue *models.UERecoveryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ues[ue.IMSI] = *ue
	return nil
}

func (s *memoryRecoveryStore) GetUERecoveryByIMSI(_ context.Context, imsi string) (*models.UERecoveryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.ues[imsi]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &rec, nil
}

func (s *memoryRecoveryStore) GetUERecoveryByGUTI(_ context.Context, guti string) (*models.UERecoveryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.ues {
		if rec.CurrentGUTI == guti || rec.OldGUTI == guti || rec.ReallocatedGUTI == guti {
			r := rec
			return &r, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (s *memoryRecoveryStore) ListUERecoveryRecords(_ context.Context, filter repository.UERecoveryFilter) ([]models.UERecoveryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []models.UERecoveryRecord
	for _, rec := range s.ues {
		if filter.IMSI != "" && rec.IMSI != filter.IMSI {
			continue
		}
		if filter.GUTI != "" && rec.CurrentGUTI != filter.GUTI && rec.OldGUTI != filter.GUTI && rec.ReallocatedGUTI != filter.GUTI {
			continue
		}
		if filter.RecoveryState != "" && rec.RecoveryState != filter.RecoveryState {
			continue
		}
		if filter.StaleOnly && rec.RecoveryState != models.RecoveryStateStaleAfterRestart {
			continue
		}
		if filter.DisconnectedOnly && !testClearEligible(rec.RecoveryState) {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

func (s *memoryRecoveryStore) DeleteUERecoveryRecordsByIMSI(_ context.Context, imsis []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, imsi := range imsis {
		delete(s.ues, imsi)
		delete(s.sessions, imsi)
	}
	return nil
}

func (s *memoryRecoveryStore) MarkRecoveryRecordsStaleAfterRestart(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (s *memoryRecoveryStore) UpsertSessionRecoveryRecord(_ context.Context, session *models.SessionRecoveryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.IMSI] = append(s.sessions[session.IMSI], *session)
	return nil
}

func (s *memoryRecoveryStore) ListSessionRecoveryRecords(_ context.Context, imsi string) ([]models.SessionRecoveryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.SessionRecoveryRecord(nil), s.sessions[imsi]...), nil
}

func (s *memoryRecoveryStore) AppendRecoveryEvent(_ context.Context, event *models.RecoveryEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[event.IMSI] = append(s.events[event.IMSI], *event)
	return nil
}

func (s *memoryRecoveryStore) ListRecoveryEvents(_ context.Context, imsi string, _ int) ([]models.RecoveryEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.RecoveryEvent(nil), s.events[imsi]...), nil
}

func (s *memoryRecoveryStore) UpsertENBRegistration(_ context.Context, _ *models.ENBRegistration) error {
	return nil
}
func (s *memoryRecoveryStore) DeleteENBRegistration(_ context.Context, _ string) error { return nil }
func (s *memoryRecoveryStore) ListENBRegistrations(_ context.Context) ([]models.ENBRegistration, error) {
	return nil, nil
}

func newRecoveryAPITestHandler(store repository.Repository, mgr *uecontext.Manager) http.Handler {
	log, _ := zap.NewDevelopment()
	return api.New(
		config.APIConfig{BindAddress: "127.0.0.1", BindPort: 8080},
		config.NFConfig{},
		config.OperatorConfig{},
		store,
		peertracker.New(),
		mgr,
		stubDiamStatus{},
		log,
	).Handler()
}

func TestRecoveryAPIListComputesActiveInMemory(t *testing.T) {
	store := newMemoryRecoveryStore(models.UERecoveryRecord{
		IMSI: "204950000000001", RecoveryState: models.RecoveryStateDisconnected,
	})
	mgr := uecontext.NewManager()
	ue := mgr.Allocate()
	ue.IMSI = "204950000000001"
	mgr.Register(ue)

	h := newRecoveryAPITestHandler(store, mgr)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mme/recovery/ues", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET recovery UEs = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		UEs []struct {
			IMSI           string `json:"imsi"`
			ActiveInMemory bool   `json:"active_in_memory"`
		} `json:"ues"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.UEs) != 1 || !resp.UEs[0].ActiveInMemory {
		t.Fatalf("response = %+v, want one active recovery row", resp)
	}
}

func TestRecoveryAPIClearDisconnectedSkipsActiveAndSupportsDryRun(t *testing.T) {
	store := newMemoryRecoveryStore(
		models.UERecoveryRecord{IMSI: "204950000000001", RecoveryState: models.RecoveryStateDisconnected},
		models.UERecoveryRecord{IMSI: "204950000000002", RecoveryState: models.RecoveryStateDetached},
	)
	mgr := uecontext.NewManager()
	ue := mgr.Allocate()
	ue.IMSI = "204950000000001"
	mgr.Register(ue)
	h := newRecoveryAPITestHandler(store, mgr)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mme/recovery/ues/disconnected?dry_run=true", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dry-run clear = %d: %s", w.Code, w.Body.String())
	}
	var dry struct {
		SkippedActiveCount    int      `json:"skipped_active_count"`
		RecordsWouldBeDeleted []string `json:"records_that_would_be_deleted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &dry); err != nil {
		t.Fatalf("unmarshal dry run: %v", err)
	}
	if dry.SkippedActiveCount != 1 || len(dry.RecordsWouldBeDeleted) != 1 || dry.RecordsWouldBeDeleted[0] != "204950000000002" {
		t.Fatalf("dry run response = %+v", dry)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/mme/recovery/ues/disconnected", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("clear = %d: %s", w.Code, w.Body.String())
	}
	if _, err := store.GetUERecoveryByIMSI(context.Background(), "204950000000001"); err != nil {
		t.Fatalf("active row should remain: %v", err)
	}
	if _, err := store.GetUERecoveryByIMSI(context.Background(), "204950000000002"); err != repository.ErrNotFound {
		t.Fatalf("detached row err = %v, want ErrNotFound", err)
	}
}

func testClearEligible(state string) bool {
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
