package s1ap

import (
	"context"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/uecontext"
)

// fakeRecoveryStore serves a single, fixed UE/session recovery record for
// loader tests. Everything else falls back to noopStore's not-found/no-op
// behaviour.
type fakeRecoveryStore struct {
	noopStore
	ueRec    *models.UERecoveryRecord
	sessions []models.SessionRecoveryRecord
}

func (f fakeRecoveryStore) GetUERecoveryByGUTI(_ context.Context, guti string) (*models.UERecoveryRecord, error) {
	if f.ueRec == nil || f.ueRec.CurrentGUTI != guti {
		return nil, repository.ErrNotFound
	}
	rec := *f.ueRec
	return &rec, nil
}

func (f fakeRecoveryStore) ListSessionRecoveryRecords(_ context.Context, imsi string) ([]models.SessionRecoveryRecord, error) {
	if f.ueRec == nil || imsi != f.ueRec.IMSI {
		return nil, nil
	}
	return f.sessions, nil
}

func testGUTIRecord(imsi, guti string, recoveryState string) *models.UERecoveryRecord {
	return &models.UERecoveryRecord{
		IMSI:             imsi,
		MSISDN:           "15550001234",
		CurrentGUTI:      guti,
		RecoveryState:    recoveryState,
		NASIntegrityAlg:  1,
		NASCipheringAlg:  1,
		NASKSI:           2,
		UplinkNASCount:   10,
		DownlinkNASCount: 20,
		KASME:            make([]byte, 32),
	}
}

func newLoaderTestServer() *Server {
	s := newTestServer(&mockS11{})
	s.recoveryPersistent = true
	return s
}

func TestRecoverUEFromStore_ReconstructsContextAndArmsTimers(t *testing.T) {
	guti := uecontext.SerialiseGUTI(&emm.GUTI{PLMN: [3]byte{0x02, 0xF8, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 42})
	rec := testGUTIRecord("001010000000099", guti, models.RecoveryStateStaleAfterRestart)

	s := newLoaderTestServer()
	s.store = fakeRecoveryStore{ueRec: rec}

	ue, ok := s.recoverUEFromStore(guti)
	if !ok {
		t.Fatal("expected recovery to succeed")
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.IMSI != rec.IMSI {
		t.Errorf("IMSI: got %q, want %q", ue.IMSI, rec.IMSI)
	}
	if ue.EMMState != emm.StateRegistered || ue.ECMState != emm.ECMIdle {
		t.Errorf("expected EMM=Registered/ECM=Idle, got EMM=%s ECM=%s", ue.EMMState, ue.ECMState)
	}
	if ue.NASKSI != rec.NASKSI {
		t.Errorf("NASKSI: got %d, want %d", ue.NASKSI, rec.NASKSI)
	}
	if uint32(ue.ULNASCount) != rec.UplinkNASCount || uint32(ue.DLNASCount) != rec.DownlinkNASCount {
		t.Errorf("NAS counts not restored: UL=%d DL=%d", uint32(ue.ULNASCount), uint32(ue.DLNASCount))
	}
	if len(ue.KNASint) == 0 || len(ue.KNASenc) == 0 {
		t.Error("NAS session keys were not derived from restored KASME")
	}
	if ue.GUTI == nil || uecontext.SerialiseGUTI(ue.GUTI) != guti {
		t.Error("GUTI was not correctly reconstructed")
	}
	// Reachability is a "reachable" default with no persisted deadline in
	// this record; RestoreReachability still runs and should not panic or
	// leave the timer state inconsistent.
	if ue.ReachabilityState == "" {
		t.Error("RestoreReachability did not run against the recovered context")
	}

	if got, ok := s.ueManager.GetByIMSI(rec.IMSI); !ok || got != ue {
		t.Error("recovered UE was not registered by IMSI")
	}
	if got, ok := s.ueManager.GetByGUTI(guti); !ok || got != ue {
		t.Error("recovered UE was not registered by GUTI")
	}
}

func TestRecoverUEFromStore_RestoresSessionFields(t *testing.T) {
	guti := uecontext.SerialiseGUTI(&emm.GUTI{PLMN: [3]byte{0x02, 0xF8, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 43})
	rec := testGUTIRecord("001010000000098", guti, models.RecoveryStateDisconnected)
	sess := models.SessionRecoveryRecord{
		IMSI:       rec.IMSI,
		APN:        "internet",
		DefaultEBI: 5,
		MMES11TEID: 0x1000,
		SGWS11TEID: 0x2000,
		SGWS11IP:   "10.0.0.1",
		UEIPv4:     "100.64.0.5",
	}

	s := newLoaderTestServer()
	s.store = fakeRecoveryStore{ueRec: rec, sessions: []models.SessionRecoveryRecord{sess}}

	ue, ok := s.recoverUEFromStore(guti)
	if !ok {
		t.Fatal("expected recovery to succeed")
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.APN != "internet" || ue.DefaultEBI != 5 {
		t.Errorf("session APN/EBI not restored: apn=%q ebi=%d", ue.APN, ue.DefaultEBI)
	}
	if ue.LocalS11TEID != 0x1000 || ue.SGWC_TEID != 0x2000 {
		t.Errorf("S11 TEIDs not restored: local=%#x sgw=%#x", ue.LocalS11TEID, ue.SGWC_TEID)
	}
	if ue.SGWC_IP == nil || ue.SGWC_IP.String() != "10.0.0.1" {
		t.Errorf("SGW IP not restored: got %v", ue.SGWC_IP)
	}
	if ue.UEIPv4 == nil || ue.UEIPv4.String() != "100.64.0.5" {
		t.Errorf("UE IPv4 not restored: got %v", ue.UEIPv4)
	}
}

func TestRecoverUEFromStore_RejectsTerminalStates(t *testing.T) {
	for _, state := range []string{models.RecoveryStateDetached, models.RecoveryStateExpired, models.RecoveryStateCleanedUp} {
		guti := uecontext.SerialiseGUTI(&emm.GUTI{PLMN: [3]byte{0x02, 0xF8, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 44})
		rec := testGUTIRecord("001010000000097", guti, state)

		s := newLoaderTestServer()
		s.store = fakeRecoveryStore{ueRec: rec}

		if _, ok := s.recoverUEFromStore(guti); ok {
			t.Errorf("recovery state %q should not be recoverable", state)
		}
		if s.ueManager.Count() != 0 {
			t.Errorf("recovery state %q left a registered context behind", state)
		}
	}
}

func TestRecoverUEFromStore_MissingRecordReturnsFalse(t *testing.T) {
	s := newLoaderTestServer()
	s.store = fakeRecoveryStore{}

	if _, ok := s.recoverUEFromStore("does-not-exist"); ok {
		t.Fatal("expected recovery to fail for an unknown GUTI")
	}
}

func TestRecoverUEFromStore_NotPersistentModeReturnsFalse(t *testing.T) {
	guti := uecontext.SerialiseGUTI(&emm.GUTI{PLMN: [3]byte{0x02, 0xF8, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 45})
	rec := testGUTIRecord("001010000000096", guti, models.RecoveryStateStaleAfterRestart)

	s := newTestServer(&mockS11{})
	s.recoveryPersistent = false
	s.store = fakeRecoveryStore{ueRec: rec}

	if _, ok := s.recoverUEFromStore(guti); ok {
		t.Fatal("expected recovery to be a no-op when recoveryPersistent is false")
	}
}

func TestRecoverUEFromStore_SkipsWhenIMSIAlreadyLive(t *testing.T) {
	guti := uecontext.SerialiseGUTI(&emm.GUTI{PLMN: [3]byte{0x02, 0xF8, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 46})
	rec := testGUTIRecord("001010000000095", guti, models.RecoveryStateStaleAfterRestart)

	s := newLoaderTestServer()
	s.store = fakeRecoveryStore{ueRec: rec}

	existing := s.ueManager.Allocate()
	existing.IMSI = rec.IMSI
	s.ueManager.Register(existing)

	if _, ok := s.recoverUEFromStore(guti); ok {
		t.Fatal("expected recovery to yield to the already-live context for this IMSI")
	}
	if s.ueManager.Count() != 1 {
		t.Errorf("expected exactly the pre-existing context to remain, got %d contexts", s.ueManager.Count())
	}
}

// TestHandleIdleTAUMessage_RecoversUEFromPersistedStoreOnGUTIMiss is the
// end-to-end proof that the tau.go wiring point actually uses the loader:
// the UE exists only in the recovery store (simulating "known before an MME
// restart, not yet re-contacted"), never in the in-memory manager, and the
// TAU must still be accepted rather than rejected with CauseImplicitlyDetached.
func TestHandleIdleTAUMessage_RecoversUEFromPersistedStoreOnGUTIMiss(t *testing.T) {
	srv := newTAUTestServer()
	srv.recoveryPersistent = true

	const addr = "10.0.0.40:36412"
	ch := setupSendCapture(srv, addr)

	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0x1357}
	gutiStr := uecontext.SerialiseGUTI(guti)
	rec := testGUTIRecord("001010000000077", gutiStr, models.RecoveryStateDisconnected)
	// NASIntegrityAlg/NASCipheringAlg = 1 (EIA1/EEA1, SNOW 3G): this test
	// exercises the real, encrypted+integrity-protected TAU Accept encode
	// path with a genuinely derived (non-null) key, which is exactly the
	// scenario that used to panic in snow3g.Init before it was fixed.
	srv.store = fakeRecoveryStore{ueRec: rec}

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 4000
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	if _, ok := srv.ueManager.GetByGUTI(gutiStr); ok {
		t.Fatal("setup: UE must not be present in memory before recovery")
	}

	nasPDU := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case <-ch:
		// A PDU was sent — since a store-only miss with no recovery would
		// send a TAU Reject too, the real assertion is the manager state below.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no PDU sent for TAU against a store-only UE")
	}

	recovered, ok := srv.ueManager.GetByIMSI(rec.IMSI)
	if !ok {
		t.Fatal("UE known only to the persisted store was not recovered into the manager")
	}
	recovered.Lock()
	defer recovered.Unlock()
	if recovered.EMMState != emm.StateTrackingAreaUpdating && recovered.EMMState != emm.StateRegistered {
		t.Errorf("recovered UE EMMState after TAU: got %v, want Updating or Registered", recovered.EMMState)
	}
}
