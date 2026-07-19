package s1ap

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/uecontext"
)

func (s *Server) securityHexField(name string, value []byte) zap.Field {
	return zap.Skip()
}

func (s *Server) logASSecuritySnapshotCreated(ue *uecontext.Context, procedure string) {
	if ue == nil {
		return
	}
	ue.Lock()
	fields := []zap.Field{
		zap.String("event", "as_security_snapshot_created"),
		zap.String("procedure", procedure),
		zap.String("imsi", ue.IMSI),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Uint8("nas_ksi", ue.NASKSI),
		zap.String("nas_security_context_type", "native_eps"),
		zap.Uint32("ul_nas_count_at_accept", ue.KeNBULCount),
		zap.Uint32("ul_nas_overflow_at_accept", ue.KeNBULCount>>8),
		zap.Uint8("ul_nas_sequence_at_accept", security.NASCount(ue.KeNBULCount).SequenceNumber()),
		zap.Uint32("dl_nas_count_at_accept", uint32(ue.DLNASCount)),
		zap.Uint8("nhcc", ue.NCC),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
	}
	ue.Unlock()
	s.log.Debug("s1ap: AS security snapshot created", fields...)
}

func (s *Server) createASSecuritySnapshotLocked(ue *uecontext.Context, procedure string) error {
	if ue == nil {
		return fmt.Errorf("nil UE context")
	}
	if len(ue.KeNB) > 0 {
		reason := "security-context-replaced"
		if ue.KeNBSnapshotGeneration != ue.S1BindingGeneration {
			reason = "new-binding-created"
		}
		s.invalidateASSecuritySnapshotLoggedLocked(ue, reason)
	}
	if _, _, err := deriveAndStoreASContextLocked(ue); err != nil {
		return err
	}
	fields := []zap.Field{
		zap.String("event", "as_security_snapshot_created"),
		zap.String("procedure", procedure),
		zap.String("imsi", ue.IMSI),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Uint8("nas_ksi", ue.NASKSI),
		zap.String("nas_security_context_type", "native_eps"),
		zap.Uint32("ul_nas_count_at_accept", ue.KeNBULCount),
		zap.Uint32("ul_nas_overflow_at_accept", ue.KeNBULCount>>8),
		zap.Uint8("ul_nas_sequence_at_accept", security.NASCount(ue.KeNBULCount).SequenceNumber()),
		zap.Uint32("dl_nas_count_at_accept", uint32(ue.DLNASCount)),
		zap.Uint8("nhcc", ue.NCC),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
	}
	s.log.Debug("s1ap: AS security snapshot created", fields...)
	return nil
}

func (s *Server) logASSecuritySnapshotReused(ue *uecontext.Context) {
	if ue == nil {
		return
	}
	ue.Lock()
	fields := []zap.Field{
		zap.String("event", "as_security_snapshot_reused"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Uint64("snapshot_generation", ue.KeNBSnapshotGeneration),
		zap.Uint32("ul_nas_count_at_snapshot", ue.KeNBULCount),
		zap.Uint32("current_ul_nas_count", uint32(ue.ULNASCount)),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
	}
	ue.Unlock()
	s.log.Debug("s1ap: AS security snapshot reused", fields...)
}

func (s *Server) logASSecuritySnapshotInvalidated(ue *uecontext.Context, reason string) {
	if ue == nil {
		return
	}
	ue.Lock()
	fields := []zap.Field{
		zap.String("event", "as_security_snapshot_invalidated"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Uint64("snapshot_generation", ue.KeNBSnapshotGeneration),
		zap.String("reason", reason),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
	}
	ue.Unlock()
	s.log.Debug("s1ap: AS security snapshot invalidated", fields...)
}

func (s *Server) invalidateASSecuritySnapshotLocked(ue *uecontext.Context) {
	if ue == nil {
		return
	}
	ue.KeNB = nil
	ue.KeNBULCount = 0
	ue.KeNBSnapshotGeneration = 0
}

func (s *Server) invalidateASSecuritySnapshotLoggedLocked(ue *uecontext.Context, reason string) {
	if ue == nil {
		return
	}
	fields := []zap.Field{
		zap.String("event", "as_security_snapshot_invalidated"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Uint64("snapshot_generation", ue.KeNBSnapshotGeneration),
		zap.String("reason", reason),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
	}
	s.invalidateASSecuritySnapshotLocked(ue)
	s.log.Debug("s1ap: AS security snapshot invalidated", fields...)
}

func (s *Server) logICSSecurityKeySelected(ue *uecontext.Context, procedure, source string, icsSecurityKey, comparisonKey []byte) {
	if ue == nil {
		return
	}
	ue.Lock()
	fields := []zap.Field{
		zap.String("event", "ics_security_key_selected"),
		zap.String("procedure", procedure),
		zap.String("imsi", ue.IMSI),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Uint32("current_ul_nas_count", uint32(ue.ULNASCount)),
		zap.Uint32("snapshot_ul_nas_count", ue.KeNBULCount),
		zap.Uint8("nas_ksi", ue.NASKSI),
		zap.Uint8("nhcc", ue.NCC),
		zap.String("security_key_source", source),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
		s.securityHexField("ics_security_key_hex", icsSecurityKey),
	}
	ue.Unlock()
	s.log.Debug("s1ap: ICS security key selected", fields...)

	if len(comparisonKey) > 0 {
		ue.Lock()
		compareFields := []zap.Field{
			zap.String("event", "ics_security_key_comparison"),
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.Uint64("binding_generation", ue.S1BindingGeneration),
			zap.Uint32("snapshot_ul_nas_count", ue.KeNBULCount),
			zap.Uint32("current_ul_nas_count", uint32(ue.ULNASCount)),
			zap.Bool("keys_equal", false),
			s.securityHexField("kenb_snapshot_hex", ue.KeNB),
			s.securityHexField("kenb_rederived_current_count_hex", comparisonKey),
		}
		ue.Unlock()
		s.log.Debug("s1ap: ICS security key comparison", compareFields...)
	}
}

func (s *Server) logStaleBindingMutationRejected(ue *uecontext.Context, callbackENBUEID uint32, callbackBindingGeneration uint64, mutationType string) {
	if ue == nil {
		return
	}
	ue.Lock()
	fields := []zap.Field{
		zap.String("event", "stale_binding_mutation_rejected"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("current_enb_ue_id", ue.ENBS1APID),
		zap.Uint32("callback_enb_ue_id", callbackENBUEID),
		zap.Uint64("current_binding_generation", ue.S1BindingGeneration),
		zap.Uint64("callback_binding_generation", callbackBindingGeneration),
		zap.String("mutation_type", mutationType),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
	}
	ue.Unlock()
	s.log.Debug("s1ap: stale binding mutation rejected", fields...)
}

func (s *Server) logPostICSMutation(ue *uecontext.Context, mutationType, oldValue, newValue string, extra ...zap.Field) {
	if ue == nil {
		return
	}
	ue.Lock()
	if time.Now().After(ue.PostICSDebugUntil) {
		ue.Unlock()
		return
	}
	bearerStatus, activeBearers, _ := tauMMEBearerContextStatusSnapshotLocked(ue)
	fields := []zap.Field{
		zap.String("event", "post_ics_context_mutation"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.Uint64("binding_generation", ue.S1BindingGeneration),
		zap.Int64("elapsed_since_ics_ms", time.Since(ue.PostICSDebugUntil.Add(-15*time.Second)).Milliseconds()),
		zap.String("mutation_type", mutationType),
		zap.String("old_value", oldValue),
		zap.String("new_value", newValue),
		zap.Uint32("ul_nas_count", uint32(ue.ULNASCount)),
		zap.Uint32("dl_nas_count", uint32(ue.DLNASCount)),
		zap.Uint8("nas_ksi", ue.NASKSI),
		zap.Uint8("nhcc", ue.NCC),
		s.securityHexField("kenb_snapshot_hex", ue.KeNB),
		zap.String("active_bearers", activeBearers),
		zap.Bool("pending_release", ue.S1ReleasePending),
		zap.String("ecm_state", ue.ECMState.String()),
		zap.String("emm_state", ue.EMMState.String()),
		zap.String("eps_bearer_status_hex", tauBearerStatusHex(bearerStatus)),
	}
	ue.Unlock()
	fields = append(fields, extra...)
	s.log.Debug("s1ap: post-ICS context mutation", fields...)
}

func nasCountParts(count uint32) (overflow uint32, seq uint8) {
	return count >> 8, security.NASCount(count).SequenceNumber()
}

func resumeProcedureName(step uint8) string {
	switch {
	case isTAUActiveResumeStep(step):
		return "active_flag_tau"
	case isServiceRequestResumeStep(step):
		return "service_request"
	default:
		return "initial_attach"
	}
}

func (s *Server) maybeComparisonKeNB(ue *uecontext.Context) []byte {
	return nil
}

func formatUint64(v uint64) string {
	return fmt.Sprintf("%d", v)
}
