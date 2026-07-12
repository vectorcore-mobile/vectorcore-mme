package s1ap

import (
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

func (s *Server) handleInitialUEDetach(
	tempUE *uecontext.Context,
	mmec uint8, mtmsi uint32, stmsiRaw []byte, stmsiPresent bool,
	tai *ies.TAI, nasPDU []byte,
) {
	tempUE.Lock()
	enbUEID := tempUE.ENBS1APID
	enbAddr := tempUE.ENBGlobalID
	tempMmeUEID := tempUE.MMEUES1APID
	tempUE.Unlock()

	log := s.log.With(
		zap.String("remote", enbAddr),
		zap.String("procedure", "Detach"),
		zap.Uint32("tmp_mme_ue_id", tempMmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	)
	log.Info("s1ap: InitialUE Detach Request received",
		zap.String("nas_hex", hex.EncodeToString(nasPDU)),
		zap.String("stmsi_raw", hex.EncodeToString(stmsiRaw)),
		zap.Bool("stmsi_present", stmsiPresent),
		zap.Uint8("decoded_mmec", mmec),
		zap.Uint32("decoded_mtmsi", mtmsi),
		zap.String("decoded_mtmsi_hex", fmt.Sprintf("0x%08x", mtmsi)))

	fail := func(msg string, fields ...zap.Field) {
		log.Warn(msg, fields...)
		s.ueManager.Remove(tempUE)
	}

	if !stmsiPresent {
		fail("s1ap: InitialUE Detach: no S-TMSI in Initial UE Message")
		return
	}

	realUE, gutiStr, ok := s.lookupUEBySTMSI(mmec, mtmsi)
	if !ok {
		fail("s1ap: InitialUE Detach: GUTI not found",
			zap.String("lookup_guti", gutiStr),
			zap.Uint8("mmec", mmec),
			zap.Uint32("mtmsi", mtmsi),
			zap.String("mtmsi_hex", fmt.Sprintf("0x%08x", mtmsi)))
		return
	}

	realUE.Lock()
	intAlg := realUE.IntAlg
	encAlg := realUE.EncAlg
	knasInt := append([]byte(nil), realUE.KNASint...)
	knasEnc := append([]byte(nil), realUE.KNASenc...)
	storedULCount := uint32(realUE.ULNASCount)
	emmState := realUE.EMMState
	realMmeUEID := realUE.MMEUES1APID
	imsi := realUE.IMSI
	realUE.Unlock()

	log = log.With(zap.Uint32("mme_ue_id", realMmeUEID), zap.String("imsi", imsi))
	log.Info("s1ap: InitialUE Detach lookup result",
		zap.String("lookup_result", "hit"),
		zap.String("lookup_guti", gutiStr),
		zap.Stringer("emm_state", emmState),
		zap.Uint32("stored_ul_nas_count", storedULCount))

	if emmState != emm.StateRegistered {
		fail("s1ap: InitialUE Detach: UE not in Registered state",
			zap.Stringer("state", emmState),
			zap.String("lookup_guti", gutiStr))
		return
	}

	reconstructedCount, seq, countErr := reconstructFullULNASCount(nasPDU, storedULCount)
	if countErr != nil {
		fail("s1ap: InitialUE Detach: cannot reconstruct NAS COUNT", zap.Error(countErr))
		return
	}

	result, err := nas.Decode(nasPDU, intAlg, encAlg, knasInt, knasEnc, reconstructedCount)
	if err != nil {
		fail("s1ap: InitialUE Detach: NAS security verification failed",
			zap.Uint32("stored_ul_nas_count", storedULCount),
			zap.Uint32("reconstructed_ul_nas_count", reconstructedCount),
			zap.Uint8("nas_sequence_number", seq),
			zap.Error(err))
		return
	}
	if result.SecHeaderType == emm.SecurityHeaderPlain {
		fail("s1ap: InitialUE Detach: refusing plain Detach Request for registered UE with known context",
			zap.Uint32("stored_ul_nas_count", storedULCount))
		return
	}
	if result.PD != emm.PDEPSMobilityMgmt || result.MsgType != emm.MsgDetachRequest {
		fail("s1ap: InitialUE Detach: decoded NAS is not Detach Request",
			zap.Uint8("pd", result.PD),
			zap.Uint8("msg_type", result.MsgType))
		return
	}

	realUE.Lock()
	realUE.ENBS1APID = enbUEID
	realUE.ENBGlobalID = enbAddr
	if tai != nil {
		plmnBytes, _ := ies.EncodePLMN(tai.MCC, tai.MNC)
		t := emm.TAI{TAC: tai.TAC}
		if len(plmnBytes) == 3 {
			copy(t.PLMN[:], plmnBytes)
		}
		realUE.TAI = &t
	}
	realUE.ULNASCount = security.NASCount(reconstructedCount)
	realUE.SetECMState(emm.ECMConnected)
	realUE.Unlock()

	s.ueManager.Remove(tempUE)
	if err := s.processDetach(realUE, result.Inner, log); err != nil {
		log.Error("s1ap: InitialUE Detach: processing failed", zap.Error(err))
	}
}

func (s *Server) lookupUEBySTMSI(mmec uint8, mtmsi uint32) (*uecontext.Context, string, bool) {
	plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		return nil, "", false
	}
	lookupGUTI := &emm.GUTI{
		MMEGI: s.nfCfg.MMEGI,
		MMEC:  mmec,
		MTMSI: mtmsi,
	}
	copy(lookupGUTI.PLMN[:], plmn)
	gutiStr := uecontext.SerialiseGUTI(lookupGUTI)
	ue, ok := s.ueManager.GetByGUTI(gutiStr)
	return ue, gutiStr, ok
}

func reconstructFullULNASCount(nasPDU []byte, stored uint32) (uint32, uint8, error) {
	secHdr, _, err := emm.DecodeSecurityHeader(nasPDU)
	if err != nil {
		return 0, 0, err
	}
	if secHdr == emm.SecurityHeaderPlain {
		return stored, 0, nil
	}
	if len(nasPDU) < 6 {
		return 0, 0, fmt.Errorf("security-protected NAS too short: %d", len(nasPDU))
	}
	seq := nasPDU[5]
	count := (stored & 0xffffff00) | uint32(seq)
	if count < stored {
		count += 0x100
	}
	return count, seq, nil
}
