package s1ap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	s1ReleaseRABRTimerName = "S1ReleaseRABR"
	s1ReleaseRABRTimeout   = 2 * time.Second
)

type s1ReleaseRABRAction struct {
	ENBAddr    string
	ENBUEID    uint32
	CauseGroup ies.CauseGroup
	Cause      uint8
	LogFields  []zap.Field
}

// handleUEContextReleaseRequest handles an eNB-initiated UE Context Release Request.
func (s *Server) handleUEContextReleaseRequest(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	causeGroup := ies.CauseGroupNAS
	causeValue := ies.CauseNASNormalRelease
	causePresent := false

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UE Context Release Request MME UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UE Context Release Request eNB UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Uint32("mme_ue_id", mmeUEID),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			enbUEID = id
		case pdu.IECause:
			if group, value, err := ies.DecodeCause(ie.Value); err == nil {
				causeGroup = group
				causeValue = value
				causePresent = true
			}
		}
	}

	s.log.Info("s1ap: UE Context Release Request",
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.Bool("cause_present", causePresent),
		zap.String("cause_group_name", ies.CauseGroupName(causeGroup)),
		zap.Uint8("cause_group", uint8(causeGroup)),
		zap.Uint8("cause", causeValue),
		zap.String("cause_name", ies.CauseName(causeGroup, causeValue)))

	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, mmeUEID, enbUEID)
	if !ok {
		return
	}
	s.logPostICSDebugWindow(ue, "ue_context_release_request",
		zap.String("remote", remoteAddr),
		zap.String("release_cause_name", ies.CauseName(causeGroup, causeValue)))

	if ue != nil {
		ue.Lock()
		mmeUEID = ue.MMEUES1APID
		enbUEID = ue.ENBS1APID
		emmState := ue.EMMState
		currentENB := ue.ENBGlobalID
		imsi := ue.IMSI
		preserveEPS := emmState == emm.StateRegistered ||
			emmState == emm.StateTrackingAreaUpdating ||
			emmState == emm.StateServiceRequestInitiated
		if preserveEPS && (currentENB == "" || currentENB == remoteAddr) {
			if emmState != emm.StateTrackingAreaUpdating {
				ue.StopAllTimers()
			}
			ue.LastReleaseCause = ies.CauseName(causeGroup, causeValue)
			ue.S1ReleasePending = true
			ue.S1ReleaseENBID = enbUEID
			ue.S1ReleaseENBAddr = remoteAddr
			ue.S1ReleaseGeneration = ue.S1BindingGeneration
			ue.S1ReleaseCauseGroup = uint8(causeGroup)
			ue.S1ReleaseCauseValue = causeValue
			ue.S1BindingState = uecontext.S1BindingReleasePending
			bindingGeneration := ue.S1BindingGeneration
			ue.Unlock()

			s.log.Info("s1ap: UE S1 release pending",
				zap.String("remote", remoteAddr),
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.Uint32("enb_ue_id", enbUEID),
				zap.String("imsi", imsi),
				zap.Uint64("binding_generation", bindingGeneration),
				zap.String("binding_state", uecontext.S1BindingReleasePending.String()),
				zap.Bool("binding_preserved", true))
			s.persistUERecoverySnapshot(ue, models.RecoveryStateDisconnected, "S1_RELEASED")
			if s.startPreservedS1ReleaseRABR(ue) {
				return
			}
		} else {
			ue.Unlock()
		}
	}
	s.sendUEContextReleaseCommandCause(remoteAddr, mmeUEID, enbUEID, causeGroup, causeValue)
}

// handleUEContextReleaseComplete handles an eNB confirmation of context release.
func (s *Server) handleUEContextReleaseComplete(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UE Context Release Complete MME UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UE Context Release Complete eNB UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Uint32("mme_ue_id", mmeUEID),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			enbUEID = id
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID))
	log.Info("s1ap: UE Context Release Complete")

	ue, ok := s.findUEForReleaseComplete(remoteAddr, p, mmeUEID, enbUEID)
	if !ok {
		return
	}
	s.logPostICSDebugWindow(ue, "ue_context_release_complete",
		zap.String("remote", remoteAddr))

	ue.Lock()
	emmState := ue.EMMState
	imsi := ue.IMSI
	if emmState != emm.StateTrackingAreaUpdating {
		ue.StopAllTimers()
	}

	switch emmState {
	case emm.StateRegistered, emm.StateTrackingAreaUpdating, emm.StateServiceRequestInitiated:
		if ue.S1ReleaseGeneration != 0 && ue.S1ReleaseGeneration != ue.S1BindingGeneration {
			releaseGeneration := ue.S1ReleaseGeneration
			currentGeneration := ue.S1BindingGeneration
			currentENB := ue.ENBGlobalID
			currentENBUEID := ue.ENBS1APID
			ue.S1ReleasePending = false
			ue.S1ReleaseENBID = 0
			ue.S1ReleaseENBAddr = ""
			ue.S1ReleaseGeneration = 0
			ue.S1ReleaseCauseGroup = 0
			ue.S1ReleaseCauseValue = 0
			ue.Unlock()
			s.logStaleBindingMutationRejected(ue, enbUEID, releaseGeneration, "ue-context-release-complete")
			log.Info("s1ap: stale UE Context Release Complete ignored for old S1 binding",
				zap.Uint64("release_generation", releaseGeneration),
				zap.Uint64("binding_generation", currentGeneration),
				zap.String("current_enb", currentENB),
				zap.Uint32("current_enb_ue_id", currentENBUEID))
			return
		}
		if ue.S1ReleasePending &&
			ue.S1ReleaseENBAddr == remoteAddr &&
			(enbUEID == 0 || ue.S1ReleaseENBID == 0 || enbUEID == ue.S1ReleaseENBID) {
			ue.S1ReleasePending = false
			ue.S1ReleaseENBID = 0
			ue.S1ReleaseENBAddr = ""
			ue.S1ReleaseGeneration = 0
			ue.S1ReleaseCauseGroup = 0
			ue.S1ReleaseCauseValue = 0
			if ue.ENBGlobalID != "" && (ue.ENBGlobalID != remoteAddr || (enbUEID != 0 && ue.ENBS1APID != enbUEID)) {
				currentENB := ue.ENBGlobalID
				currentENBUEID := ue.ENBS1APID
				currentGeneration := ue.S1BindingGeneration
				ue.Unlock()
				s.logStaleBindingMutationRejected(ue, enbUEID, currentGeneration, "release-complete-old-access-context")
				log.Info("s1ap: stale UE Context Release Complete acknowledged old access context",
					zap.String("current_enb", currentENB),
					zap.Uint32("current_enb_ue_id", currentENBUEID))
				return
			}
		}
		// If the release arrived from a different eNB than the UE's current eNB, this is
		// a stale release from the old source after a successful S1 handover. The UE is
		// already connected to the target — clobbering ENBGlobalID here would break DL NAS
		// and make PageUE think the UE is idle while it's actually connected to the target.
		if ue.ENBGlobalID != "" && ue.ENBGlobalID != remoteAddr {
			currentENB := ue.ENBGlobalID
			currentGeneration := ue.S1BindingGeneration
			ue.Unlock()
			s.logStaleBindingMutationRejected(ue, enbUEID, currentGeneration, "release-complete-post-handover-source")
			log.Info("s1ap: stale UE Context Release Complete (post-HO source), ignoring",
				zap.String("current_enb", currentENB),
				zap.String("release_from", remoteAddr))
			return
		}
		// UE released S1 without detaching — keep context as ECM-IDLE so it can be paged.
		bearerStatus, activeBearers, skippedBearers := tauMMEBearerContextStatusSnapshotLocked(ue)
		ue.SetECMState(emm.ECMIdle)
		releaseCause := ue.LastReleaseCause
		ue.ENBS1APID = 0
		ue.ENBGlobalID = "" // must be cleared: handleDisconnect matches on this field
		ue.ENBU_TEID = 0
		ue.ENBU_IP = nil
		ue.S1ReleasePending = false
		ue.S1ReleaseENBID = 0
		ue.S1ReleaseENBAddr = ""
		ue.S1ReleaseGeneration = 0
		ue.S1ReleaseCauseGroup = 0
		ue.S1ReleaseCauseValue = 0
		ue.S1BindingState = uecontext.S1BindingReleased
		ue.Unlock()

		log.Info("s1ap: UE going ECM-IDLE (registered)",
			zap.String("imsi", imsi),
			zap.String("emm_state", emm.StateRegistered.String()),
			zap.String("last_release_cause", releaseCause),
			zap.String("eps_bearer_status_hex", tauBearerStatusHex(bearerStatus)),
			zap.String("active_bearers", activeBearers),
			zap.String("skipped_bearers", skippedBearers),
			zap.Bool("s1_connected", false))
		metrics.S1APMessagesTotal.WithLabelValues("UEContextRelease", "inbound", "idle").Inc()
		s.failCreateBearersWaitingForLinkedBearer(ue, gtpv2.CauseRequestRejected, "ue_ecm_idle")

		s.persistUERecoverySnapshot(ue, models.RecoveryStateDisconnected, "S1_RELEASED")
		return

	case emm.StateDeregisteredInitiated:
		ue.Unlock()
		s.sendDeleteSession(ue)
		s.ueManager.Remove(ue)
		metrics.AttachedUEs.Dec()
		metrics.S1APMessagesTotal.WithLabelValues("UEContextRelease", "inbound", "detach").Inc()

	default:
		ue.Unlock()
		s.sendDeleteSession(ue)
		s.ueManager.Remove(ue)
		metrics.S1APMessagesTotal.WithLabelValues("UEContextRelease", "inbound", "complete").Inc()
	}

	_ = mmeUEID
}

func (s *Server) findUEForReleaseComplete(remoteAddr string, p *pdu.PDU, mmeUEID, enbUEID uint32) (*uecontext.Context, bool) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		if p != nil {
			s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownMMEUES1APID)
		}
		return nil, false
	}
	if enbUEID == 0 {
		return ue, true
	}

	ue.Lock()
	boundRemote := ue.ENBGlobalID
	boundENBID := ue.ENBS1APID
	releasePending := ue.S1ReleasePending
	releaseRemote := ue.S1ReleaseENBAddr
	releaseENBID := ue.S1ReleaseENBID
	ue.Unlock()

	if releasePending && releaseRemote == remoteAddr && (releaseENBID == 0 || releaseENBID == enbUEID) {
		return ue, true
	}
	if boundRemote != "" && boundRemote != remoteAddr {
		if p != nil {
			s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownMMEUES1APID)
		}
		return nil, false
	}
	if boundENBID != 0 && boundENBID != enbUEID {
		if p != nil {
			s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownPairUES1APID)
		}
		return nil, false
	}
	return ue, true
}

// handleInitialContextSetupResponse handles a successful Initial Context Setup response.
// If an E-RAB setup list is present it extracts the eNB S1-U TEID/IP and sends a Modify Bearer Request.
func (s *Server) handleInitialContextSetupResponse(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var erabSetupList []byte
	var erabFailedList []byte

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, _ := ies.DecodeMMEUEApID(ie.Value)
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, _ := ies.DecodeENBUEApID(ie.Value)
			enbUEID = id
		case pdu.IEERABSetupListCtxtSURes:
			erabSetupList = append([]byte(nil), ie.Value...)
		case pdu.IEERABFailedToSetupListCtxtSURes:
			erabFailedList = append([]byte(nil), ie.Value...)
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID))
	log.Info("s1ap: Initial Context Setup Response",
		zap.Int("erab_setup_list_len", len(erabSetupList)),
		zap.Int("erab_failed_to_setup_list_len", len(erabFailedList)),
	)

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	// Try to extract the eNB S1-U TEIDs from the E-RAB setup list (IE 51).
	var erabSetups []icsResponseERABSetup
	if len(erabSetupList) > 0 {
		setups, err := decodeICSResponseERABSetups(erabSetupList)
		if err != nil {
			log.Warn("s1ap: Initial Context Setup Response E-RAB setup decode failed",
				zap.Error(err))
		} else {
			erabSetups = setups
			for _, setup := range setups {
				log.Info("s1ap: Initial Context Setup Response E-RAB setup item",
					zap.Uint8("erab_id", setup.ERABID),
					zap.String("enb_s1u_ipv4", setup.ENBUIP.String()),
					zap.Uint32("enb_s1u_teid", setup.ENBUTEID))
			}
		}
	}
	var erabFailures []ERABSetupFailure
	if len(erabFailedList) > 0 {
		failures, err := decodeERABFailedToSetupList(erabFailedList)
		if err != nil {
			log.Warn("s1ap: Initial Context Setup Response E-RAB failure decode failed",
				zap.Error(err),
				zap.String("erab_failed_to_setup_list_hex", truncateHex(erabFailedList, 128)))
		} else {
			erabFailures = failures
			for _, failure := range failures {
				log.Info("s1ap: Initial Context Setup Response E-RAB failed item",
					zap.Uint8("erab_id", failure.EBI),
					zap.Uint8("cause_group", failure.CauseGroup),
					zap.Uint32("cause", failure.Cause))
			}
		}
	}

	ue.Lock()
	attachStep := ue.AttachStep
	ue.SetECMState(emm.ECMConnected)
	for _, setup := range erabSetups {
		if setup.ENBUTEID == 0 {
			continue
		}
		if setup.ERABID == ue.DefaultEBI {
			ue.ENBU_TEID = setup.ENBUTEID
			ue.ENBU_IP = setup.ENBUIP
		}
		for _, pdn := range ue.PDNs {
			if pdn == nil || pdn.DefaultEBI != setup.ERABID {
				continue
			}
			pdn.ENBU_TEID = setup.ENBUTEID
			pdn.ENBU_IP = append(net.IP(nil), setup.ENBUIP...)
			pdn.ERABEstablished = true
			if pdn.ModifyBearerAccepted {
				pdn.State = "active"
			} else {
				pdn.State = "access-established"
			}
		}
		if proc := ue.DedicatedBearers[setup.ERABID]; proc != nil {
			proc.ENBS1UTEID = setup.ENBUTEID
			proc.ENBS1UIP = append(net.IP(nil), setup.ENBUIP...)
			proc.ERABEstablished = true
			proc.ERABFailed = false
		}
	}
	for _, failure := range erabFailures {
		if failure.EBI == ue.DefaultEBI {
			ue.ENBU_TEID = 0
			ue.ENBU_IP = nil
		}
		for _, pdn := range ue.PDNs {
			if pdn == nil || pdn.DefaultEBI != failure.EBI {
				continue
			}
			pdn.ENBU_TEID = 0
			pdn.ENBU_IP = nil
			pdn.ERABEstablished = false
			pdn.State = "erab-setup-failed"
		}
		if proc := ue.DedicatedBearers[failure.EBI]; proc != nil {
			proc.ENBS1UTEID = 0
			proc.ENBS1UIP = nil
			proc.ERABEstablished = false
			proc.ERABFailed = true
			proc.State = "erab-setup-failed"
		}
	}
	if !isResumeICSAttachStep(attachStep) {
		ue.AttachStep = uecontext.AttachStepWaitingAttachCplt
	}
	ue.Unlock()

	metrics.S1APMessagesTotal.WithLabelValues("InitialContextSetup", "inbound", "success").Inc()
	s.armPostICSDebugWindow(ue, "initial_context_setup_response")
	s.logPostICSDebugWindow(ue, "initial_context_setup_response_applied",
		zap.Int("erab_setup_count", len(erabSetups)),
		zap.Int("erab_failure_count", len(erabFailures)))
	if isServiceRequestResumeStep(attachStep) {
		s.handleServiceRequestReestablished(ue, log)
	} else if isTAUActiveResumeStep(attachStep) {
		s.handleActiveTAUReestablished(ue, log)
	}
	// For the attach path, MBR is sent after Attach Complete (TS 23.401 step 19).
}

type icsResponseERABSetup struct {
	ERABID    uint8
	ENBUTEID  uint32
	ENBUIP    net.IP
	ItemValue []byte
}

// decodeICSResponseERABs parses the E-RABSetupListCtxtSURes IE value to extract
// the eNB S1-U TEID and IP from the first E-RABSetupItemCtxtSURes.
//
// Wire format of the IE value:
//
//	SEQUENCE OF (count constrained 1..256): items follow
//	Each item: inner IE container with IE 50 (E-RABSetupItemCtxtSURes)
//	IE 50 value APER-encodes E-RABSetupItemCtxtSURes SEQUENCE:
//	  ext=0, optional bits, E-RAB-ID(0..15), transportLayerAddress BIT STRING (1..160,...), GTP-TEID(SIZE 4)
func decodeICSResponseERABs(data []byte) (uint32, net.IP) {
	setup, err := decodeICSResponseERABSetup(data)
	if err != nil {
		return 0, nil
	}
	return setup.ENBUTEID, setup.ENBUIP
}

func decodeICSResponseERABSetup(data []byte) (*icsResponseERABSetup, error) {
	setups, err := decodeICSResponseERABSetups(data)
	if err != nil {
		return nil, err
	}
	return &setups[0], nil
}

func decodeICSResponseERABSetups(data []byte) ([]icsResponseERABSetup, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("short E-RABSetupListCtxtSURes")
	}
	r := aper.NewBitReader(data)

	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil || count == 0 {
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB setup list count: %w", err)
		}
		return nil, fmt.Errorf("empty E-RAB setup list")
	}
	r.AlignToByte()

	setups := make([]icsResponseERABSetup, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB setup item IE ID: %w", err)
		}
		if uint16(ieID) != pdu.IEERABSetupItemCtxtSURes {
			return nil, fmt.Errorf("unexpected E-RAB setup item IE ID %d", ieID)
		}
		if _, err = aper.DecodeCriticality(r); err != nil {
			return nil, fmt.Errorf("decode E-RAB setup item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read E-RAB setup item open type: %w", err)
		}
		setup, err := decodeICSResponseERABSetupItem(itemBytes)
		if err != nil {
			return nil, err
		}
		setups = append(setups, *setup)
	}
	return setups, nil
}

func decodeICSResponseERABSetupItem(itemBytes []byte) (*icsResponseERABSetup, error) {
	ir := aper.NewBitReader(itemBytes)
	if _, err := ir.ReadBit(); err != nil {
		return nil, fmt.Errorf("decode E-RAB setup item extension bit: %w", err)
	}
	if _, err := ir.ReadBit(); err != nil {
		return nil, fmt.Errorf("decode E-RAB setup item optional bitmap: %w", err)
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB ID extension bit: %w", err)
	}
	if erabIDExt != 0 {
		return nil, fmt.Errorf("decode E-RAB ID: extension value not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB ID: %w", err)
	}
	extBit, err := ir.ReadBit()
	if err != nil {
		return nil, fmt.Errorf("decode transportLayerAddress extension bit: %w", err)
	}
	ir.AlignToByte()
	var addrBits int64
	if extBit == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	if err != nil {
		return nil, fmt.Errorf("decode transportLayerAddress length: %w", err)
	}
	ir.AlignToByte()
	numBytes := int((addrBits + 7) / 8)
	addrBytes, err := ir.ReadOctets(numBytes)
	if err != nil || numBytes < 4 {
		if err != nil {
			return nil, fmt.Errorf("read transportLayerAddress: %w", err)
		}
		return nil, fmt.Errorf("transportLayerAddress too short: %d bits", addrBits)
	}
	ip := net.IP(addrBytes[:4]).To4()
	ir.AlignToByte()
	teidBytes, err := ir.ReadOctets(4)
	if err != nil {
		return nil, fmt.Errorf("read GTP-TEID: %w", err)
	}
	teid := binary.BigEndian.Uint32(teidBytes)
	return &icsResponseERABSetup{
		ERABID:    uint8(erabID),
		ENBUTEID:  teid,
		ENBUIP:    ip,
		ItemValue: append([]byte(nil), itemBytes...),
	}, nil
}

// handleInitialContextSetupFailure handles an unsuccessful Initial Context Setup.
func (s *Server) handleInitialContextSetupFailure(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32

	for _, ie := range ieList {
		if ie.ID == pdu.IEMMEUES1APID {
			id, _ := ies.DecodeMMEUEApID(ie.Value)
			mmeUEID = id
		}
	}

	s.log.Warn("s1ap: Initial Context Setup Failure",
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID))

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	attachStep := ue.AttachStep
	ue.StopAllTimers()
	if isResumeICSAttachStep(attachStep) {
		ue.SetEMMState(emm.StateRegistered)
		ue.SetECMState(emm.ECMIdle)
		ue.AttachStep = uecontext.AttachStepNone
	}
	ue.Unlock()

	if !isResumeICSAttachStep(attachStep) {
		// Release any S-GW session that was established before the ICS failure.
		// sendDeleteSession is idempotent (checks SGWC_TEID before sending).
		s.sendDeleteSession(ue)
		s.ueManager.Remove(ue)
	} else {
		s.failDDNPagingIfPending(ue, "initial_context_setup_failure")
		// For Service Request / active-flag TAU resume ICS failure: keep UE and S-GW session; UE stays in idle mode.
		if isServiceRequestResumeStep(attachStep) {
			metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
		}
	}
	metrics.S1APMessagesTotal.WithLabelValues("InitialContextSetup", "inbound", "failure").Inc()
}

// handleErrorIndication handles an S1AP Error Indication from an eNB.
func (s *Server) handleErrorIndication(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	fields := []zap.Field{zap.String("remote", remoteAddr)}
	if p != nil {
		fields = append(fields,
			zap.Uint8("procedure_code", p.ProcedureCode),
			zap.String("triggering_message", p.Type.String()),
			zap.String("criticality", p.Criticality.String()),
			zap.String("raw_pdu_hex", hex.EncodeToString(p.Raw)))
	}
	var mmeUEID uint32
	var enbUEID uint32
	var causeGroup ies.CauseGroup
	var cause uint8
	var causePresent bool
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			if id, err := ies.DecodeMMEUEApID(ie.Value); err == nil {
				mmeUEID = id
				fields = append(fields, zap.Uint32("mme_ue_id", id))
			}
		case pdu.IEENBS1APID:
			if id, err := ies.DecodeENBUEApID(ie.Value); err == nil {
				enbUEID = id
				fields = append(fields, zap.Uint32("enb_ue_id", id))
			}
		case pdu.IECause:
			if group, decodedCause, err := ies.DecodeCause(ie.Value); err == nil {
				causeGroup, cause, causePresent = group, decodedCause, true
				fields = append(fields,
					zap.String("cause_raw_hex", hex.EncodeToString(ie.Value)),
					zap.String("cause_group_name", ies.CauseGroupName(group)),
					zap.Uint8("cause_group", uint8(group)),
					zap.Uint8("cause", decodedCause),
					zap.String("cause_name", ies.CauseName(group, decodedCause)))
			}
		case pdu.IECriticalityDiagnostics:
			fields = append(fields, decodeCriticalityDiagnosticsFields(ie.Value)...)
		}
	}
	s.log.Warn("s1ap: ErrorIndication received", fields...)
	if causePresent && causeGroup == ies.CauseGroupProtocol && cause == ies.CauseProtocolTransferSyntaxError {
		s.failDDNPagingForSyntaxError(remoteAddr)
	}
	s.rollbackResumeICSOnErrorIndication(remoteAddr, mmeUEID, enbUEID)
	metrics.S1APMessagesTotal.WithLabelValues("ErrorIndication", "inbound", "ok").Inc()
}

// failDDNPagingForSyntaxError correlates a connectionless ErrorIndication with
// an active DDN paging transaction by its selected eNB association.  Paging
// ErrorIndications do not carry UE-associated IDs, so the remote association
// and current TAI targets are the only reliable correlation keys.
func (s *Server) failDDNPagingForSyntaxError(remoteAddr string) {
	for _, ue := range s.ueManager.List() {
		ue.Lock()
		tx := ue.DDNPaging
		if tx == nil || ddnPagingTerminal(tx.Status) {
			ue.Unlock()
			continue
		}
		txID := tx.ID
		targets := s.findStrictENBsForTAILocked(ue)
		ue.Unlock()
		for _, target := range targets {
			if target != remoteAddr {
				continue
			}
			s.log.Warn("s1ap: eNB rejected DDN Paging PDU",
				zap.String("event", "ddn_paging_rejected"),
				zap.String("transaction_id", txID),
				zap.String("target_enb", remoteAddr),
				zap.String("reason", "transfer_syntax_error"))
			s.failDDNPaging(ue, txID, gtpv2.CauseSystemFailure, "enb_transfer_syntax_error")
			break
		}
	}
}

func (s *Server) rollbackResumeICSOnErrorIndication(remoteAddr string, mmeUEID, enbUEID uint32) {
	ue, ok := s.findUEByS1APIDs(remoteAddr, mmeUEID, enbUEID)
	if !ok && mmeUEID != 0 {
		ue, ok = s.ueManager.GetByMMEID(mmeUEID)
	}
	if !ok {
		return
	}
	s.logPostICSDebugWindow(ue, "resume_ics_error_indication",
		zap.String("remote", remoteAddr),
		zap.Uint32("error_enb_ue_id", enbUEID))

	ue.Lock()
	attachStep := ue.AttachStep
	if !isResumeICSAttachStep(attachStep) {
		ue.Unlock()
		return
	}
	resolvedMMEID := ue.MMEUES1APID
	resolvedENBID := ue.ENBS1APID
	imsi := ue.IMSI
	ue.SetEMMState(emm.StateRegistered)
	ue.SetECMState(emm.ECMIdle)
	ue.AttachStep = uecontext.AttachStepNone
	s.invalidateASSecuritySnapshotLoggedLocked(ue, "resume-rollback")
	ue.ENBS1APID = 0
	ue.ENBGlobalID = ""
	ue.ENBU_TEID = 0
	ue.ENBU_IP = nil
	ue.S1ReleasePending = false
	ue.S1ReleaseENBID = 0
	ue.S1ReleaseENBAddr = ""
	ue.Unlock()
	s.failDDNPagingIfPending(ue, "resume_error_indication")

	logMsg := "s1ap: access resume failed; UE restored to ECM-IDLE"
	if isServiceRequestResumeStep(attachStep) {
		logMsg = "s1ap: ServiceRequest resume failed; UE restored to ECM-IDLE"
		metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
	} else if isTAUActiveResumeStep(attachStep) {
		logMsg = "s1ap: active-flag TAU resume failed; UE restored to ECM-IDLE"
	}
	s.log.Warn(logMsg,
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", resolvedMMEID),
		zap.Uint32("enb_ue_id", resolvedENBID),
		zap.String("imsi", imsi))
}

func decodeCriticalityDiagnosticsFields(data []byte) []zap.Field {
	fields := []zap.Field{
		zap.Bool("criticality_diagnostics_present", true),
		zap.String("criticality_diagnostics_hex", hex.EncodeToString(data)),
	}
	r := aper.NewBitReader(data)
	if ext, err := r.ReadBit(); err == nil {
		fields = append(fields, zap.Uint8("criticality_diagnostics_extension", uint8(ext)))
	}
	var present [5]uint64
	for i := range present {
		bit, err := r.ReadBit()
		if err != nil {
			return fields
		}
		present[i] = uint64(bit)
	}
	if present[0] == 1 {
		r.AlignToByte()
		proc, err := r.ReadOctet()
		if err != nil {
			return fields
		}
		fields = append(fields, zap.Uint8("diagnostic_procedure_code", proc))
	}
	if present[1] == 1 {
		v, err := r.ReadBits(2)
		if err != nil {
			return fields
		}
		fields = append(fields,
			zap.Uint8("diagnostic_triggering_message", uint8(v)),
			zap.String("diagnostic_triggering_message_name", pdu.PDUType(v).String()))
	}
	if present[2] == 1 {
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			return fields
		}
		fields = append(fields, zap.String("diagnostic_procedure_criticality", crit.String()))
	}
	if present[3] == 1 {
		fields = append(fields, zap.Bool("diagnostic_ie_list_present", true))
	}
	if present[4] == 1 {
		fields = append(fields, zap.Bool("diagnostic_ie_extensions_present", true))
	}
	return fields
}

// sendUEContextReleaseCommand sends a UE Context Release Command with NAS/normal-release cause.
func (s *Server) sendUEContextReleaseCommand(enbAddr string, mmeUEID, enbUEID uint32) {
	s.sendUEContextReleaseCommandCause(enbAddr, mmeUEID, enbUEID, ies.CauseGroupNAS, 0)
}

// sendUEContextReleaseCommandCause sends a UE Context Release Command with a caller-specified cause.
func (s *Server) sendUEContextReleaseCommandCause(enbAddr string, mmeUEID, enbUEID uint32, group ies.CauseGroup, cause uint8) {
	idsValue := encodeUES1APIDs(mmeUEID, enbUEID)
	causeValue := ies.EncodeCause(group, cause)
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEUES1APIDs, Criticality: aper.CriticalityReject, Value: idsValue},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: causeValue},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcUEContextRelease, aper.CriticalityReject, ieList)
	s.log.Info("s1ap: UE Context Release Command sent",
		zap.String("remote", enbAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.String("cause_group_name", ies.CauseGroupName(group)),
		zap.Uint8("cause_group", uint8(group)),
		zap.Uint8("cause", cause),
		zap.String("cause_name", ies.CauseName(group, cause)),
		zap.String("ue_s1ap_ids_hex", hex.EncodeToString(idsValue)))
	s.sendToAddr(enbAddr, msg)
	metrics.S1APMessagesTotal.WithLabelValues("UEContextRelease", "outbound", "command").Inc()
}

// HandleRABRResult is called when a Release Access Bearers Response arrives.
func (s *Server) HandleRABRResult(mmeUEID uint32, result *gtpv2.ReleaseAccessBearersResult, err error) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	if !ue.S1ReleasePending {
		ue.Unlock()
		return
	}
	if tx := ue.S1ReleaseRABR; tx != nil && result != nil {
		if session := tx.Sessions[rabrSessionKey(result.Peer, result.RequestedSGWCTEID)]; session != nil {
			session.ResponseAt = time.Now()
			session.ResponseHeaderTEID = result.ResponseHeaderTEID
			session.Cause = result.Cause
			session.Result = classifyRABRSessionResult(result.Cause, err)
		}
	}
	action := s.maybeFinalizePreservedS1ReleaseLocked(ue)
	ue.Unlock()
	if action == nil {
		return
	}
	if err != nil {
		action.LogFields = append(action.LogFields, zap.Error(err))
	}
	s.log.Info("s1ap: RABR release transaction completed", action.LogFields...)
	s.sendUEContextReleaseCommandCause(action.ENBAddr, mmeUEID, action.ENBUEID, action.CauseGroup, action.Cause)
}

func clearUEAccessPathsLocked(ue *uecontext.Context) {
	ue.ENBU_TEID = 0
	ue.ENBU_IP = nil
	for _, pdn := range ue.PDNs {
		if pdn == nil {
			continue
		}
		pdn.ENBU_TEID = 0
		pdn.ENBU_IP = nil
		pdn.ERABEstablished = false
		if pdn.State != "pdn-disconnect-delete-session-pending" {
			pdn.State = "idle"
		}
	}
	for _, bearer := range ue.DedicatedBearers {
		if bearer == nil {
			continue
		}
		bearer.ENBS1UTEID = 0
		bearer.ENBS1UIP = nil
		bearer.ERABEstablished = false
		if bearer.State != "tau-suspended" {
			bearer.State = "idle"
		}
	}
}

func (s *Server) beginPreservedS1Release(ue *uecontext.Context, remoteAddr string, enbUEID uint32, causeGroup ies.CauseGroup, causeValue uint8) {
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	emmState := ue.EMMState
	imsi := ue.IMSI
	if emmState != emm.StateTrackingAreaUpdating {
		ue.StopAllTimers()
	}
	ue.LastReleaseCause = ies.CauseName(causeGroup, causeValue)
	ue.S1ReleasePending = true
	ue.S1ReleaseENBID = enbUEID
	ue.S1ReleaseENBAddr = remoteAddr
	ue.S1ReleaseGeneration = ue.S1BindingGeneration
	ue.S1ReleaseCauseGroup = uint8(causeGroup)
	ue.S1ReleaseCauseValue = causeValue
	ue.S1BindingState = uecontext.S1BindingReleasePending
	bindingGeneration := ue.S1BindingGeneration
	ue.Unlock()

	s.log.Info("s1ap: UE S1 release pending",
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.String("imsi", imsi),
		zap.Uint64("binding_generation", bindingGeneration),
		zap.String("binding_state", uecontext.S1BindingReleasePending.String()),
		zap.Bool("binding_preserved", true))
	s.persistUERecoverySnapshot(ue, models.RecoveryStateDisconnected, "S1_RELEASED")
	if s.startPreservedS1ReleaseRABR(ue) {
		return
	}
	s.sendUEContextReleaseCommandCause(remoteAddr, mmeUEID, enbUEID, causeGroup, causeValue)
}

func rabrSessionKey(peer string, teid uint32) string {
	return fmt.Sprintf("%s|%08x", peer, teid)
}

func classifyRABRSessionResult(cause uint8, err error) uecontext.RABRSessionResult {
	if err == nil && cause == gtpv2.CauseRequestAccepted {
		return uecontext.RABRSessionAccepted
	}
	if cause == gtpv2.CauseContextNotFound {
		return uecontext.RABRSessionContextNotFound
	}
	return uecontext.RABRSessionPeerError
}

func (s *Server) buildS1ReleaseRABRTransactionLocked(ue *uecontext.Context) *uecontext.S1ReleaseRABRTransaction {
	tx := &uecontext.S1ReleaseRABRTransaction{
		ID:           fmt.Sprintf("rabr-%d-%d", ue.MMEUES1APID, time.Now().UnixNano()),
		StartedAt:    time.Now(),
		ReleaseCause: ue.LastReleaseCause,
		Sessions:     make(map[string]*uecontext.S1ReleaseRABRSession),
	}
	for _, pdn := range sortedPDNContextsLocked(ue) {
		if pdn == nil || pdn.SGWAddress == "" || pdn.SGWC_TEID == 0 || pdnDisconnectInProgress(pdn) {
			continue
		}
		key := rabrSessionKey(pdn.SGWAddress, pdn.SGWC_TEID)
		if _, exists := tx.Sessions[key]; exists {
			continue
		}
		tx.Sessions[key] = &uecontext.S1ReleaseRABRSession{
			Key:                        key,
			APN:                        pdn.APN,
			DefaultEBI:                 pdn.DefaultEBI,
			MMES11TEID:                 pdn.LocalS11TEID,
			SGWS11TEID:                 pdn.SGWC_TEID,
			SGWS11Addr:                 pdn.SGWAddress,
			SessionState:               pdn.State,
			LastSuccessfulS11Procedure: pdn.LastSuccessfulS11Procedure,
			Result:                     uecontext.RABRSessionPending,
		}
	}
	if ue.SGWAddress != "" && ue.SGWC_TEID != 0 {
		key := rabrSessionKey(ue.SGWAddress, ue.SGWC_TEID)
		if _, exists := tx.Sessions[key]; !exists {
			tx.Sessions[key] = &uecontext.S1ReleaseRABRSession{
				Key:                        key,
				APN:                        ue.APN,
				DefaultEBI:                 ue.DefaultEBI,
				MMES11TEID:                 ue.LocalS11TEID,
				SGWS11TEID:                 ue.SGWC_TEID,
				SGWS11Addr:                 ue.SGWAddress,
				SessionState:               "legacy",
				LastSuccessfulS11Procedure: "",
				Result:                     uecontext.RABRSessionPending,
			}
		}
	}
	if len(tx.Sessions) == 0 {
		return nil
	}
	return tx
}

func (s *Server) startPreservedS1ReleaseRABR(ue *uecontext.Context) bool {
	rabClient, ok := s.s11.(S11RABClient)
	if !ok {
		return false
	}

	ue.Lock()
	tx := s.buildS1ReleaseRABRTransactionLocked(ue)
	if tx == nil {
		ue.Unlock()
		return false
	}
	ue.S1ReleaseRABR = tx
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	ecmState := ue.ECMState.String()
	emmState := ue.EMMState.String()
	selectedSessions := make([]*uecontext.S1ReleaseRABRSession, 0, len(tx.Sessions))
	selectedKeys := make([]string, 0, len(tx.Sessions))
	for _, session := range tx.Sessions {
		selectedSessions = append(selectedSessions, session)
		selectedKeys = append(selectedKeys, session.Key)
	}
	ue.StartTimer(s1ReleaseRABRTimerName, s1ReleaseRABRTimeout, func() {
		s.handleS1ReleaseRABRTimeout(mmeUEID)
	})
	ue.Unlock()

	s.log.Info("s1ap: preparing Release Access Bearers requests",
		zap.String("event", "rabr_prepare"),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.Int("pdn_count", len(selectedSessions)),
		zap.Int("active_session_count", len(selectedSessions)),
		zap.Strings("selected_sessions", selectedKeys),
		zap.String("ecm_state", ecmState),
		zap.String("emm_state", emmState),
		zap.String("release_cause", tx.ReleaseCause))

	for _, session := range selectedSessions {
		req := &gtpv2.ReleaseAccessBearersRequest{
			SGWAddress:       session.SGWS11Addr,
			SGWC_TEID:        session.SGWS11TEID,
			OriginatingNode:  gtpv2.NodeTypeMME,
			MMES11TEID:       session.MMES11TEID,
			APN:              session.APN,
			DefaultEBI:       session.DefaultEBI,
			SessionState:     session.SessionState,
			LastS11Procedure: session.LastSuccessfulS11Procedure,
			TransactionID:    tx.ID,
		}
		seq, err := rabClient.SendRABR(mmeUEID, req)
		ue.Lock()
		if current := ue.S1ReleaseRABR; current != nil && current.ID == tx.ID {
			if tracked := current.Sessions[session.Key]; tracked != nil {
				if err != nil {
					tracked.ResponseAt = time.Now()
					tracked.Result = uecontext.RABRSessionLocalValidationFailed
				} else {
					tracked.Sequence = seq
					tracked.SentAt = time.Now()
				}
			}
		}
		action := s.maybeFinalizePreservedS1ReleaseLocked(ue)
		ue.Unlock()
		if err != nil {
			s.log.Warn("s1ap: Release Access Bearers Request send failed",
				zap.String("event", "rabr_send_failed"),
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("imsi", imsi),
				zap.String("apn", session.APN),
				zap.Uint8("ebi", session.DefaultEBI),
				zap.String("peer", session.SGWS11Addr),
				zap.Uint32("sgw_s11_teid", session.SGWS11TEID),
				zap.Error(err))
			if action != nil {
				s.log.Warn("s1ap: finalizing S1 release with local RABR send failures", action.LogFields...)
				s.sendUEContextReleaseCommandCause(action.ENBAddr, mmeUEID, action.ENBUEID, action.CauseGroup, action.Cause)
			}
		}
	}
	return true
}

func (s *Server) handleS1ReleaseRABRTimeout(mmeUEID uint32) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	tx := ue.S1ReleaseRABR
	if tx == nil || tx.CommandSent {
		ue.Unlock()
		return
	}
	for _, session := range tx.Sessions {
		if session != nil && session.Result == uecontext.RABRSessionPending {
			session.Result = uecontext.RABRSessionTimedOut
			session.ResponseAt = time.Now()
		}
	}
	action := s.maybeFinalizePreservedS1ReleaseLocked(ue)
	ue.Unlock()
	if action != nil {
		s.log.Warn("s1ap: RABR transaction timed out", action.LogFields...)
		s.sendUEContextReleaseCommandCause(action.ENBAddr, mmeUEID, action.ENBUEID, action.CauseGroup, action.Cause)
	}
}

func (s *Server) maybeFinalizePreservedS1ReleaseLocked(ue *uecontext.Context) *s1ReleaseRABRAction {
	tx := ue.S1ReleaseRABR
	if tx == nil || tx.CommandSent {
		return nil
	}
	var accepted, failed, timedOut int
	failedPDNs := make([]string, 0)
	failedTEIDs := make([]uint32, 0)
	causes := make([]uint8, 0)
	for _, session := range tx.Sessions {
		if session == nil {
			continue
		}
		switch session.Result {
		case uecontext.RABRSessionPending:
			return nil
		case uecontext.RABRSessionAccepted:
			accepted++
		case uecontext.RABRSessionTimedOut:
			timedOut++
			failed++
			failedPDNs = append(failedPDNs, session.APN)
			failedTEIDs = append(failedTEIDs, session.SGWS11TEID)
		default:
			failed++
			failedPDNs = append(failedPDNs, session.APN)
			failedTEIDs = append(failedTEIDs, session.SGWS11TEID)
			causes = append(causes, session.Cause)
		}
	}
	if failed == 0 {
		tx.PolicyApplied = "all_accepted"
	} else if accepted == 0 {
		tx.PolicyApplied = "all_failed_continue_s1_release"
	} else {
		tx.PolicyApplied = "partial_failure_continue_s1_release"
	}
	tx.CommandSent = true
	ue.StopTimer(s1ReleaseRABRTimerName)
	clearUEAccessPathsLocked(ue)
	enbAddr := ue.S1ReleaseENBAddr
	enbUEID := ue.S1ReleaseENBID
	group := ies.CauseGroup(ue.S1ReleaseCauseGroup)
	cause := ue.S1ReleaseCauseValue
	fields := []zap.Field{
		zap.String("event", "ecm_idle_transition"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.String("imsi", ue.IMSI),
		zap.Int("rabr_total", len(tx.Sessions)),
		zap.Int("rabr_accepted", accepted),
		zap.Int("rabr_failed", failed),
		zap.Int("rabr_timed_out", timedOut),
		zap.String("policy_applied", tx.PolicyApplied),
		zap.Strings("failed_pdns", failedPDNs),
		zap.Uint32s("failed_teids", failedTEIDs),
		zap.Uint8s("causes", causes),
	}
	return &s1ReleaseRABRAction{
		ENBAddr:    enbAddr,
		ENBUEID:    enbUEID,
		CauseGroup: group,
		Cause:      cause,
		LogFields:  fields,
	}
}

// encodeUES1APIDs encodes the UE-S1AP-IDs CHOICE (pair form) per APER X.691.
// CHOICE and SEQUENCE preamble bits are packed continuously; do not byte-align
// between the CHOICE selector and the selected UE-S1AP-ID-pair value.
func encodeUES1APIDs(mmeUEID, enbUEID uint32) []byte {
	return ies.EncodeUES1APIDPair(mmeUEID, enbUEID)
}
