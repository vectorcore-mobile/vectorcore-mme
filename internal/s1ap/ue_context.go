package s1ap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// handleUEContextReleaseRequest handles an eNB-initiated UE Context Release Request.
func (s *Server) handleUEContextReleaseRequest(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, _ := ies.DecodeMMEUEApID(ie.Value)
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, _ := ies.DecodeENBUEApID(ie.Value)
			enbUEID = id
		}
	}

	s.log.Info("s1ap: UE Context Release Request",
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID))

	if ue, ok := s.findUEByS1APIDs(remoteAddr, mmeUEID, enbUEID); ok {
		ue.Lock()
		if mmeUEID == 0 {
			mmeUEID = ue.MMEUES1APID
		}
		if enbUEID == 0 {
			enbUEID = ue.ENBS1APID
		}
		ue.Unlock()
	}
	if mmeUEID == 0 {
		s.log.Warn("s1ap: UE Context Release Request missing resolvable MME UE S1AP ID",
			zap.String("remote", remoteAddr),
			zap.Uint32("enb_ue_id", enbUEID))
		return
	}
	s.sendUEContextReleaseCommand(remoteAddr, mmeUEID, enbUEID)
}

// handleUEContextReleaseComplete handles an eNB confirmation of context release.
func (s *Server) handleUEContextReleaseComplete(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32

	for _, ie := range ieList {
		if ie.ID == pdu.IEMMEUES1APID {
			id, _ := ies.DecodeMMEUEApID(ie.Value)
			mmeUEID = id
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID))
	log.Info("s1ap: UE Context Release Complete")

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	emmState := ue.EMMState
	imsi := ue.IMSI
	ue.StopAllTimers()

	switch emmState {
	case emm.StateRegistered:
		// If the release arrived from a different eNB than the UE's current eNB, this is
		// a stale release from the old source after a successful S1 handover. The UE is
		// already connected to the target — clobbering ENBGlobalID here would break DL NAS
		// and make PageUE think the UE is idle while it's actually connected to the target.
		if ue.ENBGlobalID != "" && ue.ENBGlobalID != remoteAddr {
			ue.Unlock()
			log.Info("s1ap: stale UE Context Release Complete (post-HO source), ignoring",
				zap.String("current_enb", ue.ENBGlobalID),
				zap.String("release_from", remoteAddr))
			return
		}
		// UE released S1 without detaching — keep context as ECM-IDLE so it can be paged.
		ue.SetECMState(emm.ECMIdle)
		ue.ENBS1APID = 0
		ue.ENBGlobalID = "" // must be cleared: handleDisconnect matches on this field
		ue.ENBU_TEID = 0
		ue.ENBU_IP = nil
		dbState := ue.EMMState.String()
		dbMmeID := ue.MMEUES1APID
		ue.Unlock()

		log.Info("s1ap: UE going ECM-IDLE (registered)", zap.String("imsi", imsi))
		metrics.S1APMessagesTotal.WithLabelValues("UEContextRelease", "inbound", "idle").Inc()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.store.UpsertUEContext(ctx, buildIdleDBContext(ue, dbMmeID, imsi, dbState)); err != nil {
				s.log.Warn("s1ap: failed to persist ECM-IDLE context",
					zap.Uint32("mme_ue_id", dbMmeID), zap.String("imsi", imsi), zap.Error(err))
			}
		}()
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

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.DeleteUEContext(ctx, mmeUEID); err != nil {
			s.log.Warn("s1ap: failed to delete UE context from DB",
				zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Error(err))
		}
	}()
}

// buildIdleDBContext constructs a models.UEContext snapshot for an ECM-IDLE UE.
// Called without the UE lock held — all fields passed explicitly to avoid races.
func buildIdleDBContext(ue *uecontext.Context, mmeID uint32, imsi, emmState string) *models.UEContext {
	ue.Lock()
	defer ue.Unlock()
	dbCtx := &models.UEContext{
		MMEUES1APID:  mmeID,
		IMSI:         imsi,
		EMMState:     emmState,
		KASME:        append([]byte(nil), ue.KASME...),
		KNASint:      append([]byte(nil), ue.KNASint...),
		KNASenc:      append([]byte(nil), ue.KNASenc...),
		ULNASCount:   uint32(ue.ULNASCount),
		DLNASCount:   uint32(ue.DLNASCount),
		IntAlg:       ue.IntAlg,
		EncAlg:       ue.EncAlg,
		ENBGlobalID:  ue.ENBGlobalID,
		DefaultEBI:   uint32(ue.DefaultEBI),
		SGWU_TEID:    ue.SGWU_TEID,
		SGWC_TEID:    ue.SGWC_TEID,
		LastModified: time.Now().UTC().Format(time.RFC3339),
	}
	if ue.MSISDN != "" {
		ms := ue.MSISDN
		dbCtx.MSISDN = &ms
	}
	if ue.APN != "" {
		a := ue.APN
		dbCtx.APN = &a
	}
	if ue.UEIPv4 != nil {
		dbCtx.UEIPv4 = ue.UEIPv4.String()
	}
	if ue.SGWU_IP != nil {
		dbCtx.SGWU_IP = ue.SGWU_IP.String()
	}
	if ue.SGWC_IP != nil {
		dbCtx.SGWC_IP = ue.SGWC_IP.String()
	}
	if ue.GUTI != nil {
		g := uecontext.SerialiseGUTI(ue.GUTI)
		dbCtx.GUTI = &g
	}
	if ue.TAI != nil {
		tai := fmt.Sprintf("%02X%02X%02X-%04X",
			ue.TAI.PLMN[0], ue.TAI.PLMN[1], ue.TAI.PLMN[2], ue.TAI.TAC)
		dbCtx.TAI = tai
	}
	return dbCtx
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
		zap.String("erab_setup_list_hex", truncateHex(erabSetupList, 96)),
		zap.Int("erab_failed_to_setup_list_len", len(erabFailedList)),
		zap.String("erab_failed_to_setup_list_hex", truncateHex(erabFailedList, 96)))

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	// Try to extract the eNB S1-U TEID from the E-RAB setup list (IE 51).
	var erabSetup *icsResponseERABSetup
	if len(erabSetupList) > 0 {
		setup, err := decodeICSResponseERABSetup(erabSetupList)
		if err != nil {
			log.Warn("s1ap: Initial Context Setup Response E-RAB setup decode failed",
				zap.Error(err),
				zap.String("erab_setup_list_hex", truncateHex(erabSetupList, 128)))
		} else {
			erabSetup = setup
			log.Info("s1ap: Initial Context Setup Response E-RAB setup item",
				zap.Uint8("erab_id", setup.ERABID),
				zap.String("enb_s1u_ipv4", setup.ENBUIP.String()),
				zap.Uint32("enb_s1u_teid", setup.ENBUTEID),
				zap.String("enb_s1u_teid_hex", fmt.Sprintf("0x%08x", setup.ENBUTEID)),
				zap.String("item_hex", truncateHex(setup.ItemValue, 96)))
		}
	}

	ue.Lock()
	attachStep := ue.AttachStep
	ue.SetECMState(emm.ECMConnected)
	if erabSetup != nil && erabSetup.ENBUTEID != 0 {
		ue.ENBU_TEID = erabSetup.ENBUTEID
		ue.ENBU_IP = erabSetup.ENBUIP
	}
	if attachStep != uecontext.AttachStepWaitingICSRespSR {
		ue.AttachStep = uecontext.AttachStepWaitingAttachCplt
	}
	ue.Unlock()

	metrics.S1APMessagesTotal.WithLabelValues("InitialContextSetup", "inbound", "success").Inc()
	if attachStep == uecontext.AttachStepWaitingICSRespSR {
		s.handleServiceRequestReestablished(ue, log)
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

	// Each item is an inner IE field: [id:2B aligned][crit:2bits][opentype len][value]
	// Read one item.
	ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB setup item IE ID: %w", err)
	}
	if uint16(ieID) != pdu.IEERABSetupItemCtxtSURes {
		return nil, fmt.Errorf("unexpected E-RAB setup item IE ID %d", ieID)
	}
	_, err = aper.DecodeCriticality(r)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB setup item criticality: %w", err)
	}
	itemBytes, err := aper.ReadOpenType(r)
	if err != nil {
		return nil, fmt.Errorf("read E-RAB setup item open type: %w", err)
	}

	// Decode E-RABSetupItemCtxtSURes SEQUENCE
	ir := aper.NewBitReader(itemBytes)
	// extension marker
	if _, err := ir.ReadBit(); err != nil {
		return nil, fmt.Errorf("decode E-RAB setup item extension bit: %w", err)
	}
	// optional iE-Extensions bit
	if _, err := ir.ReadBit(); err != nil {
		return nil, fmt.Errorf("decode E-RAB setup item optional bitmap: %w", err)
	}
	// E-RAB-ID (0..15)
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB ID: %w", err)
	}
	// transportLayerAddress BIT STRING (1..160,...): ext=0, constrained len, then IP bytes
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

	// GTP-TEID OCTET STRING (SIZE 4) — fixed, no length prefix
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
	if attachStep == uecontext.AttachStepWaitingICSRespSR {
		ue.SetEMMState(emm.StateRegistered)
		ue.SetECMState(emm.ECMIdle)
		ue.AttachStep = uecontext.AttachStepNone
	}
	ue.Unlock()

	if attachStep != uecontext.AttachStepWaitingICSRespSR {
		// Release any S-GW session that was established before the ICS failure.
		// sendDeleteSession is idempotent (checks SGWC_TEID before sending).
		s.sendDeleteSession(ue)
		s.ueManager.Remove(ue)
	} else {
		// For Service Request ICS failure: keep UE and S-GW session; UE stays in idle mode.
		metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
	}
	metrics.S1APMessagesTotal.WithLabelValues("InitialContextSetup", "inbound", "failure").Inc()
}

// handleErrorIndication handles an S1AP Error Indication from an eNB.
func (s *Server) handleErrorIndication(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	fields := []zap.Field{zap.String("remote", remoteAddr)}
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			if id, err := ies.DecodeMMEUEApID(ie.Value); err == nil {
				fields = append(fields, zap.Uint32("mme_ue_id", id))
			}
		case pdu.IEENBS1APID:
			if id, err := ies.DecodeENBUEApID(ie.Value); err == nil {
				fields = append(fields, zap.Uint32("enb_ue_id", id))
			}
		case pdu.IECause:
			if group, cause, err := ies.DecodeCause(ie.Value); err == nil {
				fields = append(fields,
					zap.Uint8("cause_group", uint8(group)),
					zap.Uint8("cause", cause))
			}
		case pdu.IECriticalityDiagnostics:
			fields = append(fields, zap.Bool("criticality_diagnostics_present", true))
		}
	}
	s.log.Warn("s1ap: ErrorIndication received", fields...)
	metrics.S1APMessagesTotal.WithLabelValues("ErrorIndication", "inbound", "ok").Inc()
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
	s.sendToAddr(enbAddr, msg)
	metrics.S1APMessagesTotal.WithLabelValues("UEContextRelease", "outbound", "command").Inc()
}

// encodeUES1APIDs encodes the UE-S1AP-IDs CHOICE (pair form) per APER X.691.
// CHOICE with extension marker: ext=0 (1 bit), index=0 (1 bit), then byte-align.
// SEQUENCE preamble: ext=0 (1 bit), then byte-align.
// MME-UE-S1AP-ID (0..4294967295) + ENB-UE-S1AP-ID (0..16777215).
func encodeUES1APIDs(mmeUEID, enbUEID uint32) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // CHOICE: no extension
	w.WriteBit(0) // CHOICE: index = 0 (uE-S1AP-ID-pair)
	w.AlignToByte()
	w.WriteBit(0) // SEQUENCE: no extension
	w.AlignToByte()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(mmeUEID), 0, 4294967295)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(enbUEID), 0, 16777215)
	return w.Bytes()
}
