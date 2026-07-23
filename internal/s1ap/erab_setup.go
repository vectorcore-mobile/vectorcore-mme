package s1ap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	imsModifyBearerTimeout     = 2 * time.Second
	imsModifyBearerSettleDelay = 750 * time.Millisecond
	// The SGW's linked Create Bearer arrived 9.080 ms after the IMS CSRsp in
	// the Nokia capture. Keep the initial default activation for 20 ms so the
	// immediately associated dedicated bearers can share one E-RAB Setup.
	imsInitialERABAggregationWindow = 20 * time.Millisecond
)

func imsModifyBearerTimerName(ebi uint8) string {
	return fmt.Sprintf("IMSModifyBearer:%d", ebi)
}

func imsModifyBearerSettleTimerName(ebi uint8) string {
	return fmt.Sprintf("IMSModifyBearerSettle:%d", ebi)
}

func imsInitialERABAggregationTimerName(ebi uint8) string {
	return fmt.Sprintf("IMSInitialERABAggregation:%d", ebi)
}

type ERABSetupItem struct {
	EBI                     uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	BearerQoS               []byte
	SGWS1UIPv4              net.IP
	SGWS1UTEID              uint32
	NASPDU                  []byte
}

type ERABSetupResult struct {
	EBI        uint8
	Success    bool
	ENBS1UIPv4 net.IP
	ENBS1UTEID uint32
	CauseGroup uint8
	Cause      uint32
}

// initialIMSBearerSetupPlan is made while holding the UE lock. Marking the
// staged activation consumed before releasing that lock guarantees that only
// one handler or timer callback can dispatch the initial E-RAB Setup.
type initialIMSBearerSetupPlan struct {
	MMEUEID        uint32
	Items          []ERABSetupItem
	TransactionID  string
	TransactionKey string
	Aggregated     bool
	Generation     uint64
	Trigger        string
}

func defaultIMSERABSetupItem(pdn *uecontext.PDNContext, nasPDU []byte) ERABSetupItem {
	return ERABSetupItem{
		EBI:                     pdn.DefaultEBI,
		QCI:                     pdn.QCI,
		ARPPriority:             pdn.ARPPriority,
		PreemptionCapability:    pdn.PreemptionCapability,
		PreemptionVulnerability: pdn.PreemptionVulnerability,
		SGWS1UIPv4:              append(net.IP(nil), pdn.SGWU_IP...),
		SGWS1UTEID:              pdn.SGWU_TEID,
		NASPDU:                  append([]byte(nil), nasPDU...),
	}
}

// stageInitialIMSDefaultERABActivation starts a short, bounded procedure
// window for an initial linked Create Bearer Request. NAS COUNT is consumed
// when the activation is staged, so any dedicated NAS PDUs built during the
// window use the next count values.
func (s *Server) stageInitialIMSDefaultERABActivation(ue *uecontext.Context, pdn *uecontext.PDNContext, plain, protected []byte, log *zap.Logger) {
	if ue == nil || pdn == nil {
		return
	}
	ue.Lock()
	pdn.InitialERABAggregationPending = true
	pdn.InitialERABActivationNAS = append([]byte(nil), protected...)
	pdn.ActivationPlainNAS = append([]byte(nil), plain...)
	pdn.State = "initial-erab-aggregation-pending"
	pdn.InitialERABAggregationGeneration++
	generation := pdn.InitialERABAggregationGeneration
	ue.DLNASCount.Increment()
	ue.LastDownlinkNASMessage = "Activate Default EPS Bearer Context Request"
	mmeUEID := ue.MMEUES1APID
	ebi := pdn.DefaultEBI
	ue.StartTimer(imsInitialERABAggregationTimerName(ebi), imsInitialERABAggregationWindow, func() {
		s.flushInitialIMSDefaultERABActivation(mmeUEID, ebi, generation)
	})
	plan, err := s.maybeFlushInitialIMSBearerSetupLocked(ue, pdn, "create-session-response", false)
	ue.Unlock()
	if err != nil {
		log.Warn("s1ap: failed to reconcile staged IMS initial bearer setup", zap.Error(err), zap.Uint8("ebi", ebi))
		return
	}
	if plan != nil {
		s.dispatchInitialIMSBearerSetup(plan)
		return
	}
	log.Debug("s1ap: IMS default bearer aggregation window started",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("ebi", ebi),
		zap.Uint64("aggregation_generation", generation),
		zap.Duration("window", imsInitialERABAggregationWindow))
}

// maybeFlushInitialIMSBearerSetupLocked reconciles the staged default bearer
// and an already-pending linked Create Bearer transaction without depending on
// which S11 handler won scheduling. The caller owns ue.Lock().
func (s *Server) maybeFlushInitialIMSBearerSetupLocked(ue *uecontext.Context, pdn *uecontext.PDNContext, trigger string, timerExpired bool) (*initialIMSBearerSetupPlan, error) {
	if ue == nil || pdn == nil || !pdn.InitialERABAggregationPending {
		return nil, nil
	}
	var key string
	var linkedTx *uecontext.DedicatedBearerTransaction
	for candidateKey, tx := range ue.PendingBearerTransactions {
		if tx != nil && tx.Kind == bearerTxCreate && tx.LinkedEBI == pdn.DefaultEBI && !isCreateBearerTerminal(tx.CreateState) && (tx.CreateState == uecontext.CreateBearerReceived || tx.CreateState == uecontext.CreateBearerWaitingForLink) {
			key, linkedTx = candidateKey, tx
			break
		}
	}
	if linkedTx == nil && !timerExpired {
		return nil, nil
	}

	nasPDU := append([]byte(nil), pdn.InitialERABActivationNAS...)
	items := []ERABSetupItem{defaultIMSERABSetupItem(pdn, nasPDU)}
	plan := &initialIMSBearerSetupPlan{
		MMEUEID:    ue.MMEUES1APID,
		Generation: pdn.InitialERABAggregationGeneration,
		Trigger:    trigger,
	}
	if linkedTx != nil {
		dedicatedItems, err := buildCreateBearerERABItemsLocked(ue, linkedTx)
		if err != nil {
			return nil, err
		}
		items = append(items, dedicatedItems...)
		linkedTx.CreateState = uecontext.CreateBearerSettingUpERAB
		linkedTx.State = string(linkedTx.CreateState)
		plan.TransactionID = linkedTx.ID
		plan.TransactionKey = key
		plan.Aggregated = true
	} else {
		plan.TransactionID = fmt.Sprintf("ims-erab-%d-%d", ue.MMEUES1APID, pdn.DefaultEBI)
	}
	pdn.InitialERABAggregationPending = false
	pdn.InitialERABActivationNAS = nil
	pdn.InitialERABAggregationGeneration++ // invalidates a running stale callback
	pdn.State = "erab-setup-pending"
	ue.StopTimer(imsInitialERABAggregationTimerName(pdn.DefaultEBI))
	plan.Items = items
	return plan, nil
}

func (s *Server) dispatchInitialIMSBearerSetup(plan *initialIMSBearerSetupPlan) {
	if plan == nil {
		return
	}
	ebis := make([]uint8, 0, len(plan.Items))
	for _, item := range plan.Items {
		ebis = append(ebis, item.EBI)
	}
	mode := "fallback"
	if plan.Aggregated {
		mode = "aggregated"
	}
	procedureKind := "ims_default_bearer"
	if plan.Aggregated {
		procedureKind = "ims_initial_aggregate"
	}
	if err := s.SendERABSetupRequestTracked(plan.MMEUEID, plan.Items, procedureKind, plan.TransactionID); err != nil {
		s.log.Warn("s1ap: initial IMS E-RAB Setup Request failed", zap.Uint32("mme_ue_id", plan.MMEUEID), zap.String("transaction_id", plan.TransactionID), zap.Error(err))
		if plan.Aggregated {
			if ue, ok := s.ueManager.GetByMMEID(plan.MMEUEID); ok {
				s.failCreateBearerTransaction(ue, plan.TransactionKey, gtpv2.CauseRequestDenied)
			}
		}
		return
	}
	s.log.Info("s1ap: initial IMS E-RAB Setup Request sent", zap.Uint32("mme_ue_id", plan.MMEUEID), zap.Uint8s("erab_ebis", ebis), zap.String("mode", mode), zap.String("trigger", plan.Trigger), zap.Uint64("aggregation_generation", plan.Generation), zap.String("linked_create_bearer_transaction_id", plan.TransactionID))
	s.onInitialIMSERABSetupTransmitted(plan.MMEUEID, plan.Items, plan.TransactionKey, plan.TransactionID)
	if plan.Aggregated {
		if ue, ok := s.ueManager.GetByMMEID(plan.MMEUEID); ok {
			ue.Lock()
			if tx := ue.PendingBearerTransactions[plan.TransactionKey]; tx != nil && tx.ID == plan.TransactionID {
				tx.CreateState = uecontext.CreateBearerWaitingResults
				tx.State = string(tx.CreateState)
			}
			ue.Unlock()
		}
	}
}

// onInitialIMSERABSetupTransmitted is the single post-wire hook for both IMS
// initial E-RAB send paths. It deliberately starts activation timers only
// after SendERABSetupRequestTracked has succeeded.
func (s *Server) onInitialIMSERABSetupTransmitted(mmeUEID uint32, items []ERABSetupItem, txKey, txID string) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	for _, item := range items {
		if len(item.NASPDU) == 0 {
			continue
		}
		if pdn := findPDNByEBI(ue, item.EBI); pdn != nil {
			s.startDefaultT3485(ue, item.EBI, item.NASPDU)
			continue
		}
		if txKey == "" {
			continue
		}
		s.startDedicatedT3485(ue, txKey, item.EBI, item.NASPDU)
	}
	s.log.Info("s1ap: initial IMS activation timers armed", zap.Uint32("mme_ue_id", mmeUEID), zap.String("transaction_id", txID), zap.String("transaction_key", txKey))
}

func findPDNByEBI(ue *uecontext.Context, ebi uint8) *uecontext.PDNContext {
	ue.Lock()
	defer ue.Unlock()
	return findPDNByLinkedEBILocked(ue, ebi)
}

func (s *Server) flushInitialIMSDefaultERABActivation(mmeUEID uint32, ebi uint8, generation uint64) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	var pdn *uecontext.PDNContext
	for _, candidate := range ue.PDNs {
		if candidate != nil && candidate.DefaultEBI == ebi {
			pdn = candidate
			break
		}
	}
	if pdn == nil || !pdn.InitialERABAggregationPending || pdn.InitialERABAggregationGeneration != generation {
		ue.Unlock()
		return
	}
	plan, err := s.maybeFlushInitialIMSBearerSetupLocked(ue, pdn, "aggregation-timer", true)
	ue.Unlock()
	if err != nil {
		s.log.Warn("s1ap: failed to reconcile IMS aggregation timer", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Error(err))
		return
	}
	s.dispatchInitialIMSBearerSetup(plan)
}

type ERABSetupResponse struct {
	MMEUEID                uint32
	ENBUEID                uint32
	Successful             []ERABSetupSuccess
	Failed                 []ERABSetupFailure
	CriticalityDiagnostics []byte
}

type ERABSetupSuccess struct {
	EBI        uint8
	ENBS1UAddr net.IP
	ENBS1UTEID uint32
}

type ERABSetupFailure struct {
	EBI        uint8
	CauseGroup uint8
	Cause      uint32
}

type UEAggregateMaximumBitrate struct {
	Downlink uint64
	Uplink   uint64
}

func (s *Server) SendERABSetupRequest(mmeUEID uint32, items []ERABSetupItem) error {
	return s.SendERABSetupRequestTracked(mmeUEID, items, "", "")
}

func (s *Server) SendERABSetupRequestTracked(mmeUEID uint32, items []ERABSetupItem, procedureKind string, transactionID string) error {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbS1APID := ue.ENBS1APID
	bindingGeneration := ue.S1BindingGeneration
	ue.Unlock()
	if enbAddr == "" {
		return fmt.Errorf("s1ap: UE %d has no active S1 binding", mmeUEID)
	}
	if transactionID != "" {
		s.registerPendingERABProcedure(ue, transactionID, procedureKind, bindingGeneration, items)
		defer func() {
			if transactionID != "" {
				ue.Lock()
				if proc := ue.PendingERABProcedures[transactionID]; proc != nil && proc.S1BindingGeneration == bindingGeneration {
					ue.Unlock()
					return
				}
				ue.Unlock()
			}
		}()
	}

	effectiveAMBR := s.logEffectiveUEAMBR(ue, "erab-setup")
	if effectiveAMBR.Downlink == 0 || effectiveAMBR.Uplink == 0 {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return fmt.Errorf("s1ap: UE %d missing effective UE AMBR for E-RAB Setup (down=%d up=%d)", mmeUEID, effectiveAMBR.Downlink, effectiveAMBR.Uplink)
	}
	msg, erabValue, err := BuildERABSetupRequest(mmeUEID, enbS1APID, &UEAggregateMaximumBitrate{
		Downlink: effectiveAMBR.Downlink,
		Uplink:   effectiveAMBR.Uplink,
	}, items)
	if err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	for _, item := range items {
		fields := []zap.Field{
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("enb_ue_id", enbS1APID),
			zap.Uint64("s1_binding_generation", bindingGeneration),
			zap.Uint8("ebi", item.EBI),
			zap.Uint8("qci", item.QCI),
			zap.Uint8("arp", item.ARPPriority),
			zap.String("sgw_s1u_ip", item.SGWS1UIPv4.String()),
			zap.Uint32("sgw_s1u_teid", item.SGWS1UTEID),
			zap.Bool("nas_pdu_present", len(item.NASPDU) > 0),
			zap.Int("nas_pdu_len", len(item.NASPDU)),
		}
		if gbr, present := deriveGBRQosInformation(item.BearerQoS); present {
			encoded, decoded, roundTripOK := encodeAndDecodeERABGBRQoSForDebug(gbr)
			fields = append(fields,
				zap.Uint64("max_dl_bps", gbr.MaxBitrateDL),
				zap.Uint64("max_ul_bps", gbr.MaxBitrateUL),
				zap.Uint64("gbr_dl_bps", gbr.GuaranteedBitrateDL),
				zap.Uint64("gbr_ul_bps", gbr.GuaranteedBitrateUL),
				zap.String("encoded_gbr_qos_bits_hex", hex.EncodeToString(encoded)),
				zap.Uint64("decoded_max_dl_bps", decoded.MaxBitrateDL),
				zap.Uint64("decoded_max_ul_bps", decoded.MaxBitrateUL),
				zap.Uint64("decoded_gbr_dl_bps", decoded.GuaranteedBitrateDL),
				zap.Uint64("decoded_gbr_ul_bps", decoded.GuaranteedBitrateUL),
				zap.Bool("gbr_qos_round_trip_ok", roundTripOK),
			)
		}
		s.log.Debug("s1ap: E-RAB Setup Request item", fields...)
	}
	s.log.Debug("s1ap: E-RAB Setup Request encoded",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("erab_setup_list_hex", hex.EncodeToString(erabValue)),
		zap.String("s1ap_hex", hex.EncodeToString(msg)))
	if err := s.sendToAddr(enbAddr, msg); err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	return nil
}

func BuildERABSetupRequest(mmeUEID uint32, enbS1APID uint32, ueAMBR *UEAggregateMaximumBitrate, items []ERABSetupItem) (msg []byte, erabList []byte, err error) {
	if len(items) == 0 {
		return nil, nil, fmt.Errorf("s1ap: E-RAB Setup Request requires at least one item")
	}
	if len(items) > 256 {
		return nil, nil, fmt.Errorf("s1ap: E-RAB Setup Request has too many items: %d", len(items))
	}
	seenEBI := map[uint8]bool{}
	for _, item := range items {
		if item.EBI > 15 {
			return nil, nil, fmt.Errorf("s1ap: invalid E-RAB ID %d", item.EBI)
		}
		if seenEBI[item.EBI] {
			return nil, nil, fmt.Errorf("s1ap: duplicate E-RAB ID %d", item.EBI)
		}
		seenEBI[item.EBI] = true
		if item.QCI > 255 {
			return nil, nil, fmt.Errorf("s1ap: invalid QCI %d", item.QCI)
		}
		if item.ARPPriority > 15 {
			return nil, nil, fmt.Errorf("s1ap: invalid ARP priority %d", item.ARPPriority)
		}
		if ip := item.SGWS1UIPv4.To4(); ip == nil {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d requires IPv4 SGW S1-U address", item.EBI)
		}
		if item.SGWS1UTEID == 0 {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d requires nonzero SGW S1-U TEID", item.EBI)
		}
		if len(item.NASPDU) == 0 {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d requires NAS-PDU", item.EBI)
		}
		if len(item.NASPDU) > aper.MaxASN1Length {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d NAS-PDU too large: %d", item.EBI, len(item.NASPDU))
		}
	}

	downlink, uplink := uint64(100000000), uint64(100000000)
	if ueAMBR != nil {
		downlink = ueAMBR.Downlink
		uplink = ueAMBR.Uplink
	}
	erabList = encodeERABSetupListBearerSUReq(items)
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
		{ID: pdu.IEUEAggregateMaxBitrate, Criticality: aper.CriticalityReject, Value: ies.EncodeUEAggregateMaxBitrate(downlink, uplink)},
		{ID: pdu.IEERABToBeSetupListBearerSUReq, Criticality: aper.CriticalityReject, Value: erabList},
	}
	return pdu.BuildInitiatingMessage(pdu.ProcERABSetup, aper.CriticalityReject, ieList), erabList, nil
}

func encodeERABSetupListBearerSUReq(items []ERABSetupItem) []byte {
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, int64(len(items)), 1, 256)
	ow.AlignToByte()
	for _, item := range items {
		itemBody := encodeERABSetupItemBody(item)
		innerContainer := pdu.EncodeIEContainer([]pdu.ProtocolIE{
			{ID: pdu.IEERABToBeSetupItemBearerSUReq, Criticality: aper.CriticalityReject, Value: itemBody},
		})
		if len(innerContainer) >= 2 {
			innerContainer = innerContainer[2:]
		}
		ow.WriteOctets(innerContainer)
	}
	return ow.Bytes()
}

func encodeERABSetupItemBody(item ERABSetupItem) []byte {
	nasPDUPresent := len(item.NASPDU) > 0
	qci := item.QCI
	if qci == 0 {
		qci = 9
	}
	arp := item.ARPPriority
	if arp == 0 {
		arp = 8
	}
	gbrInfo, gbrPresent := deriveGBRQosInformation(item.BearerQoS)

	w := aper.NewBitWriter()

	w.WriteBit(0) // E-RABToBeSetupItemBearerSUReq extension marker
	w.WriteBit(0) // iE-Extensions absent

	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)

	w.WriteBit(0) // E-RABLevelQoSParameters extension marker
	if gbrPresent {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(qci), 0, 255)

	w.WriteBit(0) // ARP extension marker
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(arp), 0, 15)
	if item.PreemptionCapability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}
	if item.PreemptionVulnerability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}
	if gbrPresent {
		w.WriteBit(0) // GBR-QosInformation extension marker
		w.WriteBit(0) // iE-Extensions absent
		encodeBitRateForERABSetup(w, gbrInfo.MaxBitrateDL)
		encodeBitRateForERABSetup(w, gbrInfo.MaxBitrateUL)
		encodeBitRateForERABSetup(w, gbrInfo.GuaranteedBitrateDL)
		encodeBitRateForERABSetup(w, gbrInfo.GuaranteedBitrateUL)
	}

	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	ip := item.SGWS1UIPv4.To4()
	if ip == nil {
		ip = net.IP{0, 0, 0, 0}
	}
	w.WriteOctets(ip[:4])

	w.AlignToByte()
	w.WriteOctet(byte(item.SGWS1UTEID >> 24))
	w.WriteOctet(byte(item.SGWS1UTEID >> 16))
	w.WriteOctet(byte(item.SGWS1UTEID >> 8))
	w.WriteOctet(byte(item.SGWS1UTEID))

	if nasPDUPresent {
		w.AlignToByte()
		_ = aper.EncodeLength(w, len(item.NASPDU), 0, -1)
		w.WriteOctets(item.NASPDU)
	}
	return w.Bytes()
}

type erabGBRQosInformation struct {
	MaxBitrateDL        uint64
	MaxBitrateUL        uint64
	GuaranteedBitrateDL uint64
	GuaranteedBitrateUL uint64
}

func deriveGBRQosInformation(bearerQoS []byte) (erabGBRQosInformation, bool) {
	if len(bearerQoS) < 22 {
		return erabGBRQosInformation{}, false
	}
	info := erabGBRQosInformation{
		MaxBitrateUL:        decodeBearerQoSBitrate(bearerQoS[2:7]),
		MaxBitrateDL:        decodeBearerQoSBitrate(bearerQoS[7:12]),
		GuaranteedBitrateUL: decodeBearerQoSBitrate(bearerQoS[12:17]),
		GuaranteedBitrateDL: decodeBearerQoSBitrate(bearerQoS[17:22]),
	}
	if info.MaxBitrateDL == 0 && info.MaxBitrateUL == 0 && info.GuaranteedBitrateDL == 0 && info.GuaranteedBitrateUL == 0 {
		return erabGBRQosInformation{}, false
	}
	return info, true
}

func decodeBearerQoSBitrate(b []byte) uint64 {
	var out uint64
	for _, octet := range b {
		out = (out << 8) | uint64(octet)
	}
	// TS 29.274 Bearer QoS carries each five-octet bitrate in kbit/s.
	// S1AP BitRate is expressed in bit/s, so preserve the unit conversion
	// already used by the GTPv2 and NAS Bearer QoS paths.
	return out * 1000
}

func encodeBitRateForERABSetup(w *aper.BitWriter, bitrate uint64) {
	const maxBitRate = 10000000000
	if bitrate > maxBitRate {
		bitrate = maxBitRate
	}
	_ = aper.EncodeConstrainedWholeNumber(w, int64(bitrate), 0, maxBitRate)
}

// encodeAndDecodeERABGBRQoSForDebug provides focused debug-level evidence for
// the four S1AP BitRate fields without decoding the complete outbound PDU.
func encodeAndDecodeERABGBRQoSForDebug(info erabGBRQosInformation) ([]byte, erabGBRQosInformation, bool) {
	w := aper.NewBitWriter()
	w.WriteBit(0) // GBR-QosInformation extension marker
	w.WriteBit(0) // iE-Extensions absent
	encodeBitRateForERABSetup(w, info.MaxBitrateDL)
	encodeBitRateForERABSetup(w, info.MaxBitrateUL)
	encodeBitRateForERABSetup(w, info.GuaranteedBitrateDL)
	encodeBitRateForERABSetup(w, info.GuaranteedBitrateUL)
	encoded := w.Bytes()

	r := aper.NewBitReader(encoded)
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		return encoded, erabGBRQosInformation{}, false
	}
	if extensions, err := r.ReadBit(); err != nil || extensions != 0 {
		return encoded, erabGBRQosInformation{}, false
	}
	decoded := erabGBRQosInformation{}
	values := []*uint64{&decoded.MaxBitrateDL, &decoded.MaxBitrateUL, &decoded.GuaranteedBitrateDL, &decoded.GuaranteedBitrateUL}
	for _, target := range values {
		value, err := aper.DecodeConstrainedWholeNumber(r, 0, 10000000000)
		if err != nil {
			return encoded, erabGBRQosInformation{}, false
		}
		*target = uint64(value)
	}
	return encoded, decoded, decoded == info
}

func decodeERABSetupResponseList(data []byte) ([]ERABSetupSuccess, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB setup response list count: %w", err)
	}
	r.AlignToByte()
	results := make([]ERABSetupSuccess, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB setup response item IE ID: %w", err)
		}
		_, err = aper.DecodeCriticality(r)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB setup response item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read E-RAB setup response item: %w", err)
		}
		if uint16(ieID) != pdu.IEERABSetupItemBearerSURes {
			return nil, fmt.Errorf("unexpected E-RAB setup response item IE ID %d", ieID)
		}
		result, err := decodeERABSetupResponseItem(itemBytes)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func decodeERABSetupResponseItem(data []byte) (ERABSetupSuccess, error) {
	ir := aper.NewBitReader(data)
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupSuccess{}, err
	}
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupSuccess{}, err
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	if erabIDExt != 0 {
		return ERABSetupSuccess{}, fmt.Errorf("E-RAB ID extension value not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	extBit, err := ir.ReadBit()
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	ir.AlignToByte()
	var addrBits int64
	if extBit == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	ir.AlignToByte()
	addrBytes, err := ir.ReadOctets(int((addrBits + 7) / 8))
	if err != nil || len(addrBytes) < 4 {
		return ERABSetupSuccess{}, fmt.Errorf("invalid transportLayerAddress")
	}
	ir.AlignToByte()
	teidBytes, err := ir.ReadOctets(4)
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	return ERABSetupSuccess{
		EBI:        uint8(erabID),
		ENBS1UAddr: net.IP(addrBytes[:4]).To4(),
		ENBS1UTEID: binary.BigEndian.Uint32(teidBytes),
	}, nil
}

func decodeERABFailedToSetupList(data []byte) ([]ERABSetupFailure, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB failed-to-setup response list count: %w", err)
	}
	r.AlignToByte()
	results := make([]ERABSetupFailure, 0, int(count))
	for i := 0; i < int(count); i++ {
		if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535); err != nil {
			return nil, fmt.Errorf("decode failed-to-setup item IE ID: %w", err)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, fmt.Errorf("decode failed-to-setup item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read failed-to-setup item: %w", err)
		}
		result, err := decodeERABFailedToSetupItem(itemBytes)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func decodeERABFailedToSetupItem(data []byte) (ERABSetupFailure, error) {
	ir := aper.NewBitReader(data)
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupFailure{}, err
	}
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupFailure{}, err
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return ERABSetupFailure{}, err
	}
	if erabIDExt != 0 {
		return ERABSetupFailure{}, fmt.Errorf("E-RAB failed item extension value not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return ERABSetupFailure{}, err
	}
	group, cause, err := decodeCauseFromBitReader(ir)
	if err != nil {
		return ERABSetupFailure{}, err
	}
	return ERABSetupFailure{
		EBI:        uint8(erabID),
		CauseGroup: uint8(group),
		Cause:      uint32(cause),
	}, nil
}

func decodeCauseFromBitReader(r *aper.BitReader) (ies.CauseGroup, uint8, error) {
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	groupBits, err := r.ReadBits(3)
	if err != nil {
		return 0, 0, err
	}
	group := ies.CauseGroup(groupBits)
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	bits := 6
	switch group {
	case ies.CauseGroupTransport:
		bits = 1
	case ies.CauseGroupNAS:
		bits = 2
	case ies.CauseGroupProtocol:
		bits = 3
	case ies.CauseGroupMisc:
		bits = 5
	}
	value, err := r.ReadBits(bits)
	if err != nil {
		return 0, 0, err
	}
	return group, uint8(value), nil
}

func decodeERABSetupResponse(_ *pdu.PDU, ieList []pdu.ProtocolIE) (*ERABSetupResponse, []uint16, []int, []string, []string, bool, string, bool, string, error) {
	resp := &ERABSetupResponse{}
	ieIDs := make([]uint16, 0, len(ieList))
	ieLengths := make([]int, 0, len(ieList))
	ieHex := make([]string, 0, len(ieList))
	unknownIEs := []string{}
	var setupList []byte
	var failedList []byte
	for _, ie := range ieList {
		ieIDs = append(ieIDs, ie.ID)
		ieLengths = append(ieLengths, len(ie.Value))
		ieHex = append(ieHex, hex.EncodeToString(ie.Value))
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			v, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				return nil, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), fmt.Errorf("decode MME-UE-S1AP-ID: %w", err)
			}
			resp.MMEUEID = v
		case pdu.IEENBS1APID:
			v, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				return nil, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), fmt.Errorf("decode eNB-UE-S1AP-ID: %w", err)
			}
			resp.ENBUEID = v
		case pdu.IEERABSetupListBearerSURes:
			setupList = ie.Value
		case pdu.IEERABFailedToSetupListBearerSURes:
			failedList = ie.Value
		case pdu.IECriticalityDiagnostics:
			resp.CriticalityDiagnostics = append([]byte(nil), ie.Value...)
		default:
			meta, ok := pdu.Phase1ProcedureIEs[pdu.ProcedureIEKey{
				ProcedureCode: pdu.ProcERABSetup,
				PDUType:       pdu.PDUTypeSuccessfulOutcome,
				IEID:          ie.ID,
			}]
			if ok {
				unknownIEs = append(unknownIEs, fmt.Sprintf("id=%d name=%s len=%d", ie.ID, meta.Name, len(ie.Value)))
			} else {
				unknownIEs = append(unknownIEs, fmt.Sprintf("id=%d len=%d", ie.ID, len(ie.Value)))
			}
		}
	}
	if len(setupList) > 0 {
		successes, err := decodeERABSetupResponseList(setupList)
		if err != nil {
			return nil, ieIDs, ieLengths, ieHex, unknownIEs, true, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), err
		}
		resp.Successful = successes
	}
	if len(failedList) > 0 {
		failures, err := decodeERABFailedToSetupList(failedList)
		if err != nil {
			return nil, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), true, hex.EncodeToString(failedList), err
		}
		resp.Failed = failures
	}
	return resp, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), nil
}

func (s *Server) handleERABSetupResponse(remoteAddr string, p *pdu.PDU, raw []byte, ieList []pdu.ProtocolIE) {
	resp, ieIDs, ieLengths, ieHex, unknownIEs, setupPresent, setupHex, failedPresent, failedHex, err := decodeERABSetupResponse(p, ieList)
	if err != nil {
		s.log.Warn("s1ap: E-RAB Setup Response decode failed",
			zap.String("remote", remoteAddr),
			zap.Uint32("procedure_code", uint32(p.ProcedureCode)),
			zap.String("pdu_choice", p.Type.String()),
			zap.String("criticality", p.Criticality.String()),
			zap.String("raw_s1ap_hex", hex.EncodeToString(raw)),
			zap.Int("ie_count", len(ieList)),
			zap.Uint16s("ie_ids", ieIDs),
			zap.Ints("ie_lengths", ieLengths),
			zap.Strings("ie_hex", ieHex),
			zap.Bool("setup_list_present", setupPresent),
			zap.String("setup_list_hex", setupHex),
			zap.Bool("failed_list_present", failedPresent),
			zap.String("failed_list_hex", failedHex),
			zap.Strings("unknown_ies", unknownIEs),
			zap.Error(err))
		return
	}
	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", resp.MMEUEID),
		zap.Uint32("enb_ue_id", resp.ENBUEID))
	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, resp.MMEUEID, resp.ENBUEID)
	if !ok {
		return
	}
	ue.Lock()
	pendingIDs, expectedEBIs, bindingGeneration := pendingERABDiagnosticsLocked(ue)
	ue.Unlock()
	if len(unknownIEs) > 0 {
		log.Warn("s1ap: E-RAB Setup Response contains unsupported IEs",
			zap.Strings("unknown_ies", unknownIEs))
	}
	log.Debug("s1ap: E-RAB Setup Response decoded",
		zap.Uint32("procedure_code", uint32(p.ProcedureCode)),
		zap.String("pdu_choice", p.Type.String()),
		zap.String("criticality", p.Criticality.String()),
		zap.String("raw_s1ap_hex", hex.EncodeToString(raw)),
		zap.Int("ie_count", len(ieList)),
		zap.Uint16s("ie_ids", ieIDs),
		zap.Ints("ie_lengths", ieLengths),
		zap.Strings("ie_hex", ieHex),
		zap.Bool("setup_list_present", setupPresent),
		zap.String("setup_list_hex", setupHex),
		zap.Bool("failed_list_present", failedPresent),
		zap.String("failed_list_hex", failedHex),
		zap.Strings("pending_transaction_ids", pendingIDs),
		zap.Uint8s("expected_ebis", expectedEBIs),
		zap.Uint64("s1_binding_generation", bindingGeneration))
	received := map[uint8]struct{}{}
	successEBIs := make([]uint8, 0, len(resp.Successful))
	for _, result := range resp.Successful {
		successEBIs = append(successEBIs, result.EBI)
		received[result.EBI] = struct{}{}
		log.Debug("s1ap: E-RAB Setup Response item",
			zap.Uint8("ebi", result.EBI),
			zap.Bool("success", true),
			zap.String("enb_s1u_ip", result.ENBS1UAddr.String()),
			zap.Uint32("enb_s1u_teid", result.ENBS1UTEID))
	}
	failedEBIs := make([]uint8, 0, len(resp.Failed))
	for _, result := range resp.Failed {
		failedEBIs = append(failedEBIs, result.EBI)
		received[result.EBI] = struct{}{}
		log.Debug("s1ap: E-RAB Setup Response item",
			zap.Uint8("ebi", result.EBI),
			zap.Bool("success", false),
			zap.Uint8("cause_group", result.CauseGroup),
			zap.Uint32("cause", result.Cause))
	}
	if len(resp.Successful) == 0 && len(resp.Failed) == 0 {
		log.Warn("s1ap: E-RAB Setup Response contains no setup or failure items")
		return
	}
	ue.Lock()
	proc, matchReason, ambiguous := matchPendingERABProcedureLocked(ue, received)
	ue.Unlock()
	if proc == nil {
		log.Warn("s1ap: E-RAB Setup Response could not be correlated",
			zap.Uint8s("received_success_ebis", successEBIs),
			zap.Uint8s("received_failed_ebis", failedEBIs),
			zap.Bool("ambiguous", ambiguous))
		return
	}
	matchedExpected := sortedExpectedEBIs(proc.ExpectedEBIs)
	log.Debug("s1ap: E-RAB Setup Response correlated",
		zap.Uint8s("received_success_ebis", successEBIs),
		zap.Uint8s("received_failed_ebis", failedEBIs),
		zap.String("matched_transaction_id", proc.TransactionID),
		zap.Uint8s("expected_ebis", matchedExpected),
		zap.String("match_reason", matchReason),
		zap.Bool("ambiguous", ambiguous))
	s.applyERABSetupResponseForProcedure(ue, proc, resp, log)
}

func (s *Server) applyERABSetupResponseForProcedure(ue *uecontext.Context, proc *uecontext.PendingERABProcedure, resp *ERABSetupResponse, log *zap.Logger) {
	for _, success := range resp.Successful {
		result := ERABSetupResult{
			EBI:        success.EBI,
			Success:    true,
			ENBS1UIPv4: append(net.IP(nil), success.ENBS1UAddr...),
			ENBS1UTEID: success.ENBS1UTEID,
		}
		if proc.ProcedureKind == "dedicated_create_bearer" || (proc.ProcedureKind == "ims_initial_aggregate" && !isDefaultPDNEBILocked(ue, result.EBI)) {
			s.completeDedicatedERABSetupForBearer(ue, result, log)
			continue
		}
		s.completeIMSDefaultERABSetupForBearer(ue, result, log)
	}
	for _, failure := range resp.Failed {
		result := ERABSetupResult{
			EBI:        failure.EBI,
			Success:    false,
			CauseGroup: failure.CauseGroup,
			Cause:      failure.Cause,
		}
		if proc.ProcedureKind == "dedicated_create_bearer" || (proc.ProcedureKind == "ims_initial_aggregate" && !isDefaultPDNEBILocked(ue, result.EBI)) {
			s.completeDedicatedERABSetupForBearer(ue, result, log)
			continue
		}
		s.completeIMSDefaultERABSetupForBearer(ue, result, log)
		if proc.ProcedureKind == "ims_initial_aggregate" {
			s.failPendingCreateBearersForLinkedEBI(ue, result.EBI, gtpv2.CauseRequestRejected, "initial_aggregate_default_erab_failed")
		}
	}
	ue.Lock()
	allCovered := true
	for ebi := range proc.ExpectedEBIs {
		if !containsERABResult(resp.Successful, resp.Failed, ebi) {
			allCovered = false
			break
		}
	}
	if allCovered {
		delete(ue.PendingERABProcedures, proc.TransactionID)
	}
	ue.Unlock()
}

func isDefaultPDNEBILocked(ue *uecontext.Context, ebi uint8) bool {
	ue.Lock()
	defer ue.Unlock()
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == ebi {
			return true
		}
	}
	return false
}

func (s *Server) completeIMSDefaultERABSetupForBearer(ue *uecontext.Context, result ERABSetupResult, log *zap.Logger) {
	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == result.EBI {
			target = pdn
			break
		}
	}
	if target == nil {
		ue.Unlock()
		log.Warn("s1ap: E-RAB Setup Response for unknown EBI", zap.Uint8("ebi", result.EBI))
		return
	}
	if !result.Success {
		target.ERABEstablished = false
		target.State = "erab-setup-failed"
		apn := target.APN
		ue.Unlock()
		log.Warn("s1ap: IMS E-RAB Setup failed",
			zap.String("apn", apn),
			zap.Uint8("ebi", result.EBI),
			zap.Uint8("cause_group", result.CauseGroup),
			zap.Uint32("cause", result.Cause))
		return
	}
	target.ENBU_TEID = result.ENBS1UTEID
	target.ENBU_IP = append(net.IP(nil), result.ENBS1UIPv4...)
	target.ERABEstablished = true
	apn := target.APN
	if target.ModifyBearerAccepted {
		target.State = "active"
	} else {
		target.State = "access-established"
	}
	ue.Unlock()

	log.Info("s1ap: IMS default bearer access established",
		zap.String("apn", apn),
		zap.Uint8("ebi", result.EBI),
		zap.Bool("modify_bearer_accepted", target.ModifyBearerAccepted))
	s.maybeAdvanceDefaultBearer(ue, result.EBI, "erab-established", log)
}

func (s *Server) maybeAdvanceDefaultBearer(ue *uecontext.Context, ebi uint8, trigger string, log *zap.Logger) {
	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == ebi {
			target = pdn
			break
		}
	}
	if target == nil {
		ue.Unlock()
		return
	}
	nasAccepted := target.NASAccepted
	erabEstablished := target.ERABEstablished
	modifyBearerSent := target.ModifyBearerSent
	modifyBearerAccepted := target.ModifyBearerAccepted
	modifyBearerFailed := target.ModifyBearerFailed
	linkedBearerReady := nasAccepted && erabEstablished && modifyBearerAccepted
	if linkedBearerReady {
		target.State = "active"
		ue.Unlock()
		log.Info("s1ap: IMS default bearer ready",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.Bool("linked_bearer_ready", linkedBearerReady),
			zap.String("trigger", trigger))
		s.resumePendingCreateBearersForLinkedEBI(ue, ebi, "modify_bearer_accepted")
		return
	}
	if modifyBearerFailed {
		target.State = "modify-bearer-failed"
		ue.Unlock()
		log.Warn("s1ap: IMS default bearer advance blocked by Modify Bearer failure",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.Bool("linked_bearer_ready", linkedBearerReady),
			zap.String("trigger", trigger))
		s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_failed")
		return
	}
	// A Create Bearer Request is an outstanding S11 procedure for this PDN.
	// Complete its access-side transaction first, then send the default-bearer
	// MBR from advanceLinkedDefaultBearerAfterCreateBearerResponse. This avoids
	// an SGW transaction collision without making the dedicated bearer depend on
	// the default MBR response (NAS+E-RAB is sufficient to activate it).
	if hasPendingCreateBearerForLinkedEBILocked(ue, ebi) {
		if nasAccepted && erabEstablished && !modifyBearerSent {
			target.ModifyBearerDeferred = true
			target.State = "access-established"
		}
		ue.Unlock()
		if nasAccepted && erabEstablished && !modifyBearerSent {
			log.Info("s1ap: IMS Modify Bearer deferred behind outstanding Create Bearer",
				zap.Uint8("ebi", ebi), zap.String("trigger", trigger))
			s.resumePendingCreateBearersForLinkedEBI(ue, ebi, "default_access_ready")
		}
		return
	}
	if !nasAccepted || !erabEstablished || modifyBearerSent {
		if nasAccepted && erabEstablished {
			if modifyBearerSent && !modifyBearerAccepted && !modifyBearerFailed {
				target.State = "modify-bearer-pending"
			} else {
				target.State = "access-established"
			}
		}
		ue.Unlock()
		log.Debug("s1ap: IMS default bearer waiting for completion",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.Bool("linked_bearer_ready", linkedBearerReady),
			zap.String("trigger", trigger))
		return
	}
	// Dedicated Create Bearer requests can arrive before this default bearer is
	// complete. Keep them queued until Modify Bearer succeeds; never make the
	// default bearer wait for their completion.
	target.ModifyBearerDeferred = false
	target.State = "access-established"
	ue.Unlock()
	s.sendIMSModifyBearerNow(ue, ebi, trigger, log)
}

func (s *Server) startIMSModifyBearerTimer(ue *uecontext.Context, ebi uint8) {
	if ue == nil || ebi == 0 {
		return
	}
	timerName := imsModifyBearerTimerName(ebi)
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.StartTimer(timerName, imsModifyBearerTimeout, func() {
		s.onIMSModifyBearerTimeout(mmeUEID, ebi)
	})
	ue.Unlock()
}

func (s *Server) sendIMSModifyBearerNow(ue *uecontext.Context, ebi uint8, trigger string, log *zap.Logger) {
	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == ebi {
			target = pdn
			break
		}
	}
	if target == nil || !target.NASAccepted || !target.ERABEstablished || target.ModifyBearerSent || target.ModifyBearerAccepted || target.ModifyBearerFailed {
		ue.Unlock()
		return
	}
	target.ModifyBearerDeferred = false
	target.ModifyBearerSent = true
	target.State = "modify-bearer-pending"
	mmeUEID := ue.MMEUES1APID
	mbr := &gtpv2.ModifyBearerRequest{
		SGWAddress:            target.SGWAddress,
		SGWC_TEID:             target.SGWC_TEID,
		EBI:                   target.DefaultEBI,
		ENBU_TEID:             target.ENBU_TEID,
		ENBU_IP:               append(net.IP(nil), target.ENBU_IP...),
		RATType:               gtpv2.RATTypeEUTRAN,
		IncludeIndicationCRSI: true,
		OmitRATType:           true,
	}
	apn := target.APN
	imsi := ue.IMSI
	ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
	ue.Unlock()

	log.Debug("s1ap: sending IMS S11 Modify Bearer Request",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi),
		zap.Uint32("sgwc_teid", mbr.SGWC_TEID),
		zap.String("sequence_number", "allocated-in-s11-client"),
		zap.Uint32("enb_s1u_teid", mbr.ENBU_TEID),
		zap.String("enb_s1u_ipv4", mbr.ENBU_IP.String()),
		zap.String("trigger", trigger))
	if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
		log.Warn("s1ap: IMS SendMBR failed", zap.String("apn", apn), zap.Uint8("ebi", ebi), zap.Error(err))
		ue.Lock()
		if current := findPDNByLinkedEBILocked(ue, ebi); current != nil {
			current.ModifyBearerDeferred = false
			current.ModifyBearerSent = false
			current.ModifyBearerFailed = true
			current.State = "modify-bearer-failed"
		}
		ue.Unlock()
		s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_send_failed")
		return
	}
	s.startIMSModifyBearerTimer(ue, ebi)
}

func (s *Server) onIMSModifyBearerSettleTimeout(mmeUEID uint32, ebi uint8) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	target := findPDNByLinkedEBILocked(ue, ebi)
	if target == nil || !target.ModifyBearerDeferred || target.ModifyBearerSent || target.ModifyBearerAccepted || target.ModifyBearerFailed {
		ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
		ue.Unlock()
		return
	}
	if hasPendingCreateBearerForLinkedEBILocked(ue, ebi) {
		imsi := ue.IMSI
		apn := target.APN
		ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
		ue.StartTimer(imsModifyBearerSettleTimerName(ebi), imsModifyBearerSettleDelay, func() {
			s.onIMSModifyBearerSettleTimeout(mmeUEID, ebi)
		})
		ue.Unlock()
		s.log.Info("s1ap: IMS Modify Bearer settle delayed by additional linked Create Bearer activity",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("ebi", ebi))
		return
	}
	ue.Unlock()
	s.sendIMSModifyBearerNow(ue, ebi, "linked-bearer-settled", s.log)
}

func (s *Server) onIMSModifyBearerTimeout(mmeUEID uint32, ebi uint8) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == ebi {
			target = pdn
			break
		}
	}
	if target == nil || !target.ModifyBearerSent || target.ModifyBearerAccepted || target.ModifyBearerFailed || target.State != "modify-bearer-pending" {
		ue.StopTimer(imsModifyBearerTimerName(ebi))
		ue.Unlock()
		return
	}

	apn := target.APN
	imsi := ue.IMSI
	sgwAddr := target.SGWAddress
	sgwcTEID := target.SGWC_TEID
	enbTEID := target.ENBU_TEID
	enbIP := append(net.IP(nil), target.ENBU_IP...)
	fallbackSent := target.ModifyBearerFallbackSent

	if !fallbackSent && sgwcTEID != 0 && enbTEID != 0 && enbIP != nil {
		target.ModifyBearerFallbackSent = true
		ue.StopTimer(imsModifyBearerTimerName(ebi))
		ue.StartTimer(imsModifyBearerTimerName(ebi), imsModifyBearerTimeout, func() {
			s.onIMSModifyBearerTimeout(mmeUEID, ebi)
		})
		ue.Unlock()

		s.log.Warn("s1ap: IMS Modify Bearer timeout; sending standalone fallback MBR",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("ebi", ebi))
		if err := s.s11.SendMBR(mmeUEID, &gtpv2.ModifyBearerRequest{
			SGWAddress:            sgwAddr,
			SGWC_TEID:             sgwcTEID,
			EBI:                   ebi,
			ENBU_TEID:             enbTEID,
			ENBU_IP:               enbIP,
			RATType:               gtpv2.RATTypeEUTRAN,
			IncludeIndicationCRSI: true,
			OmitRATType:           true,
		}); err != nil {
			ue.Lock()
			if current := findPDNByLinkedEBILocked(ue, ebi); current != nil && current.State == "modify-bearer-pending" {
				current.ModifyBearerFailed = true
				current.State = "modify-bearer-failed"
			}
			ue.StopTimer(imsModifyBearerTimerName(ebi))
			ue.Unlock()
			s.log.Warn("s1ap: standalone IMS fallback MBR send failed",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("imsi", imsi),
				zap.String("apn", apn),
				zap.Uint8("ebi", ebi),
				zap.Error(err))
			s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_fallback_send_failed")
		}
		return
	}

	target.ModifyBearerFailed = true
	target.State = "modify-bearer-failed"
	ue.StopTimer(imsModifyBearerTimerName(ebi))
	ue.Unlock()

	s.log.Warn("s1ap: IMS Modify Bearer timed out after fallback",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi))
	s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_timeout")
}

func hasPendingCreateBearerForLinkedEBILocked(ue *uecontext.Context, linkedEBI uint8) bool {
	for _, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate || tx.LinkedEBI != linkedEBI || isCreateBearerTerminal(tx.CreateState) {
			continue
		}
		return true
	}
	return false
}

func (s *Server) registerPendingERABProcedure(ue *uecontext.Context, transactionID string, procedureKind string, bindingGeneration uint64, items []ERABSetupItem) {
	ebis := make([]uint8, 0, len(items))
	for _, item := range items {
		ebis = append(ebis, item.EBI)
	}
	s.registerPendingERABProcedureForEBIs(ue, transactionID, procedureKind, bindingGeneration, ebis)
}

func (s *Server) registerPendingERABProcedureForEBIs(ue *uecontext.Context, transactionID string, procedureKind string, bindingGeneration uint64, ebis []uint8) {
	ue.Lock()
	defer ue.Unlock()
	if ue.PendingERABProcedures == nil {
		ue.PendingERABProcedures = make(map[string]*uecontext.PendingERABProcedure)
	}
	expected := make(map[uint8]struct{}, len(ebis))
	for _, ebi := range ebis {
		expected[ebi] = struct{}{}
	}
	ue.PendingERABProcedures[transactionID] = &uecontext.PendingERABProcedure{
		TransactionID:       transactionID,
		ProcedureKind:       procedureKind,
		ExpectedEBIs:        expected,
		S1BindingGeneration: bindingGeneration,
		CreatedAt:           time.Now(),
		Deadline:            time.Now().Add(createBearerOverallTimeout),
	}
}

func (s *Server) unregisterPendingERABProcedure(ue *uecontext.Context, transactionID string) {
	ue.Lock()
	defer ue.Unlock()
	delete(ue.PendingERABProcedures, transactionID)
}

func matchPendingERABProcedureLocked(ue *uecontext.Context, received map[uint8]struct{}) (*uecontext.PendingERABProcedure, string, bool) {
	var exact []*uecontext.PendingERABProcedure
	var subset []*uecontext.PendingERABProcedure
	for _, proc := range ue.PendingERABProcedures {
		if proc.S1BindingGeneration != 0 && proc.S1BindingGeneration != ue.S1BindingGeneration {
			continue
		}
		match := true
		for ebi := range received {
			if _, ok := proc.ExpectedEBIs[ebi]; !ok {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if len(received) == len(proc.ExpectedEBIs) {
			exact = append(exact, proc)
		} else {
			subset = append(subset, proc)
		}
	}
	if len(exact) == 1 {
		return exact[0], "exact_expected_ebi_set", false
	}
	if len(exact) > 1 {
		return nil, "", true
	}
	if len(subset) == 1 {
		return subset[0], "subset_of_expected_ebis", false
	}
	if len(subset) > 1 {
		return nil, "", true
	}
	return nil, "", false
}

func pendingERABDiagnosticsLocked(ue *uecontext.Context) ([]string, []uint8, uint64) {
	pendingIDs := make([]string, 0, len(ue.PendingERABProcedures))
	expectedMap := map[uint8]struct{}{}
	for id, proc := range ue.PendingERABProcedures {
		pendingIDs = append(pendingIDs, id)
		for ebi := range proc.ExpectedEBIs {
			expectedMap[ebi] = struct{}{}
		}
	}
	sort.Strings(pendingIDs)
	return pendingIDs, sortedExpectedEBIs(expectedMap), ue.S1BindingGeneration
}

func sortedExpectedEBIs(expected map[uint8]struct{}) []uint8 {
	out := make([]uint8, 0, len(expected))
	for ebi := range expected {
		out = append(out, ebi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func containsERABResult(successes []ERABSetupSuccess, failures []ERABSetupFailure, ebi uint8) bool {
	for _, success := range successes {
		if success.EBI == ebi {
			return true
		}
	}
	for _, failure := range failures {
		if failure.EBI == ebi {
			return true
		}
	}
	return false
}
