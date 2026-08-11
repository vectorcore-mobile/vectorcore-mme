package s6a

import (
	"encoding/hex"
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/roaming"
)

// SendULR sends an Update-Location-Request to the HSS.
// The result arrives asynchronously via handleULA → nas.HandleULAResult.
func (h *Handlers) SendULR(imsi string, plmn [3]byte, mmeUEID uint32) error {
	destinationRealm := h.diameterCfg.OriginRealm
	selected, err := h.selectPeer(destinationRealm)
	if err != nil {
		return err
	}

	sid := h.newSessionID(imsi)
	h.pendingULR.Store(sid, mmeUEID)
	if h.sgdCfg.Enabled && h.sgdCfg.SubscribeEPSOnlyAttach {
		if receiver, ok := h.nas.(interface{ HandleSMSRegistrationPending(uint32) }); ok {
			receiver.HandleSMSRegistrationPending(mmeUEID)
		}
	}

	m := h.buildULR(sid, imsi, plmn, selected.DestinationHost, destinationRealm)

	if _, err := m.WriteTo(selected.Connection); err != nil {
		h.pendingULR.Delete(sid)
		h.reportTransactionFailure(selected)
		return fmt.Errorf("s6a: ULR write: %w", err)
	}

	metrics.S6aRequestsTotal.WithLabelValues("ULR", "sent").Inc()
	h.log.Info("s6a: ULR sent",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("visited_plmn_id_hex", hex.EncodeToString(plmn[:])))
	return nil
}

// SendULRToHSS sends ULR with the verified HSS destination selected during
// identity classification, rather than deriving either identity from MME config.
func (h *Handlers) SendULRToHSS(req roaming.S6aRequest, mmeUEID uint32) error {
	encoded, err := security.EncodePLMN(req.VisitedPLMN.MCC, req.VisitedPLMN.MNC)
	if err != nil {
		return fmt.Errorf("s6a: encode visited PLMN: %w", err)
	}
	var visited [3]byte
	copy(visited[:], encoded)
	selected, err := h.selectPeer(req.DestinationRealm)
	if err != nil {
		return fmt.Errorf("s6a: route ULR for %s: %w", req.DestinationRealm, err)
	}
	sid := h.newSessionID(req.SubscriberIMSI)
	h.pendingULR.Store(sid, mmeUEID)
	if h.sgdCfg.Enabled && h.sgdCfg.SubscribeEPSOnlyAttach {
		if receiver, ok := h.nas.(interface{ HandleSMSRegistrationPending(uint32) }); ok {
			receiver.HandleSMSRegistrationPending(mmeUEID)
		}
	}
	destHost := req.DestinationHost
	if destHost == "" && req.DestinationRealm == h.diameterCfg.OriginRealm {
		destHost = selected.DestinationHost
	}
	m := h.buildULR(sid, req.SubscriberIMSI, visited, destHost, req.DestinationRealm)
	if _, err := m.WriteTo(selected.Connection); err != nil {
		h.pendingULR.Delete(sid)
		h.reportTransactionFailure(selected)
		return fmt.Errorf("s6a: ULR write: %w", err)
	}
	metrics.S6aRequestsTotal.WithLabelValues("ULR", "sent").Inc()
	h.log.Info("s6a: ULR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.String("destination_realm", req.DestinationRealm), zap.String("visited_plmn_id_hex", hex.EncodeToString(visited[:])))
	return nil
}

func (h *Handlers) buildULR(sessionID, imsi string, plmn [3]byte, destHost, destRealm string) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginRealm))
	h.addDestinationRouting(m, destHost, destRealm)
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)) // NO_STATE_MAINTAINED
	m.NewAVP(avp.RATType, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Enumerated(ratTypeEUTRAN))
	m.NewAVP(avp.ULRFlags, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(h.cfg.ULR.Flags))
	m.NewAVP(avp.VisitedPLMNID, avp.Vbit|avp.Mbit, vendor3GPP, datatype.OctetString(plmn[:]))
	if h.sgdCfg.Enabled && h.sgdCfg.SubscribeEPSOnlyAttach {
		// TS 29.272: request SMS registration in the normal ULR, advertise the
		// SMS-in-MME feature, and carry the MME's E.164 number in TBCD.
		flags := h.cfg.ULR.Flags | (1 << 7) // SMS-Only-Indication
		for _, a := range m.AVP {
			if a.Code == avp.ULRFlags && a.VendorID == vendor3GPP {
				a.Data = datatype.Unsigned32(flags)
			}
		}
		mmeNumber, err := config.EncodeTBCD(h.sgdCfg.MMENumberForMTSMS)
		if err == nil {
			m.NewAVP(1645, avp.Vbit, vendor3GPP, datatype.OctetString(mmeNumber)) // MME-Number-for-MT-SMS
			m.NewAVP(1648, avp.Vbit, vendor3GPP, datatype.Enumerated(0))          // SMS_REGISTRATION_REQUIRED
		}
		m.AddAVP(diam.NewAVP(avp.SupportedFeatures, avp.Vbit, vendor3GPP, &diam.GroupedAVP{AVP: []*diam.AVP{
			diam.NewAVP(avp.VendorID, avp.Vbit, vendor3GPP, datatype.Unsigned32(vendor3GPP)),
			diam.NewAVP(avp.FeatureListID, avp.Vbit, vendor3GPP, datatype.Unsigned32(2)),
			diam.NewAVP(avp.FeatureList, avp.Vbit, vendor3GPP, datatype.Unsigned32(1)),
		}}))
	}
	return m
}

// handleULA processes an Update-Location-Answer from the HSS.
func (h *Handlers) handleULA(c diam.Conn, m *diam.Message) {
	type MIPHomeAgentHost struct {
		DestinationRealm datatype.DiameterIdentity `avp:"Destination-Realm"`
		DestinationHost  datatype.DiameterIdentity `avp:"Destination-Host"`
	}
	type MIP6AgentInfo struct {
		MIPHomeAgentAddress []datatype.Address `avp:"MIP-Home-Agent-Address"`
		MIPHomeAgentHost    MIPHomeAgentHost   `avp:"MIP-Home-Agent-Host"`
	}
	type AMBR struct {
		MaxRequestedBandwidthDL uint32 `avp:"Max-Requested-Bandwidth-DL"`
		MaxRequestedBandwidthUL uint32 `avp:"Max-Requested-Bandwidth-UL"`
	}
	type AllocationRetentionPriority struct {
		PriorityLevel           uint32 `avp:"Priority-Level"`
		PreemptionCapability    int32  `avp:"Pre-emption-Capability"`
		PreemptionVulnerability int32  `avp:"Pre-emption-Vulnerability"`
	}
	type EPSSubscribedQoSProfile struct {
		QoSClassIdentifier          int32                       `avp:"QoS-Class-Identifier"`
		AllocationRetentionPriority AllocationRetentionPriority `avp:"Allocation-Retention-Priority"`
	}
	type APNConfig struct {
		ContextIdentifier       uint32                  `avp:"Context-Identifier"`
		ServiceSelection        string                  `avp:"Service-Selection"`
		MIP6AgentInfo           MIP6AgentInfo           `avp:"MIP6-Agent-Info"`
		PDNGWAllocationType     int32                   `avp:"PDN-GW-Allocation-Type"`
		PDNType                 int32                   `avp:"PDN-Type"`
		EPSSubscribedQoSProfile EPSSubscribedQoSProfile `avp:"EPS-Subscribed-QoS-Profile"`
		AMBR                    AMBR                    `avp:"AMBR"`
		APNOIReplacement        string                  `avp:"APN-OI-Replacement"`
	}
	type APNProfile struct {
		ContextIdentifier            uint32      `avp:"Context-Identifier"`
		AllAPNConfigurationsIncluded int32       `avp:"All-APN-Configurations-Included-Indicator"`
		APNConfiguration             []APNConfig `avp:"APN-Configuration"`
	}
	type SubscriptionData struct {
		MSISDN                  datatype.OctetString `avp:"MSISDN"`
		AMBR                    AMBR                 `avp:"AMBR"`
		APNConfigurationProfile APNProfile           `avp:"APN-Configuration-Profile"`
		AccessRestrictionData   uint32               `avp:"Access-Restriction-Data"`
	}
	type experimentalResult struct {
		ExperimentalResultCode uint32 `avp:"Experimental-Result-Code"`
	}
	type ULA struct {
		SessionID          string             `avp:"Session-Id"`
		ResultCode         uint32             `avp:"Result-Code"`
		ExperimentalResult experimentalResult `avp:"Experimental-Result"`
		ULAFlags           uint32             `avp:"ULA-Flags"`
		SubscriptionData   SubscriptionData   `avp:"Subscription-Data"`
	}

	var ula ULA
	if err := m.Unmarshal(&ula); err != nil {
		h.log.Warn("s6a: ULA unmarshal error", zap.Error(err))
		metrics.S6aRequestsTotal.WithLabelValues("ULA", "error").Inc()
		return
	}

	v, ok := h.pendingULR.LoadAndDelete(ula.SessionID)
	if !ok {
		h.log.Warn("s6a: ULA: no pending ULR for session", zap.String("session", ula.SessionID))
		return
	}
	mmeUEID := v.(uint32)

	metrics.S6aRequestsTotal.WithLabelValues("ULA", "ok").Inc()

	if ula.ResultCode != diam.Success || ula.ExperimentalResult.ExperimentalResultCode != 0 {
		errCode := ula.ResultCode
		if errCode == 0 {
			errCode = ula.ExperimentalResult.ExperimentalResultCode
		}
		h.log.Warn("s6a: ULA failure",
			zap.Uint32("result_code", errCode),
			zap.Uint32("mme_ue_id", mmeUEID))
		h.nas.HandleULAResultWithSubscriberProfile(mmeUEID, "", nil,
			fmt.Errorf("s6a: ULA result code %d", errCode))
		return
	}
	if h.sgdCfg.Enabled && h.sgdCfg.SubscribeEPSOnlyAttach {
		registered := ula.ULAFlags&(1<<1) != 0 // MME-Registered-for-SMS
		if receiver, ok := h.nas.(interface{ HandleSMSRegistrationResult(uint32, bool, string) }); ok {
			cause := ""
			if !registered {
				cause = "hss-not-registered"
			}
			receiver.HandleSMSRegistrationResult(mmeUEID, registered, cause)
		}
	}

	// Decode MSISDN (BCD-encoded OctetString)
	msisdn := decodeMSISDN([]byte(ula.SubscriptionData.MSISDN))

	profile := &gateway.SubscriberProfile{
		DefaultContextID:      ula.SubscriptionData.APNConfigurationProfile.ContextIdentifier,
		APNs:                  make(map[string]gateway.APNConfiguration),
		UEAMBRDown:            ula.SubscriptionData.AMBR.MaxRequestedBandwidthDL,
		UEAMBRUp:              ula.SubscriptionData.AMBR.MaxRequestedBandwidthUL,
		AccessRestrictionData: gateway.AccessRestrictionData(ula.SubscriptionData.AccessRestrictionData),
	}
	for _, selected := range ula.SubscriptionData.APNConfigurationProfile.APNConfiguration {
		cfg := gateway.APNConfiguration{
			ContextIdentifier:       selected.ContextIdentifier,
			ServiceSelection:        selected.ServiceSelection,
			MIPHomeAgentHost:        string(selected.MIP6AgentInfo.MIPHomeAgentHost.DestinationHost),
			APNOIReplacement:        selected.APNOIReplacement,
			PDNGWAllocationType:     &selected.PDNGWAllocationType,
			PDNType:                 pdnPolicyDefaultType(uint8(selected.PDNType)),
			PDNTypePolicy:           uint8(selected.PDNType),
			QCI:                     uint8(selected.EPSSubscribedQoSProfile.QoSClassIdentifier),
			ARPPriority:             uint8(selected.EPSSubscribedQoSProfile.AllocationRetentionPriority.PriorityLevel),
			PreemptionCapability:    selected.EPSSubscribedQoSProfile.AllocationRetentionPriority.PreemptionCapability == 0,
			PreemptionVulnerability: selected.EPSSubscribedQoSProfile.AllocationRetentionPriority.PreemptionVulnerability == 0,
			APNAMBRDown:             selected.AMBR.MaxRequestedBandwidthDL,
			APNAMBRUp:               selected.AMBR.MaxRequestedBandwidthUL,
		}
		if len(selected.MIP6AgentInfo.MIPHomeAgentAddress) > 0 {
			cfg.MIPHomeAgentAddress = []byte(selected.MIP6AgentInfo.MIPHomeAgentAddress[0])
		}
		if cfg.ServiceSelection != "" {
			profile.APNs[cfg.ServiceSelection] = cfg
		}
	}
	apnCfg := profile.DefaultAPNConfiguration()
	apn := ""
	if apnCfg != nil {
		apn = apnCfg.ServiceSelection
	}
	apns := make([]string, 0, len(profile.APNs))
	for apnName := range profile.APNs {
		apns = append(apns, apnName)
	}

	h.log.Info("s6a: ULA received",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("msisdn", msisdn),
		zap.Uint32("default_context_id", profile.DefaultContextID),
		zap.Uint32("ue_ambr_dl", profile.UEAMBRDown),
		zap.Uint32("ue_ambr_ul", profile.UEAMBRUp),
		zap.String("apn", apn),
		zap.Strings("subscribed_apns", apns),
		zap.Uint32("access_restriction_data", uint32(profile.AccessRestrictionData)))
	for _, apnName := range apns {
		cfg, ok := profile.APNs[apnName]
		if !ok {
			continue
		}
		fields := []zap.Field{
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("apn", cfg.ServiceSelection),
			zap.Uint32("context_id", cfg.ContextIdentifier),
			zap.Uint8("pdn_type", cfg.PDNType),
			zap.Uint8("qci", cfg.QCI),
			zap.Uint8("arp_priority", cfg.ARPPriority),
			zap.Bool("preemption_capability", cfg.PreemptionCapability),
			zap.Bool("preemption_vulnerability", cfg.PreemptionVulnerability),
			zap.Uint32("apn_ambr_dl", cfg.APNAMBRDown),
			zap.Uint32("apn_ambr_ul", cfg.APNAMBRUp),
			zap.String("mip_home_agent_host", cfg.MIPHomeAgentHost),
		}
		if cfg.PDNGWAllocationType != nil {
			fields = append(fields, zap.Int32("pdn_gw_allocation_type", *cfg.PDNGWAllocationType))
		}
		if len(cfg.MIPHomeAgentAddress) > 0 {
			fields = append(fields, zap.String("mip_home_agent_addr", cfg.MIPHomeAgentAddress.String()))
		}
		h.log.Info("s6a: ULA APN profile", fields...)
	}
	h.nas.HandleULAResultWithSubscriberProfile(mmeUEID, msisdn, profile, nil)
}

// decodeMSISDN decodes an S6a MSISDN AVP value. TS 29.272 defines MSISDN as
// ISDN-AddressString digits encoded in TBCD; it does not include a TON/NPI
// address header byte in this AVP.
func decodeMSISDN(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	digits := make([]byte, 0, len(data)*2)
	for _, b := range data {
		lo := b & 0x0F
		hi := (b >> 4) & 0x0F
		if lo <= 9 {
			digits = append(digits, '0'+lo)
		} else if lo != 0x0F {
			return hex.EncodeToString(data)
		}
		if hi <= 9 {
			digits = append(digits, '0'+hi)
		} else if hi != 0x0F {
			return hex.EncodeToString(data)
		}
	}
	return string(digits)
}

func pdnPolicyDefaultType(policy uint8) uint8 {
	switch policy {
	case 0:
		return 1 // NAS/GTP IPv4
	case 1:
		return 2 // NAS/GTP IPv6
	case 2:
		return 3 // NAS/GTP IPv4v6
	case 3:
		return 1 // IPv4-or-IPv6: default selection is IPv4; request may override
	default:
		return 1
	}
}
