package gtpv2

import (
	"encoding/binary"
	"fmt"
	"net"
)

// CreateSessionRequest holds the parameters for a GTPv2-C Create Session Request
// (TS 29.274 §7.2.1). The MME sends this to the S-GW on S11.
type CreateSessionRequest struct {
	SGWAddress              string
	IMSI                    string
	MSISDN                  string
	APN                     string
	RATType                 uint8
	ServingNetwork          [3]byte // PLMN BCD (MCC+MNC encoded per TS 24.008 §10.5.1.13)
	LocalS11TEID            uint32
	LocalS11IP              net.IP
	PGWIP                   net.IP  // PGW S5/S8 GTP-C address (mandatory for S-GW to forward to PGW)
	ULIPLMN                 [3]byte // PLMN for ULI TAI + ECGI
	ULITAC                  uint16  // Tracking Area Code
	ULIECI                  uint32  // 28-bit E-UTRAN Cell Identity
	PCO                     []byte  // Protocol Configuration Options from UE PDN Connectivity Request
	PDNType                 uint8
	DefaultEBI              uint8
	BearerQCI               uint8
	BearerPriorityLevel     uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	UplinkAMBRKbps          uint32
	DownlinkAMBRKbps        uint32
}

// Encode returns the wire bytes for this CSR with the given sequence number.
func (r *CreateSessionRequest) Encode(seqNum uint32) []byte {
	bearerPriorityLevel := r.BearerPriorityLevel
	if bearerPriorityLevel == 0 {
		bearerPriorityLevel = 8
	}
	bearerCtx := EncodeGrouped(IETypeBearerContext, 0, []IE{
		EncodeEBI(r.DefaultEBI, 0),
		EncodeBearerQoS(r.BearerQCI, bearerPriorityLevel, r.PreemptionCapability, r.PreemptionVulnerability),
	})

	ies := []IE{
		EncodeIMSI(r.IMSI),
		EncodeMSISDN(r.MSISDN),
		EncodeRATType(r.RATType),
		EncodeServingNetwork(r.ServingNetwork),
		EncodeFTEID(IFTypeS11MME, r.LocalS11TEID, r.LocalS11IP, FTEIDInstanceSender),
		EncodeFTEID(IFTypeS5S8PGWC, 0, r.PGWIP, 1), // PGW S5/S8 Address for Control Plane or PMIP
		EncodeULI(r.ULIPLMN, r.ULITAC, r.ULIECI),   // User Location Information (TAI + ECGI)
		EncodeAPN(r.APN),
		EncodePDNType(r.PDNType),
		EncodePAA(net.IP{0, 0, 0, 0}), // request any IPv4 address
		EncodeAPNRestriction(APNRestrictionNoRestriction),
		EncodeAMBR(r.UplinkAMBRKbps, r.DownlinkAMBRKbps),
		EncodeSelectionMode(SelectionModeMS),
		bearerCtx,
	}
	if len(r.PCO) > 0 {
		ies = append(ies, EncodePCO(r.PCO))
	}

	msg := &Message{
		Type:   MsgCreateSessionRequest,
		TEID:   0, // initial request: peer TEID unknown
		SeqNum: seqNum,
		IEs:    ies,
	}
	return Encode(msg)
}

// CreateSessionResponse holds the decoded fields from a GTPv2-C Create Session Response.
type CreateSessionResponse struct {
	Cause          uint8
	SGWC_TEID      uint32
	SGWC_IP        net.IP
	PGWC_TEID      uint32
	PGWC_IP        net.IP
	SGWU_TEID      uint32
	SGWU_IP        net.IP
	PGWU_TEID      uint32
	PGWU_IP        net.IP
	UEIPv4         net.IP
	PDNType        uint8 // network-selected type from PAA
	EBI            uint8
	PCO            []byte
	APNRestriction uint8
	AMBRUplink     uint32
	AMBRDownlink   uint32
}

// DecodeCreateSessionResponse decodes a CSRsp message. Returns an error if the
// message type is wrong or required IEs are missing/malformed.
func DecodeCreateSessionResponse(m *Message) (*CreateSessionResponse, error) {
	if m.Type != MsgCreateSessionResponse {
		return nil, fmt.Errorf("gtpv2: expected CSRsp (33), got %d", m.Type)
	}

	causeIE := FindIE(m.IEs, IETypeCause, 0)
	cause, err := DecodeCause(causeIE)
	if err != nil {
		return nil, fmt.Errorf("gtpv2: CSRsp missing Cause IE: %w", err)
	}

	resp := &CreateSessionResponse{Cause: cause}
	if !IsAcceptedCause(cause) {
		return resp, nil
	}

	// Outer F-TEID (instance 0) = S-GW C-plane S11 TEID (TS 29.274 Table 7.2.2-1)
	sgwcFTEID := FindIE(m.IEs, IETypeFTEID, FTEIDInstanceSGWC)
	if sgwcFTEID == nil {
		return nil, fmt.Errorf("gtpv2: CSRsp missing SGW-C F-TEID (instance 0)")
	}
	sgwc, err := DecodeFTEID(sgwcFTEID)
	if err != nil {
		return nil, fmt.Errorf("gtpv2: CSRsp SGW-C F-TEID decode: %w", err)
	}
	resp.SGWC_TEID = sgwc.TEID
	resp.SGWC_IP = sgwc.IP

	if pgwcFTEID := FindIE(m.IEs, IETypeFTEID, 1); pgwcFTEID != nil {
		if pgwc, err := DecodeFTEID(pgwcFTEID); err == nil {
			resp.PGWC_TEID = pgwc.TEID
			resp.PGWC_IP = pgwc.IP
		}
	}

	// PAA → UE IPv4
	paaIE := FindIE(m.IEs, IETypePAA, 0)
	if paaIE != nil {
		if len(paaIE.Value) > 0 {
			resp.PDNType = paaIE.Value[0] & 0x07
		}
		resp.UEIPv4, _ = DecodePAA(paaIE)
	}

	if apnRestrictionIE := FindIE(m.IEs, IETypeAPNRestriction, 0); apnRestrictionIE != nil && len(apnRestrictionIE.Value) >= 1 {
		resp.APNRestriction = apnRestrictionIE.Value[0]
	}

	if ambrIE := FindIE(m.IEs, IETypeAMBR, 0); ambrIE != nil && len(ambrIE.Value) == 8 {
		resp.AMBRUplink = binary.BigEndian.Uint32(ambrIE.Value[:4])
		resp.AMBRDownlink = binary.BigEndian.Uint32(ambrIE.Value[4:])
	}

	// Protocol Configuration Options returned by the P-GW are copied into the
	// NAS Activate Default EPS Bearer Context Request PCO IE.
	if pcoIE := FindIE(m.IEs, IETypePCO, 0); pcoIE != nil {
		resp.PCO = append([]byte(nil), pcoIE.Value...)
	}

	// Bearer Context (instance 0) contains SGW S1-U F-TEID and EBI
	bcIE := FindIE(m.IEs, IETypeBearerContext, 0)
	if bcIE == nil {
		return nil, fmt.Errorf("gtpv2: CSRsp missing Bearer Context IE")
	}
	bcIEs, err := FindGroupedIEs(bcIE)
	if err != nil {
		return nil, fmt.Errorf("gtpv2: CSRsp Bearer Context decode: %w", err)
	}

	ebiIE := FindIE(bcIEs, IETypeEBI, 0)
	ebi, e := DecodeEBI(ebiIE)
	if e != nil {
		return nil, fmt.Errorf("gtpv2: CSRsp missing Bearer Context EBI: %w", e)
	}
	if ebi == 0 {
		return nil, fmt.Errorf("gtpv2: CSRsp invalid Bearer Context EBI 0")
	}
	resp.EBI = ebi

	// S-GW S1-U GTP-U F-TEID is instance 0 inside Bearer Context
	sgwuFTEID := FindIE(bcIEs, IETypeFTEID, 0)
	if sgwuFTEID != nil {
		sgwu, err := DecodeFTEID(sgwuFTEID)
		if err == nil {
			resp.SGWU_TEID = sgwu.TEID
			resp.SGWU_IP = sgwu.IP
		}
	}
	if pgwuFTEID := FindIE(bcIEs, IETypeFTEID, 2); pgwuFTEID != nil {
		if pgwu, err := DecodeFTEID(pgwuFTEID); err == nil {
			resp.PGWU_TEID = pgwu.TEID
			resp.PGWU_IP = pgwu.IP
		}
	}

	return resp, nil
}
