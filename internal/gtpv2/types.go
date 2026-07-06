// Package gtpv2 implements the GTPv2-C (GTP version 2 control plane) codec
// per 3GPP TS 29.274. Only the messages needed for S11 (MME ↔ S-GW) are
// implemented: Create/Modify/Delete Session.
package gtpv2

// Message type codes (TS 29.274 Table 6.1-1).
const (
	MsgEchoRequest            uint8 = 1
	MsgEchoResponse           uint8 = 2
	MsgCreateSessionRequest   uint8 = 32
	MsgCreateSessionResponse  uint8 = 33
	MsgModifyBearerRequest    uint8 = 34
	MsgModifyBearerResponse   uint8 = 35
	MsgDeleteSessionRequest   uint8 = 36
	MsgDeleteSessionResponse  uint8 = 37
	MsgContextRequest         uint8 = 130
	MsgContextResponse        uint8 = 131
	MsgContextAcknowledge     uint8 = 132
)

// IE type codes (TS 29.274 Table 8.1-1, selected subset).
const (
	IETypeCause              uint8 = 2
	IETypeIMSI               uint8 = 1
	IETypeRecovery           uint8 = 3
	IETypeULI                uint8 = 86 // User Location Information (TAI + ECGI)
	IETypeAPN                uint8 = 71
	IETypeAMBR               uint8 = 72
	IETypeEBI                uint8 = 73
	IETypeMSISDN             uint8 = 76
	IETypeIndication         uint8 = 77
	IETypePAA                uint8 = 79
	IETypeBearerQoS          uint8 = 80
	IETypeRATType            uint8 = 82
	IETypeServingNetwork     uint8 = 83
	IETypeFTEID              uint8 = 87
	IETypeBearerContext      uint8 = 93
	IETypePDNType            uint8 = 99
	IETypeMMContext          uint8 = 107 // TS 29.274 §8.38 (EPS Security Context)
	IETypePDNConnection      uint8 = 109 // TS 29.274 §8.41 (grouped bearer context)
	IETypeCompleteRequestMsg uint8 = 116 // TS 29.274 §8.47 (raw NAS PDU)
	IETypeSelectionMode      uint8 = 128
)

// ULI flags (TS 29.274 §8.21, octet 5 bit positions 1=LSB).
const (
	ULIFlagTAI  uint8 = 0x08 // bit 4
	ULIFlagECGI uint8 = 0x10 // bit 5
)

// Cause values (TS 29.274 Table 8.4-1, selected).
const (
	CauseRequestAccepted             uint8 = 16
	CauseRequestDenied               uint8 = 17
	CauseContextNotFound             uint8 = 64
	CauseInvalidMsgFormat            uint8 = 65
	CauseServiceNotSupported         uint8 = 68
	CauseAllDynamicAddressesOccupied uint8 = 73
)

// PDN type values (TS 29.274 §8.34).
const (
	PDNTypeIPv4   uint8 = 1
	PDNTypeIPv6   uint8 = 2
	PDNTypeIPv4v6 uint8 = 3
)

// RAT type values (TS 29.274 §8.17).
const (
	RATTypeUTRAN   uint8 = 1
	RATTypeGERAN   uint8 = 2
	RATTypeWLAN    uint8 = 3
	RATTypeGAN     uint8 = 4
	RATTypeHSPAEvo uint8 = 5
	RATTypeEUTRAN  uint8 = 6
	RATTypeVirtual uint8 = 7
)

// Selection Mode values (TS 29.274 §8.58).
const (
	SelectionModeMS                uint8 = 0
	SelectionModeNetworkProvided   uint8 = 1
	SelectionModeNetworkVerified   uint8 = 2
)

// F-TEID interface type codes (TS 29.274 Table 8.22-1).
const (
	IFTypeS1UENB        uint8 = 0  // S1-U eNB GTP-U
	IFTypeS1USGW        uint8 = 1  // S1-U SGW GTP-U
	IFTypeS11S4SGW      uint8 = 4  // S11/S4 SGW GTP-C
	IFTypeS11MME        uint8 = 5  // S11 MME GTP-C
	IFTypeS5S8PGWC      uint8 = 9  // S5/S8 PGW GTP-C (PGW S5/S8 Address for CP or PMIP)
	IFTypeS10MME        uint8 = 14 // S10 MME GTP-C (inter-MME)
)

// F-TEID instance values used in this implementation.
const (
	FTEIDInstanceSender uint8 = 0 // MME S11 F-TEID in CSReq; eNB S1U in MBReq Bearer Context
	FTEIDInstanceSGWC   uint8 = 0 // S-GW C-plane F-TEID returned in CSRsp (outer, TS 29.274 Table 7.2.2-1)
)
