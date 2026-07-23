// Package gtpv2 implements the GTPv2-C (GTP version 2 control plane) codec
// per 3GPP TS 29.274. Only the messages needed for S11 (MME ↔ S-GW) are
// implemented: Create/Modify/Delete Session.
package gtpv2

import "errors"

// Message type codes (TS 29.274 Table 6.1-1).
const (
	MsgEchoRequest                  uint8 = 1
	MsgEchoResponse                 uint8 = 2
	MsgCreateSessionRequest         uint8 = 32
	MsgCreateSessionResponse        uint8 = 33
	MsgModifyBearerRequest          uint8 = 34
	MsgModifyBearerResponse         uint8 = 35
	MsgDeleteSessionRequest         uint8 = 36
	MsgDeleteSessionResponse        uint8 = 37
	MsgCreateBearerRequest          uint8 = 95
	MsgCreateBearerResponse         uint8 = 96
	MsgUpdateBearerRequest          uint8 = 97
	MsgUpdateBearerResponse         uint8 = 98
	MsgDeleteBearerRequest          uint8 = 99
	MsgDeleteBearerResponse         uint8 = 100
	MsgDownlinkDataNotification     uint8 = 176
	MsgDownlinkDataNotificationAck  uint8 = 177
	MsgDownlinkDataNotificationFail uint8 = 178
	MsgReleaseAccessBearersRequest  uint8 = 170
	MsgReleaseAccessBearersResponse uint8 = 171
	MsgContextRequest               uint8 = 130
	MsgContextResponse              uint8 = 131
	MsgContextAcknowledge           uint8 = 132
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
	IETypeMEI                uint8 = 75
	IETypeMSISDN             uint8 = 76
	IETypeIndication         uint8 = 77
	IETypePCO                uint8 = 78
	IETypePAA                uint8 = 79
	IETypeBearerQoS          uint8 = 80
	IETypeRATType            uint8 = 82
	IETypeServingNetwork     uint8 = 83
	IETypeTFT                uint8 = 84
	IETypeFTEID              uint8 = 87
	IETypeDelayValue         uint8 = 92
	IETypeBearerContext      uint8 = 93
	IETypeChargingChars      uint8 = 95
	IETypePDNType            uint8 = 99
	IETypeMMContext          uint8 = 107 // TS 29.274 §8.38 (EPS Security Context)
	IETypePDNConnection      uint8 = 109 // TS 29.274 §8.41 (grouped bearer context)
	IETypeUETimeZone         uint8 = 114
	IETypeCompleteRequestMsg uint8 = 116 // TS 29.274 §8.47 (raw NAS PDU)
	IETypeAPNRestriction     uint8 = 127
	IETypeSelectionMode      uint8 = 128
	IETypeNodeType           uint8 = 135
	IETypeThrottling         uint8 = 154
	IETypeARP                uint8 = 155
	IETypeEPCTimer           uint8 = 156
	IETypeULITimestamp       uint8 = 170 // TS 29.274 §8.141 (ULI Timestamp)
	IETypePagingSvcInfo      uint8 = 186
	IETypeIntegerNumber      uint8 = 187
)

// ULI flags (TS 29.274 §8.21, octet 5 bit positions 1=LSB).
const (
	ULIFlagTAI  uint8 = 0x08 // bit 4
	ULIFlagECGI uint8 = 0x10 // bit 5
)

// Cause values (TS 29.274 Table 8.4-1, selected).
const (
	CauseRequestAccepted             uint8 = 16
	CauseRequestAcceptedPartially    uint8 = 17
	CauseNewPDNTypeDueToNetworkPref  uint8 = 18
	CauseNewPDNTypeDueToSingleAddr   uint8 = 19
	CauseContextNotFound             uint8 = 64
	CauseInvalidMsgFormat            uint8 = 65
	CauseServiceNotSupported         uint8 = 68
	CauseMandatoryIEIncorrect        uint8 = 69
	CauseMandatoryIEMissing          uint8 = 70
	CauseSystemFailure               uint8 = 72
	CauseAllDynamicAddressesOccupied uint8 = 84
	CauseUEIsNotResponding           uint8 = 87
	CauseUnableToPageUE              uint8 = 90
	CauseUERefuses                   uint8 = 88
	CauseRequestRejected             uint8 = 94
	CauseConditionalIEMissing        uint8 = 103
	CauseUEAlreadyReattached         uint8 = 115

	// Deprecated alias kept for existing callers that still mean "rejected".
	CauseRequestDenied uint8 = CauseRequestRejected
)

var (
	ErrMandatoryIEMissing   = errors.New("gtpv2: mandatory IE missing")
	ErrMandatoryIEIncorrect = errors.New("gtpv2: mandatory IE incorrect")
	ErrConditionalIEMissing = errors.New("gtpv2: conditional IE missing")
)

func IsAcceptedCause(cause uint8) bool {
	switch cause {
	case CauseRequestAccepted,
		CauseRequestAcceptedPartially,
		CauseNewPDNTypeDueToNetworkPref,
		CauseNewPDNTypeDueToSingleAddr:
		return true
	default:
		return false
	}
}

func DecodeErrorCause(err error) uint8 {
	switch {
	case errors.Is(err, ErrMandatoryIEMissing):
		return CauseMandatoryIEMissing
	case errors.Is(err, ErrMandatoryIEIncorrect):
		return CauseMandatoryIEIncorrect
	case errors.Is(err, ErrConditionalIEMissing):
		return CauseConditionalIEMissing
	default:
		return CauseInvalidMsgFormat
	}
}

func CauseName(cause uint8) string {
	switch cause {
	case CauseRequestAccepted:
		return "Request accepted"
	case CauseRequestAcceptedPartially:
		return "Request accepted partially"
	case CauseNewPDNTypeDueToNetworkPref:
		return "New PDN type due to network preference"
	case CauseNewPDNTypeDueToSingleAddr:
		return "New PDN type due to single address bearer only"
	case CauseContextNotFound:
		return "Context not found"
	case CauseInvalidMsgFormat:
		return "Invalid message format"
	case CauseServiceNotSupported:
		return "Service not supported"
	case CauseMandatoryIEIncorrect:
		return "Mandatory IE incorrect"
	case CauseMandatoryIEMissing:
		return "Mandatory IE missing"
	case CauseSystemFailure:
		return "System failure"
	case CauseAllDynamicAddressesOccupied:
		return "All dynamic addresses are occupied"
	case CauseUEIsNotResponding:
		return "UE is not responding"
	case CauseUnableToPageUE:
		return "Unable to page UE"
	case CauseUERefuses:
		return "UE refuses"
	case CauseRequestRejected:
		return "Request rejected"
	case CauseConditionalIEMissing:
		return "Conditional IE missing"
	case CauseUEAlreadyReattached:
		return "UE already re-attached"
	default:
		return "unknown"
	}
}

// PDN type values (TS 29.274 §8.34).
const (
	PDNTypeIPv4   uint8 = 1
	PDNTypeIPv6   uint8 = 2
	PDNTypeIPv4v6 uint8 = 3
)

// APN Restriction values (TS 29.274 §8.57).
const (
	APNRestrictionNoRestriction uint8 = 0
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
	SelectionModeMS              uint8 = 0
	SelectionModeNetworkProvided uint8 = 1
	SelectionModeNetworkVerified uint8 = 2
)

// F-TEID interface type codes (TS 29.274 Table 8.22-1).
const (
	IFTypeS1UENB   uint8 = 0  // S1-U eNB GTP-U
	IFTypeS1USGW   uint8 = 1  // S1-U SGW GTP-U
	IFTypeS5S8SGWC uint8 = 6  // S5/S8 SGW GTP-C
	IFTypeS5S8PGWC uint8 = 7  // S5/S8 PGW GTP-C
	IFTypeS11MME   uint8 = 10 // S11 MME GTP-C
	IFTypeS11S4SGW uint8 = 11 // S11/S4 SGW GTP-C
	IFTypeS10MME   uint8 = 12 // S10/N26 MME GTP-C (inter-MME)
)

// F-TEID instance values used in this implementation.
const (
	FTEIDInstanceSender uint8 = 0 // MME S11 F-TEID in CSReq; eNB S1U in MBReq Bearer Context
	FTEIDInstanceSGWC   uint8 = 0 // S-GW C-plane F-TEID returned in CSRsp (outer, TS 29.274 Table 7.2.2-1)
	FTEIDInstanceSGWU   uint8 = 1 // S-GW user-plane F-TEID in bearer context responses
)

const (
	NodeTypeMME  uint8 = 0
	NodeTypeSGSN uint8 = 1
)
