package esm

import (
	"fmt"
	"net"
	"strings"
)

// PDNType values.
const (
	PDNTypeIPv4   uint8 = 0x01
	PDNTypeIPv6   uint8 = 0x02
	PDNTypeIPv4v6 uint8 = 0x03
	PDNTypeNonIP  uint8 = 0x05
)

// PDNConnectivityRequest holds the decoded ESM PDN Connectivity Request.
type PDNConnectivityRequest struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	PDNType                uint8
	RequestType            uint8
	APN                    string // optional
	PCO                    []byte // optional Protocol Configuration Options value part
	ESMInformationRequired bool
}

// ActivateDefaultEPSBearerContextAccept holds the UE response embedded in Attach Complete.
type ActivateDefaultEPSBearerContextAccept struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	PCO                    []byte // optional Protocol Configuration Options value part
}

type ESMInformationResponse struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	APN                    string
	PCO                    []byte
}

type PDNDisconnectRequest struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	LinkedEPSBearerID      uint8
	PCO                    []byte
}

// DecodePDNConnectivityRequest decodes a PDN Connectivity Request from the ESM container.
func DecodePDNConnectivityRequest(data []byte) *PDNConnectivityRequest {
	if len(data) < 3 {
		return nil
	}
	r := &PDNConnectivityRequest{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
		// data[2] = MsgPDNConnectivityRequest
	}
	if len(data) < 4 {
		return r
	}
	r.PDNType = data[3] & 0x07
	r.RequestType = (data[3] >> 4) & 0x07

	for i := 4; i < len(data); {
		iei := data[i]
		i++
		if iei == 0x27 {
			if i >= len(data) {
				break
			}
			pcoLen := int(data[i])
			i++
			if i+pcoLen <= len(data) {
				r.PCO = append([]byte(nil), data[i:i+pcoLen]...)
				i += pcoLen
			}
			continue
		}
		if iei == 0x28 {
			if i >= len(data) {
				break
			}
			apnLen := int(data[i])
			i++
			if i+apnLen <= len(data) {
				r.APN = decodeDNSLabels(data[i : i+apnLen])
				i += apnLen
			}
			continue
		}
		// ESM information transfer flag is a type-1 IE: IEI in the high nibble,
		// value in the low nibble, no length octet.
		if iei&0xF0 == 0xD0 {
			r.ESMInformationRequired = (iei & 0x01) == 0x01
			continue
		}
		if i >= len(data) {
			break
		}
		ieLen := int(data[i])
		i++
		if i+ieLen > len(data) {
			break
		}
		i += ieLen
	}
	return r
}

func EncodeESMInformationRequest(pti uint8) []byte {
	return []byte{
		PDEPSSessionMgmt,
		pti,
		MsgESMInformationRequest,
	}
}

func DecodeESMInformationResponse(data []byte) (*ESMInformationResponse, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("esm: ESM Information Response too short: %d", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	if data[2] != MsgESMInformationResponse {
		return nil, fmt.Errorf("esm: unexpected message type %#x", data[2])
	}
	resp := &ESMInformationResponse{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
	}
	for i := 3; i < len(data); {
		iei := data[i]
		i++
		switch iei {
		case 0x27:
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated PCO length")
			}
			pcoLen := int(data[i])
			i++
			if i+pcoLen > len(data) {
				return nil, fmt.Errorf("esm: truncated PCO value")
			}
			resp.PCO = append([]byte(nil), data[i:i+pcoLen]...)
			i += pcoLen
		case 0x28:
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated APN length")
			}
			apnLen := int(data[i])
			i++
			if i+apnLen > len(data) {
				return nil, fmt.Errorf("esm: truncated APN value")
			}
			resp.APN = decodeDNSLabels(data[i : i+apnLen])
			i += apnLen
		default:
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated optional IE %#x", iei)
			}
			ieLen := int(data[i])
			i++
			if i+ieLen > len(data) {
				return nil, fmt.Errorf("esm: optional IE %#x truncated", iei)
			}
			i += ieLen
		}
	}
	return resp, nil
}

func DecodePDNDisconnectRequest(data []byte) (*PDNDisconnectRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("esm: PDN Disconnect Request too short: %d", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	if data[2] != MsgPDNDisconnectRequest {
		return nil, fmt.Errorf("esm: unexpected message type %#x", data[2])
	}
	req := &PDNDisconnectRequest{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
		LinkedEPSBearerID:      data[3] & 0x0f,
	}
	for i := 4; i < len(data); {
		iei := data[i]
		i++
		switch iei {
		case 0x27:
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated PCO length")
			}
			pcoLen := int(data[i])
			i++
			if i+pcoLen > len(data) {
				return nil, fmt.Errorf("esm: truncated PCO value")
			}
			req.PCO = append([]byte(nil), data[i:i+pcoLen]...)
			i += pcoLen
		default:
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated optional IE %#x", iei)
			}
			ieLen := int(data[i])
			i++
			if i+ieLen > len(data) {
				return nil, fmt.Errorf("esm: optional IE %#x truncated", iei)
			}
			i += ieLen
		}
	}
	return req, nil
}

// DecodeActivateDefaultEPSBearerContextAccept decodes an ESM Activate Default EPS Bearer
// Context Accept from an Attach Complete ESM message container.
func DecodeActivateDefaultEPSBearerContextAccept(data []byte) (*ActivateDefaultEPSBearerContextAccept, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("esm: Activate Default EPS Bearer Context Accept too short: %d", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	if data[2] != MsgActivateDefaultEPSBearerContextAccept {
		return nil, fmt.Errorf("esm: unexpected message type %#x", data[2])
	}
	accept := &ActivateDefaultEPSBearerContextAccept{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
	}
	for i := 3; i < len(data); {
		iei := data[i]
		i++
		switch iei {
		case 0x27:
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated PCO length")
			}
			pcoLen := int(data[i])
			i++
			if i+pcoLen > len(data) {
				return nil, fmt.Errorf("esm: truncated PCO value")
			}
			accept.PCO = append([]byte(nil), data[i:i+pcoLen]...)
			i += pcoLen
		default:
			// Preserve forward compatibility with optional TLV IEs we do not use yet.
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated optional IE %#x", iei)
			}
			ieLen := int(data[i])
			i++
			if i+ieLen > len(data) {
				return nil, fmt.Errorf("esm: optional IE %#x truncated", iei)
			}
			i += ieLen
		}
	}
	return accept, nil
}

// EncodePDNConnectivityReject encodes an ESM PDN Connectivity Reject.
// Phase 1: the MME stubs PDN setup. PTI is the Procedure Transaction ID from the request.
func EncodePDNConnectivityReject(pti uint8, cause uint8) []byte {
	return EncodePDNConnectivityRejectWithBackoff(pti, cause, nil)
}

func EncodePDNConnectivityRejectWithBackoff(pti uint8, cause uint8, backoff *uint8) []byte {
	buf := []byte{
		PDEPSSessionMgmt, // PD = ESM, bearer ID = 0
		pti,              // Procedure Transaction ID
		MsgPDNConnectivityReject,
		cause,
	}
	if backoff != nil {
		buf = append(buf, 0x37, *backoff)
	}
	return buf
}

func EncodePDNDisconnectReject(pti uint8, cause uint8) []byte {
	return []byte{
		PDEPSSessionMgmt, // PD = ESM, bearer ID = 0
		pti,
		MsgPDNDisconnectReject,
		cause,
	}
}

// EncodePDNConnectivityAccept encodes an ESM Activate Default EPS Bearer Context Request
// (msg type 0xC1 per TS 24.301 §8.3.4). This is sent in the Attach Accept ESM container
// when S11 returns a successful Create Session Response with a UE IPv4 address.
//
// Mandatory IEs: EPS QoS, Access Point Name, PDN Address.
// ebi is placed in the upper nibble of byte 0 (bearer ID field).
func EncodePDNConnectivityAccept(pti uint8, apn string, ebi uint8, ueIPv4 net.IP) []byte {
	return EncodePDNConnectivityAcceptWithQoS(pti, apn, ebi, ueIPv4, 9, 0, 0, nil)
}

// EncodePDNConnectivityAcceptWithPCO encodes an ESM Activate Default EPS Bearer
// Context Request and includes the optional Protocol Configuration Options IE
// when the P-GW returned PCO in the Create Session Response.
func EncodePDNConnectivityAcceptWithPCO(pti uint8, apn string, ebi uint8, ueIPv4 net.IP, pco []byte) []byte {
	return EncodePDNConnectivityAcceptWithQoS(pti, apn, ebi, ueIPv4, 9, 0, 0, pco)
}

// EncodePDNConnectivityAcceptWithQoS encodes an Activate Default EPS Bearer
// Context Request from the selected bearer/APN policy.  qci must be the same
// QCI used on S11 and S1AP; callers must not substitute a generic internet
// default for an IMS bearer.
func EncodePDNConnectivityAcceptWithQoS(pti uint8, apn string, ebi uint8, ueIPv4 net.IP, qci uint8, apnAMBRUpBps uint32, apnAMBRDownBps uint32, pco []byte) []byte {
	return encodePDNConnectivityAccept(pti, apn, ebi, ueIPv4, qci, apnAMBRUpBps, apnAMBRDownBps, 0, pco)
}

func EncodePDNConnectivityAcceptWithQoSAndCause(pti uint8, apn string, ebi uint8, ueIPv4 net.IP, qci uint8, apnAMBRUpBps uint32, apnAMBRDownBps uint32, esmCause uint8, pco []byte) []byte {
	return encodePDNConnectivityAccept(pti, apn, ebi, ueIPv4, qci, apnAMBRUpBps, apnAMBRDownBps, esmCause, pco)
}

func encodePDNConnectivityAccept(pti uint8, apn string, ebi uint8, ueIPv4 net.IP, qci uint8, apnAMBRUpBps uint32, apnAMBRDownBps uint32, esmCause uint8, pco []byte) []byte {
	if qci == 0 {
		qci = 9
	}
	buf := []byte{
		(ebi << 4) | PDEPSSessionMgmt, // bearer ID | PD
		pti,
		MsgActivateDefaultEPSBearerContextRequest,
	}

	// EPS QoS (IEI not needed — mandatory first IE after header)
	// Length=1, QCI from the selected default bearer QoS.
	buf = append(buf, 0x01, qci)

	// Access Point Name (IEI 0x28 in 24.301 table — but for mandatory IE it's type 4, no IEI)
	// For Activate Default EPS Bearer Context Request, APN is a mandatory type-4 IE (no IEI):
	// Length(1B) + DNS-label-encoded APN
	apnEncoded := encodeDNSLabels(apn)
	buf = append(buf, byte(len(apnEncoded)))
	buf = append(buf, apnEncoded...)

	// PDN Address (mandatory type-4 IE): Length(1B) + PDNType(1B) + IP(4B for IPv4)
	v4 := ueIPv4.To4()
	if v4 == nil {
		v4 = net.IP{0, 0, 0, 0}
	}
	buf = append(buf, 5)           // length = 1 (PDN type) + 4 (IPv4)
	buf = append(buf, PDNTypeIPv4) // PDN type = IPv4
	buf = append(buf, v4[0], v4[1], v4[2], v4[3])

	// APN-AMBR is an optional TLV (TS 24.301 §9.9.4.4). Subscriber values are
	// in bps; the NAS rate octets use the TS 24.008 quantized mapping.
	if ambr, ok := encodeAPNAMBR(apnAMBRDownBps, apnAMBRUpBps); ok {
		buf = append(buf, 0x5e, byte(len(ambr)))
		buf = append(buf, ambr...)
	}
	if esmCause != 0 {
		buf = append(buf, 0x58, esmCause)
	}

	if len(pco) > 0 {
		if len(pco) > 255 {
			pco = pco[:255]
		}
		buf = append(buf, 0x27, byte(len(pco)))
		buf = append(buf, pco...)
	}

	return buf
}

func encodeAPNAMBR(downlinkBps, uplinkBps uint32) ([]byte, bool) {
	dl, dlExt, dlOK := encodeNASBitrate(downlinkBps)
	ul, ulExt, ulOK := encodeNASBitrate(uplinkBps)
	if !dlOK || !ulOK {
		return nil, false
	}
	out := []byte{dl, ul}
	if dlExt != 0 || ulExt != 0 {
		out = append(out, dlExt, ulExt)
	}
	return out, true
}

// encodeNASBitrate implements TS 24.008 §10.5.6.4. Rates are rounded up so
// the advertised APN-AMBR never undershoots the subscribed rate.
func encodeNASBitrate(bps uint32) (basic, extended byte, ok bool) {
	if bps == 0 {
		return 0, 0, false
	}
	kbps := (uint64(bps) + 999) / 1000
	switch {
	case kbps <= 63:
		return byte(kbps), 0, true
	case kbps <= 568:
		return byte(0x40 + (kbps-64+7)/8), 0, true
	case kbps <= 8640:
		return byte(0x80 + (kbps-576+63)/64), 0, true
	case kbps <= 16000:
		return 0xfe, byte((kbps - 8600 + 99) / 100), true
	case kbps <= 128000:
		return 0xfe, byte(0x4a + (kbps-16000+999)/1000), true
	case kbps <= 256000:
		return 0xfe, byte(0xba + (kbps-128000+1999)/2000), true
	default:
		return 0, 0, false
	}
}

// encodeDNSLabels converts APN string "internet.mnc095.mcc204.gprs" to DNS label encoding.
func encodeDNSLabels(apn string) []byte {
	if len(apn) == 0 {
		return []byte{0}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(apn); i++ {
		if i == len(apn) || apn[i] == '.' {
			label := apn[start:i]
			out = append(out, byte(len(label)))
			out = append(out, []byte(label)...)
			start = i + 1
		}
	}
	return out
}

func decodeDNSLabels(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var labels []string
	for i := 0; i < len(raw); {
		l := int(raw[i])
		i++
		if l == 0 {
			break
		}
		if i+l > len(raw) {
			return string(raw)
		}
		labels = append(labels, string(raw[i:i+l]))
		i += l
	}
	return strings.Join(labels, ".")
}
