package esm

import (
	"encoding/hex"
	"fmt"

	"github.com/vectorcore/mme/internal/gtpv2"
)

const normalizedDedicatedBearerMaxBitrateBps uint64 = 10_240_000 * 1024

type BearerProcedureResponse struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	MessageType            uint8
	Cause                  uint8
	PCO                    []byte
}

type DedicatedBearerQoSDebugInfo struct {
	FallbackQCI            uint8
	RawParseOK             bool
	RawParseError          string
	RawQCI                 uint8
	EffectiveQCI           uint8
	RawUplinkMBR           uint64
	RawDownlinkMBR         uint64
	RawUplinkGBR           uint64
	RawDownlinkGBR         uint64
	NormalizedUplinkMBR    uint64
	NormalizedDownlinkMBR  uint64
	NormalizedUplinkGBR    uint64
	NormalizedDownlinkGBR  uint64
	NormalizedFieldsFilled bool
	FallbackToQCIOnly      bool
	EncodedLength          uint8
	EncodedHex             string
}

func EncodeActivateDedicatedEPSBearerContextRequest(assignedEBI, linkedEBI, pti uint8, qos []byte, qci uint8, tft []byte, pco []byte) []byte {
	buf := []byte{
		(assignedEBI << 4) | PDEPSSessionMgmt,
		pti,
		MsgActivateDedicatedEPSBearerContextRequest,
		linkedEBI & 0x0f,
	}
	buf = append(buf, encodeDedicatedBearerEPSQoS(qos, qci)...)
	if len(tft) > 255 {
		tft = tft[:255]
	}
	buf = append(buf, byte(len(tft)))
	buf = append(buf, tft...)
	if len(pco) > 0 {
		if len(pco) > 255 {
			pco = pco[:255]
		}
		buf = append(buf, 0x27, byte(len(pco)))
		buf = append(buf, pco...)
	}
	return buf
}

func EncodeModifyEPSBearerContextRequest(ebi, pti, qci uint8, qos []byte, tft []byte, pco []byte) []byte {
	return EncodeModifyEPSBearerContextRequestWithAPNAMBR(ebi, pti, qci, qos, tft, 0, 0, pco)
}

// EncodeModifyEPSBearerContextRequestWithAPNAMBR encodes a network-initiated
// Modify EPS Bearer Context Request, including APN-AMBR when supplied in bits/s.
func EncodeModifyEPSBearerContextRequestWithAPNAMBR(ebi, pti, qci uint8, qos []byte, tft []byte, apnAMBRUpBps, apnAMBRDownBps uint32, pco []byte) []byte {
	buf := []byte{(ebi << 4) | PDEPSSessionMgmt, pti, MsgModifyEPSBearerContextRequest}
	if epsQOS := encodeDedicatedBearerEPSQoS(qos, qci); len(epsQOS) > 0 {
		buf = append(buf, 0x5b)
		buf = append(buf, epsQOS...)
	}
	if len(tft) > 0 {
		if len(tft) > 255 {
			tft = tft[:255]
		}
		buf = append(buf, 0x36, byte(len(tft)))
		buf = append(buf, tft...)
	}
	if ambr, ok := encodeAPNAMBR(apnAMBRDownBps, apnAMBRUpBps); ok {
		buf = append(buf, 0x5e, byte(len(ambr)))
		buf = append(buf, ambr...)
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

func EncodeDeactivateEPSBearerContextRequest(ebi, pti, cause uint8) []byte {
	return []byte{(ebi << 4) | PDEPSSessionMgmt, pti, MsgDeactivateEPSBearerContextRequest, cause}
}

func DecodeBearerProcedureResponse(data []byte) (*BearerProcedureResponse, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("esm: bearer procedure response too short: %d", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	resp := &BearerProcedureResponse{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
		MessageType:            data[2],
	}
	i := 3
	switch resp.MessageType {
	case MsgActivateDedicatedEPSBearerContextAccept,
		MsgModifyEPSBearerContextAccept,
		MsgDeactivateEPSBearerContextAccept:
	case MsgActivateDedicatedEPSBearerContextReject, MsgModifyEPSBearerContextReject:
		if len(data) < 4 {
			return nil, fmt.Errorf("esm: bearer procedure reject missing cause")
		}
		resp.Cause = data[3]
		i = 4
	default:
		return nil, fmt.Errorf("esm: unexpected bearer procedure message type %#x", resp.MessageType)
	}
	for i < len(data) {
		iei := data[i]
		i++
		if iei != 0x27 {
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated optional IE %#x", iei)
			}
			l := int(data[i])
			i++
			if i+l > len(data) {
				return nil, fmt.Errorf("esm: optional IE %#x truncated", iei)
			}
			i += l
			continue
		}
		if i >= len(data) {
			return nil, fmt.Errorf("esm: truncated PCO length")
		}
		l := int(data[i])
		i++
		if i+l > len(data) {
			return nil, fmt.Errorf("esm: truncated PCO value")
		}
		resp.PCO = append([]byte(nil), data[i:i+l]...)
		i += l
	}
	return resp, nil
}

func encodeDedicatedBearerEPSQoS(raw []byte, fallbackQCI uint8) []byte {
	debug := InspectDedicatedBearerQoSForDebug(raw, fallbackQCI)
	if debug.EncodedHex == "" {
		return nil
	}
	return mustDecodeHex(debug.EncodedHex)
}

func InspectDedicatedBearerQoSForDebug(raw []byte, fallbackQCI uint8) DedicatedBearerQoSDebugInfo {
	debug := DedicatedBearerQoSDebugInfo{FallbackQCI: fallbackQCI}
	if fallbackQCI == 0 {
		return debug
	}
	parsed, err := gtpv2.ParseBearerQoS(raw)
	if err != nil {
		debug.RawParseError = err.Error()
		debug.FallbackToQCIOnly = true
		debug.EncodedLength = 1
		debug.EffectiveQCI = fallbackQCI
		debug.EncodedHex = fmt.Sprintf("%02x%02x", 0x01, fallbackQCI)
		return debug
	}
	debug.RawParseOK = true
	debug.RawQCI = parsed.QCI
	debug.RawUplinkMBR = parsed.UplinkMBR
	debug.RawDownlinkMBR = parsed.DownlinkMBR
	debug.RawUplinkGBR = parsed.UplinkGBR
	debug.RawDownlinkGBR = parsed.DownlinkGBR
	qci := parsed.QCI
	if qci == 0 {
		qci = fallbackQCI
	}
	debug.EffectiveQCI = qci
	ulMBR, dlMBR, ulGBR, dlGBR := normalizeDedicatedBearerRates(parsed)
	debug.NormalizedUplinkMBR = ulMBR
	debug.NormalizedDownlinkMBR = dlMBR
	debug.NormalizedUplinkGBR = ulGBR
	debug.NormalizedDownlinkGBR = dlGBR
	debug.NormalizedFieldsFilled =
		(ulMBR != debug.RawUplinkMBR) ||
			(dlMBR != debug.RawDownlinkMBR) ||
			(ulGBR != debug.RawUplinkGBR) ||
			(dlGBR != debug.RawDownlinkGBR)
	if ulMBR == 0 && dlMBR == 0 && ulGBR == 0 && dlGBR == 0 {
		debug.FallbackToQCIOnly = true
		debug.EncodedLength = 1
		debug.EncodedHex = fmt.Sprintf("%02x%02x", 0x01, qci)
		return debug
	}
	rates := [4]nasEPSQoSBitRate{}
	length := uint8(1)
	length = maxUint8(length, encodeNASQoSFromBps(&rates[0], ulMBR))
	length = maxUint8(length, encodeNASQoSFromBps(&rates[1], dlMBR))
	length = maxUint8(length, encodeNASQoSFromBps(&rates[2], ulGBR))
	length = maxUint8(length, encodeNASQoSFromBps(&rates[3], dlGBR))
	out := []byte{length*4 + 1, qci}
	out = append(out, rates[0].base, rates[1].base, rates[2].base, rates[3].base)
	if length >= 2 {
		out = append(out, rates[0].extended, rates[1].extended, rates[2].extended, rates[3].extended)
	}
	if length >= 3 {
		out = append(out, rates[0].extended2, rates[1].extended2, rates[2].extended2, rates[3].extended2)
	}
	debug.EncodedLength = out[0]
	debug.EncodedHex = fmt.Sprintf("%x", out)
	return debug
}

type nasEPSQoSBitRate struct {
	base      uint8
	extended  uint8
	extended2 uint8
}

func normalizeDedicatedBearerRates(parsed *gtpv2.BearerQoS) (ulMBR, dlMBR, ulGBR, dlGBR uint64) {
	if parsed == nil {
		return 0, 0, 0, 0
	}
	ulMBR = parsed.UplinkMBR
	dlMBR = parsed.DownlinkMBR
	ulGBR = parsed.UplinkGBR
	dlGBR = parsed.DownlinkGBR
	if ulMBR == 0 && dlMBR == 0 && ulGBR == 0 && dlGBR == 0 {
		return 0, 0, 0, 0
	}
	if ulMBR == 0 {
		ulMBR = normalizedDedicatedBearerMaxBitrateBps
	}
	if dlMBR == 0 {
		dlMBR = normalizedDedicatedBearerMaxBitrateBps
	}
	if ulGBR == 0 {
		ulGBR = normalizedDedicatedBearerMaxBitrateBps
	}
	if dlGBR == 0 {
		dlGBR = normalizedDedicatedBearerMaxBitrateBps
	}
	return ulMBR, dlMBR, ulGBR, dlGBR
}

func encodeNASQoSFromBps(out *nasEPSQoSBitRate, input uint64) uint8 {
	if out == nil {
		return 0
	}
	input /= 1024
	if input < 1 {
		out.base = 0xff
		return 1
	}
	if input <= 63 {
		out.base = uint8(input)
		return 1
	}
	if input <= 568 {
		out.base = uint8(((input - 64) / 8) + 0b01000000)
		return 1
	}
	if input < 576 {
		out.base = 0b01111111
		return 1
	}
	if input <= 8640 {
		out.base = uint8(((input - 576) / 64) + 0b10000000)
		return 1
	}
	if input < 8700 {
		out.base = 0b11111110
		return 1
	}
	if input <= 16000 {
		out.base = 0b11111110
		out.extended = uint8((input - 8600) / 100)
		return 2
	}
	if input < 17*1024 {
		out.base = 0b11111110
		out.extended = 0b01001010
		return 2
	}
	if input <= 128*1024 {
		out.base = 0b11111110
		out.extended = uint8(((input - (16 * 1024)) / 1024) + 0b01001010)
		return 2
	}
	if input < 130*1024 {
		out.base = 0b11111110
		out.extended = 0b10111010
		return 2
	}
	if input <= 256*1024 {
		out.base = 0b11111110
		out.extended = uint8(((input - (128 * 1024)) / (2 * 1024)) + 0b10111010)
		return 2
	}
	if input < 260*1024 {
		out.base = 0b11111110
		out.extended = 0b11111010
		return 2
	}
	if input <= 500*1024 {
		out.base = 0b11111110
		out.extended = 0b11111010
		out.extended2 = uint8((input - (256 * 1024)) / (4 * 1024))
		return 3
	}
	if input < 510*1024 {
		out.base = 0b11111110
		out.extended = 0b11111010
		out.extended2 = 0b00111101
		return 3
	}
	if input <= 1500*1024 {
		out.base = 0b11111110
		out.extended = 0b11111010
		out.extended2 = uint8(((input - (500 * 1024)) / (10 * 1024)) + 0b00111101)
		return 3
	}
	if input < 1600*1024 {
		out.base = 0b11111110
		out.extended = 0b11111010
		out.extended2 = 0b10100001
		return 3
	}
	if input <= 10*1000*1024 {
		out.base = 0b11111110
		out.extended = 0b11111010
		out.extended2 = uint8(((input - (1500 * 1024)) / (100 * 1024)) + 0b10100001)
		return 3
	}
	out.base = 0b11111110
	out.extended = 0b11111010
	out.extended2 = 0b11110110
	return 3
}

func maxUint8(a, b uint8) uint8 {
	if a > b {
		return a
	}
	return b
}

func mustDecodeHex(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}
