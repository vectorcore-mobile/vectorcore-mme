package emm

import "fmt"

const GenericMessageContainerTypeLPP uint8 = 0x01

// GenericMessageContainerTypeLCS is TS 24.301 §9.9.3.42's "Location services
// message container" value (TS 24.171), carrying the TS 24.080 LCS
// notification REGISTER/RELEASE COMPLETE messages built/parsed by
// internal/nas/lcsnotify — a sibling container type to LPP on the same
// Downlink/Uplink Generic NAS Transport messages.
const GenericMessageContainerTypeLCS uint8 = 0x02
const maxGenericMessageContainer = 65535

// additionalInformationIEI is TS 24.301 §9.9.2.0's "Additional information"
// IEI. Per TS 24.171 §5.3.2.1.1, the MME must include the SLs Correlation ID
// (TS 29.171) here as a Routing Identifier on every LPP-container Downlink
// Generic NAS Transport message, so the MME can later map an Uplink Generic
// NAS Transport's LPP response back to the right SLs transaction. §5.2.1.1.0's
// NOTE explicitly says this IE is NOT used for the LCS-notification container
// type, so routing must stay nil for that path.
const additionalInformationIEI uint8 = 0x65

// maxAdditionalInformation is the IE's 1-octet length field's range (TS
// 24.301 Type 4 IE); the routing value this package actually sends is always
// a 4-byte SLs Correlation ID, well within bounds.
const maxAdditionalInformation = 255

func validGenericMessageContainerType(t uint8) bool {
	return t == GenericMessageContainerTypeLPP || t == GenericMessageContainerTypeLCS
}

// EncodeDownlinkGenericNASTransport builds a DOWNLINK GENERIC NAS TRANSPORT
// message. routing is optional (nil/empty omits the Additional Information
// IE entirely, as required for GenericMessageContainerTypeLCS); when
// present, it is carried verbatim as that IE's value.
func EncodeDownlinkGenericNASTransport(containerType uint8, routing []byte, payload []byte) ([]byte, error) {
	if !validGenericMessageContainerType(containerType) {
		return nil, fmt.Errorf("emm: unsupported generic container type %d", containerType)
	}
	if len(payload) == 0 || len(payload) > maxGenericMessageContainer {
		return nil, fmt.Errorf("emm: invalid generic container length %d", len(payload))
	}
	if len(routing) > maxAdditionalInformation {
		return nil, fmt.Errorf("emm: invalid additional information length %d", len(routing))
	}
	b := []byte{PDEPSMobilityMgmt, MsgDownlinkGenericNASTransport, containerType, byte(len(payload) >> 8), byte(len(payload))}
	b = append(b, payload...)
	if len(routing) > 0 {
		b = append(b, additionalInformationIEI, byte(len(routing)))
		b = append(b, routing...)
	}
	return b, nil
}

// DecodeUplinkGenericNASTransport parses an UPLINK GENERIC NAS TRANSPORT
// message body. A trailing Additional Information IE (TS 24.171 §5.3.2.1.2:
// the UE echoes the Routing Identifier it was given) is accepted if
// well-formed and its value discarded — the MME already knows the
// correlation ID from its own transaction state — but anything else
// trailing the declared container length is rejected fail-closed rather
// than silently ignored.
func DecodeUplinkGenericNASTransport(body []byte) (uint8, []byte, error) {
	if len(body) < 3 {
		return 0, nil, fmt.Errorf("emm: generic NAS transport truncated")
	}
	typ := body[0]
	if !validGenericMessageContainerType(typ) {
		return 0, nil, fmt.Errorf("emm: unsupported generic container type %d", typ)
	}
	n := int(body[1])<<8 | int(body[2])
	if n == 0 || n > maxGenericMessageContainer || len(body) < 3+n {
		return 0, nil, fmt.Errorf("emm: malformed generic container length")
	}
	payload := append([]byte(nil), body[3:3+n]...)
	rest := body[3+n:]
	if len(rest) > 0 {
		if len(rest) < 2 || rest[0] != additionalInformationIEI {
			return 0, nil, fmt.Errorf("emm: malformed generic container length")
		}
		alen := int(rest[1])
		if len(rest) != 2+alen {
			return 0, nil, fmt.Errorf("emm: malformed additional information length")
		}
	}
	return typ, payload, nil
}
