package emm

import "fmt"

const GenericMessageContainerTypeLPP uint8 = 0x01
const maxGenericMessageContainer = 65535

func EncodeDownlinkGenericNASTransport(containerType uint8, payload []byte) ([]byte, error) {
	if containerType != GenericMessageContainerTypeLPP {
		return nil, fmt.Errorf("emm: unsupported generic container type %d", containerType)
	}
	if len(payload) == 0 || len(payload) > maxGenericMessageContainer {
		return nil, fmt.Errorf("emm: invalid generic container length %d", len(payload))
	}
	b := []byte{PDEPSMobilityMgmt, MsgDownlinkGenericNASTransport, containerType, byte(len(payload) >> 8), byte(len(payload))}
	return append(b, payload...), nil
}
func DecodeUplinkGenericNASTransport(body []byte) (uint8, []byte, error) {
	if len(body) < 3 {
		return 0, nil, fmt.Errorf("emm: generic NAS transport truncated")
	}
	typ := body[0]
	if typ != GenericMessageContainerTypeLPP {
		return 0, nil, fmt.Errorf("emm: unsupported generic container type %d", typ)
	}
	n := int(body[1])<<8 | int(body[2])
	if n == 0 || n > maxGenericMessageContainer || len(body) != 3+n {
		return 0, nil, fmt.Errorf("emm: malformed generic container length")
	}
	return typ, append([]byte(nil), body[3:]...), nil
}
