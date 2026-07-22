package sms

import "fmt"

const (
	epsMobilityManagementPD = 0x07
	uplinkNASTransportType  = 0x63
)

// DecodeNASContainer parses the mandatory NAS message container in an
// Uplink/Downlink NAS Transport payload. TS 24.301 9.9.3.22 uses a one-octet
// length here; the input starts immediately after the EMM message type.
func DecodeNASContainer(payload []byte) ([]byte, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("sms: NAS container too short")
	}
	n := int(payload[0])
	if n == 0 || n != len(payload)-1 {
		return nil, fmt.Errorf("sms: invalid NAS container length: declared=%d available=%d", n, len(payload)-1)
	}
	return append([]byte(nil), payload[1:1+n]...), nil
}

// DecodeUplinkNASTransport decodes the plain EMM form used by TS 24.301
// Uplink NAS Transport. Security verification and deciphering happen in the
// top-level NAS decoder before this helper is called.
func DecodeUplinkNASTransport(pdu []byte) ([]byte, error) {
	if len(pdu) < 3 {
		return nil, fmt.Errorf("sms: uplink NAS transport too short")
	}
	if pdu[0]&0x0f != epsMobilityManagementPD || pdu[1] != uplinkNASTransportType {
		return nil, fmt.Errorf("sms: unexpected uplink NAS transport header pd=%#x type=%#x", pdu[0]&0x0f, pdu[1])
	}
	return DecodeNASContainer(pdu[2:])
}

func EncodeNASContainer(cp []byte) ([]byte, error) {
	if len(cp) == 0 || len(cp) > 255 {
		return nil, fmt.Errorf("sms: invalid NAS container")
	}
	return append([]byte{byte(len(cp))}, cp...), nil
}
