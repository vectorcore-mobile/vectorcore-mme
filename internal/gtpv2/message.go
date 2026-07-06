package gtpv2

import (
	"encoding/binary"
	"fmt"
)

// Message represents a GTPv2-C message (TS 29.274 §5.1).
type Message struct {
	Type   uint8
	TEID   uint32 // peer's C-plane TEID; 0 on initial CSReq
	SeqNum uint32
	IEs    []IE
}

// headerLen is the fixed header size when TEID is present (T=1).
// [flags:1][type:1][length:2][teid:4][seqNum:3][spare:1] = 12 bytes
const headerLen = 12

// flagVersion2TEID is flags byte: version=2, piggybacking=0, TEID=1, reserved=0.
const flagVersion2TEID = 0x48

// Encode serialises m into wire format.
func Encode(m *Message) []byte {
	body := EncodeIEs(m.IEs)

	// length field = total bytes − 4 (excludes first 4 bytes: flags, type, length field itself)
	totalLen := headerLen + len(body)
	lengthField := uint16(totalLen - 4)

	buf := make([]byte, totalLen)
	buf[0] = flagVersion2TEID
	buf[1] = m.Type
	binary.BigEndian.PutUint16(buf[2:4], lengthField)
	binary.BigEndian.PutUint32(buf[4:8], m.TEID)
	buf[8] = byte(m.SeqNum >> 16)
	buf[9] = byte(m.SeqNum >> 8)
	buf[10] = byte(m.SeqNum)
	buf[11] = 0 // spare
	copy(buf[12:], body)
	return buf
}

// Decode parses a GTPv2-C datagram. It requires the TEID-present (T=1) format.
func Decode(b []byte) (*Message, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("gtpv2: datagram too short (%d bytes)", len(b))
	}
	flags := b[0]
	version := (flags >> 5) & 0x07
	if version != 2 {
		return nil, fmt.Errorf("gtpv2: unexpected version %d", version)
	}
	tBit := (flags >> 3) & 0x01
	if tBit == 0 {
		return nil, fmt.Errorf("gtpv2: TEID-absent format not supported")
	}

	msgType := b[1]
	length := binary.BigEndian.Uint16(b[2:4])
	teid := binary.BigEndian.Uint32(b[4:8])
	seqNum := uint32(b[8])<<16 | uint32(b[9])<<8 | uint32(b[10])

	expectedTotal := int(length) + 4
	if len(b) < expectedTotal {
		return nil, fmt.Errorf("gtpv2: length field %d but only %d bytes available", length, len(b))
	}

	ies, err := DecodeIEs(b[headerLen:expectedTotal])
	if err != nil {
		return nil, err
	}

	return &Message{
		Type:   msgType,
		TEID:   teid,
		SeqNum: seqNum,
		IEs:    ies,
	}, nil
}
