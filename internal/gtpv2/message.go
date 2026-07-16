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

// headerLenNoTEID is used by Echo Request, Echo Response and Version Not
// Supported Indication (T=0).
const headerLenNoTEID = 8

// flagVersion2TEID is flags byte: version=2, piggybacking=0, TEID=1, reserved=0.
const flagVersion2TEID = 0x48

// flagVersion2NoTEID is flags byte: version=2, piggybacking=0, TEID=0, reserved=0.
const flagVersion2NoTEID = 0x40

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

// EncodeNoTEID serialises a T=0 GTPv2-C message. TS 29.274 uses this header
// form for Echo Request, Echo Response and Version Not Supported Indication.
func EncodeNoTEID(m *Message) []byte {
	body := EncodeIEs(m.IEs)
	totalLen := headerLenNoTEID + len(body)
	lengthField := uint16(totalLen - 4)

	buf := make([]byte, totalLen)
	buf[0] = flagVersion2NoTEID
	buf[1] = m.Type
	binary.BigEndian.PutUint16(buf[2:4], lengthField)
	buf[4] = byte(m.SeqNum >> 16)
	buf[5] = byte(m.SeqNum >> 8)
	buf[6] = byte(m.SeqNum)
	buf[7] = 0
	copy(buf[8:], body)
	return buf
}

// EncodePiggybacked returns one UDP payload containing a primary GTPv2-C
// message followed by one piggybacked message. The primary message gets the
// piggyback flag set; the final message keeps it clear.
func EncodePiggybacked(primary, piggyback []byte) ([]byte, error) {
	if len(primary) == 0 || len(piggyback) == 0 {
		return nil, fmt.Errorf("gtpv2: piggyback requires non-empty primary and piggyback messages")
	}
	if len(primary) < 1 || len(piggyback) < 1 {
		return nil, fmt.Errorf("gtpv2: piggyback message too short")
	}
	out := make([]byte, 0, len(primary)+len(piggyback))
	out = append(out, primary...)
	out[0] |= 0x10
	out = append(out, piggyback...)
	return out, nil
}

// DecodeAll parses one or more GTPv2-C messages from a UDP datagram.
// If the piggybacking flag is set on a message, decoding continues at the next
// message boundary until the final message with P=0 is reached.
func DecodeAll(b []byte) ([]*Message, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("gtpv2: empty datagram")
	}
	var msgs []*Message
	for len(b) > 0 {
		if len(b) < headerLenNoTEID {
			return nil, fmt.Errorf("gtpv2: trailing datagram too short (%d bytes)", len(b))
		}
		length := binary.BigEndian.Uint16(b[2:4])
		totalLen := int(length) + 4
		if len(b) < totalLen {
			return nil, fmt.Errorf("gtpv2: length field %d but only %d bytes available", length, len(b))
		}
		msg, err := Decode(b[:totalLen])
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
		piggyback := (b[0] & 0x10) != 0
		b = b[totalLen:]
		if !piggyback {
			if len(b) != 0 {
				return nil, fmt.Errorf("gtpv2: trailing bytes present after final message (%d bytes)", len(b))
			}
			break
		}
	}
	return msgs, nil
}

// Decode parses a GTPv2-C datagram.
func Decode(b []byte) (*Message, error) {
	if len(b) < headerLenNoTEID {
		return nil, fmt.Errorf("gtpv2: datagram too short (%d bytes)", len(b))
	}
	flags := b[0]
	version := (flags >> 5) & 0x07
	if version != 2 {
		return nil, fmt.Errorf("gtpv2: unexpected version %d", version)
	}
	tBit := (flags >> 3) & 0x01

	msgType := b[1]
	length := binary.BigEndian.Uint16(b[2:4])
	expectedTotal := int(length) + 4
	if len(b) < expectedTotal {
		return nil, fmt.Errorf("gtpv2: length field %d but only %d bytes available", length, len(b))
	}

	if tBit == 0 {
		if expectedTotal < headerLenNoTEID {
			return nil, fmt.Errorf("gtpv2: no-TEID message length %d smaller than header %d", expectedTotal, headerLenNoTEID)
		}
		seqNum := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		ies, err := DecodeIEs(b[headerLenNoTEID:expectedTotal])
		if err != nil {
			return nil, err
		}
		return &Message{
			Type:   msgType,
			TEID:   0,
			SeqNum: seqNum,
			IEs:    ies,
		}, nil
	}

	if len(b) < headerLen {
		return nil, fmt.Errorf("gtpv2: TEID-present datagram too short (%d bytes)", len(b))
	}
	if expectedTotal < headerLen {
		return nil, fmt.Errorf("gtpv2: TEID-present message length %d smaller than header %d", expectedTotal, headerLen)
	}
	teid := binary.BigEndian.Uint32(b[4:8])
	seqNum := uint32(b[8])<<16 | uint32(b[9])<<8 | uint32(b[10])

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
