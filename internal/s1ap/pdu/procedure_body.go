package pdu

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// DecodeProcedureIEContainer decodes a procedure SEQUENCE whose first field is
// protocolIEs. S1AP procedure values are OPEN TYPE payloads containing this
// SEQUENCE wrapper, not a bare ProtocolIE container.
func DecodeProcedureIEContainer(data []byte) ([]ProtocolIE, error) {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: procedure extension marker: %w", err)
	}
	if ext != 0 {
		return nil, fmt.Errorf("s1ap/pdu: procedure extensions not supported")
	}
	r.AlignToByte()
	body, err := r.ReadOctets(r.Remaining() / 8)
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: procedure body: %w", err)
	}
	return decodeBareIEContainer(body)
}

// EncodeProcedureIEContainer encodes a procedure SEQUENCE whose first field is
// protocolIEs and which has no extension additions present.
func EncodeProcedureIEContainer(ies []ProtocolIE) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // procedure SEQUENCE extension marker: no extensions
	w.AlignToByte()
	w.WriteOctets(EncodeIEContainer(ies))
	return w.Bytes()
}
