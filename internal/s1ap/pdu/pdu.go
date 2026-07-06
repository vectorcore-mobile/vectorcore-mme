// Package pdu encodes and decodes S1AP PDUs using the APER codec.
//
// S1AP PDU structure (3GPP TS 36.413):
//
//	S1AP-PDU ::= CHOICE {  -- with extension marker
//	    initiatingMessage    InitiatingMessage,
//	    successfulOutcome    SuccessfulOutcome,
//	    unsuccessfulOutcome  UnsuccessfulOutcome, ...
//	}
//	InitiatingMessage ::= SEQUENCE {
//	    procedureCode  ProcedureCode,   -- 0..255
//	    criticality    Criticality,     -- ENUMERATED {reject, ignore, notify}
//	    value          OPEN TYPE        -- the actual message content
//	}
package pdu

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// PDU is a decoded S1AP PDU.
type PDU struct {
	Type          PDUType
	ProcedureCode uint8
	Criticality   aper.Criticality
	Value         []byte // raw OPEN TYPE value (contains encoded IE container)
}

// Decode decodes a raw APER-encoded S1AP PDU.
func Decode(data []byte) (*PDU, error) {
	r := aper.NewBitReader(data)

	// Extension bit (1) + choice index (2) = 3 bits
	extBit, err := r.ReadBit()
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: read extension bit: %w", err)
	}
	if extBit == 1 {
		// Extension addition — not supported in Phase 1
		return nil, fmt.Errorf("s1ap/pdu: extended PDU type not supported")
	}

	choiceIdx, err := r.ReadBits(2)
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: read choice: %w", err)
	}
	if choiceIdx > 2 {
		return nil, fmt.Errorf("s1ap/pdu: unknown choice index %d", choiceIdx)
	}

	// ProcedureCode: INTEGER (0..255) → range=256 → byte-aligned (1 byte)
	r.AlignToByte()
	proc, err := r.ReadOctet()
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: read procedure code: %w", err)
	}

	// Criticality: ENUMERATED {reject,ignore,notify} → 2 bits (no extension)
	crit, err := aper.DecodeCriticality(r)
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: read criticality: %w", err)
	}

	// Value: OPEN TYPE (byte-aligned, length-prefixed)
	value, err := aper.ReadOpenType(r)
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: read value: %w", err)
	}

	return &PDU{
		Type:          PDUType(choiceIdx),
		ProcedureCode: proc,
		Criticality:   crit,
		Value:         value,
	}, nil
}

// Encode encodes an S1AP PDU to APER bytes.
func Encode(p *PDU) []byte {
	w := aper.NewBitWriter()

	// Extension bit = 0 (root)
	w.WriteBit(0)
	// Choice index (2 bits)
	w.WriteBits(uint64(p.Type), 2)

	// ProcedureCode: 1 byte, aligned
	w.AlignToByte()
	w.WriteOctet(p.ProcedureCode)

	// Criticality: 2 bits
	aper.EncodeCriticality(w, p.Criticality)

	// Value: OPEN TYPE
	aper.WriteOpenType(w, p.Value)

	return w.Bytes()
}

// DecodeIEContainer decodes a SEQUENCE OF ProtocolIE-Field from the PDU value bytes.
func DecodeIEContainer(data []byte) ([]ProtocolIE, error) {
	r := aper.NewBitReader(data)

	// Count: constrained to 0..65535 → 16-bit aligned
	count, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
	if err != nil {
		return nil, fmt.Errorf("s1ap/pdu: IE count: %w", err)
	}

	ies := make([]ProtocolIE, 0, int(count))
	for i := 0; i < int(count); i++ {
		// IE ID: 0..65535 → 2 bytes aligned
		id, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("s1ap/pdu: IE[%d] id: %w", i, err)
		}

		// Criticality: 2 bits
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			return nil, fmt.Errorf("s1ap/pdu: IE[%d] criticality: %w", i, err)
		}

		// Value: OPEN TYPE
		val, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("s1ap/pdu: IE[%d] value: %w", i, err)
		}

		ies = append(ies, ProtocolIE{
			ID:          uint16(id),
			Criticality: crit,
			Value:       val,
		})
	}
	return ies, nil
}

// EncodeIEContainer encodes a list of IEs as a SEQUENCE OF ProtocolIE-Field.
func EncodeIEContainer(ies []ProtocolIE) []byte {
	w := aper.NewBitWriter()

	// Count: constrained 0..65535
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(ies)), 0, 65535)

	for _, ie := range ies {
		// IE ID: constrained 0..65535
		_ = aper.EncodeConstrainedWholeNumber(w, int64(ie.ID), 0, 65535)
		// Criticality: 2 bits
		aper.EncodeCriticality(w, ie.Criticality)
		// Value: OPEN TYPE
		aper.WriteOpenType(w, ie.Value)
	}
	return w.Bytes()
}

// BuildInitiatingMessage is a helper to build a complete S1AP PDU bytes for an initiating message.
func BuildInitiatingMessage(procCode uint8, criticality aper.Criticality, ies []ProtocolIE) []byte {
	return Encode(&PDU{
		Type:          PDUTypeInitiatingMessage,
		ProcedureCode: procCode,
		Criticality:   criticality,
		Value:         EncodeIEContainer(ies),
	})
}

// BuildSuccessfulOutcome builds a complete S1AP PDU for a successful outcome.
func BuildSuccessfulOutcome(procCode uint8, criticality aper.Criticality, ies []ProtocolIE) []byte {
	return Encode(&PDU{
		Type:          PDUTypeSuccessfulOutcome,
		ProcedureCode: procCode,
		Criticality:   criticality,
		Value:         EncodeIEContainer(ies),
	})
}

// BuildUnsuccessfulOutcome builds a complete S1AP PDU for an unsuccessful outcome.
func BuildUnsuccessfulOutcome(procCode uint8, criticality aper.Criticality, ies []ProtocolIE) []byte {
	return Encode(&PDU{
		Type:          PDUTypeUnsuccessfulOutcome,
		ProcedureCode: procCode,
		Criticality:   criticality,
		Value:         EncodeIEContainer(ies),
	})
}
