// Package sls implements the MME side of TS 29.171.  It deliberately uses
// the shared Go APER primitives; no generated or native ASN.1 runtime is used.
package sls

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

const (
	ProcedureLocationRequest uint8 = 0
	// ProcedureConnectionOrientedInformation (TS 29.171 §6.2.2.1, id-Connection-
	// Oriented-Information-Transfer = 1) carries both LPP and LPPa APDUs between
	// the MME and E-SMLC over the same association as an ongoing Location
	// Request, distinguished by the Payload-Type IE - not two separate
	// procedures.
	ProcedureConnectionOrientedInformation uint8  = 1
	ProcedureLocationAbort                 uint8  = 3
	ProcedureReset                         uint8  = 4
	PPID                                   uint32 = 29
	IECorrelationID                        uint16 = 2
	IEECGI                                 uint16 = 4
	IELCSClientType                        uint16 = 8
	IELCSCause                             uint16 = 11
	IELocationEstimate                     uint16 = 12
	IELocationType                         uint16 = 13
	IEUEPositioningCapability              uint16 = 20
	IEPositioningData                      uint16 = 16
	IEAccuracyFulfilmentIndicator          uint16 = 0
	// IEAPDU and IEPayloadType (TS 29.171 §7.4.17/§7.4.18, id-APDU = 1,
	// id-Payload-Type = 15) are the Connection Oriented Information message's
	// IEs, not part of the Location Request/Response IE set above.
	IEAPDU        uint16 = 1
	IEPayloadType uint16 = 15
)

type Category uint8

const (
	Initiating Category = iota
	Successful
	Unsuccessful
)

type IE struct {
	ID          uint16
	Criticality aper.Criticality
	Value       []byte
	Known       bool
}
type PDU struct {
	Category    Category
	Procedure   uint8
	Criticality aper.Criticality
	IEs         []IE
}

// Decode is intentionally generic for the outer PDU and IE container. Typed
// procedure validation belongs to ValidateResponse so unknown ignore/notify
// extensions remain forward compatible.
func Decode(b []byte) (PDU, error) {
	r := aper.NewBitReader(b)
	extBit, err := r.ReadBit()
	if err != nil {
		return PDU{}, fmt.Errorf("lcs-ap: read extension bit: %w", err)
	}
	if extBit != 0 {
		return PDU{}, fmt.Errorf("lcs-ap: extended PDU type not supported")
	}
	v, err := r.ReadBits(2)
	if err != nil || v > 2 {
		return PDU{}, fmt.Errorf("lcs-ap: invalid PDU choice")
	}
	proc, err := r.ReadOctet()
	if err != nil {
		return PDU{}, fmt.Errorf("lcs-ap: procedure: %w", err)
	}
	crit, err := aper.DecodeCriticality(r)
	if err != nil {
		return PDU{}, err
	}
	body, err := aper.ReadOpenType(r)
	if err != nil {
		return PDU{}, err
	}
	if r.Remaining() != 0 {
		return PDU{}, fmt.Errorf("lcs-ap: trailing PDU data")
	}
	br := aper.NewBitReader(body)
	bodyExt, err := br.ReadBit()
	if err != nil {
		return PDU{}, fmt.Errorf("lcs-ap: procedure extension marker: %w", err)
	}
	if bodyExt != 0 {
		return PDU{}, fmt.Errorf("lcs-ap: procedure extensions not supported")
	}
	hasProtocolExtensions, err := br.ReadBit()
	if err != nil {
		return PDU{}, fmt.Errorf("lcs-ap: protocolExtensions presence bit: %w", err)
	}
	if hasProtocolExtensions != 0 {
		return PDU{}, fmt.Errorf("lcs-ap: protocolExtensions not supported")
	}
	n, err := aper.DecodeConstrainedWholeNumber(br, 0, 65535)
	if err != nil {
		return PDU{}, err
	}
	if n > 1024 {
		return PDU{}, fmt.Errorf("lcs-ap: too many IEs")
	}
	p := PDU{Category: Category(v), Procedure: proc, Criticality: crit, IEs: make([]IE, 0, n)}
	for i := int64(0); i < n; i++ {
		id, e := aper.DecodeConstrainedWholeNumber(br, 0, 65535)
		if e != nil {
			return PDU{}, e
		}
		c, e := aper.DecodeCriticality(br)
		if e != nil {
			return PDU{}, e
		}
		value, e := aper.ReadOpenType(br)
		if e != nil {
			return PDU{}, e
		}
		p.IEs = append(p.IEs, IE{ID: uint16(id), Criticality: c, Value: value, Known: knownIE(uint16(id))})
	}
	if br.Remaining() > 7 {
		return PDU{}, fmt.Errorf("lcs-ap: trailing procedure data")
	}
	return p, nil
}
func Encode(p PDU) ([]byte, error) {
	if p.Category > Unsuccessful {
		return nil, fmt.Errorf("lcs-ap: invalid PDU category")
	}
	bw := aper.NewBitWriter()
	bw.WriteBit(0) // procedure SEQUENCE extension marker: no extension additions
	bw.WriteBit(0) // protocolExtensions OPTIONAL: absent
	if err := aper.EncodeConstrainedWholeNumber(bw, int64(len(p.IEs)), 0, 65535); err != nil {
		return nil, err
	}
	for _, ie := range p.IEs {
		if err := aper.EncodeConstrainedWholeNumber(bw, int64(ie.ID), 0, 65535); err != nil {
			return nil, err
		}
		aper.EncodeCriticality(bw, ie.Criticality)
		aper.WriteOpenType(bw, ie.Value)
	}
	w := aper.NewBitWriter()
	w.WriteBit(0) // PDU CHOICE extension marker: root alternative
	w.WriteBits(uint64(p.Category), 2)
	w.WriteOctet(p.Procedure)
	aper.EncodeCriticality(w, p.Criticality)
	aper.WriteOpenType(w, bw.Bytes())
	return w.Bytes(), nil
}
func knownIE(id uint16) bool {
	switch id {
	case IECorrelationID, IEECGI, IELCSClientType, IELCSCause, IELocationEstimate, IELocationType, IEPositioningData, IEAccuracyFulfilmentIndicator:
		return true
	}
	return false
}
func correlation(p PDU) ([]byte, error) {
	for _, ie := range p.IEs {
		if ie.ID == IECorrelationID {
			if len(ie.Value) != 4 {
				return nil, fmt.Errorf("lcs-ap: invalid correlation ID")
			}
			return append([]byte(nil), ie.Value...), nil
		}
	}
	return nil, fmt.Errorf("lcs-ap: missing correlation ID")
}
