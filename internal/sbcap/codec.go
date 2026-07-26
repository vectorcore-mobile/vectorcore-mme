// Package sbcap implements the LTE SBc-AP (TS 29.168) wire primitives used by
// the MME.  It deliberately keeps APER containers separate from MME routing
// state: the CBC remains authoritative for warning lifecycle and content.
package sbcap

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// SCTPPPIdentifier is the IANA-assigned SCTP PPID for SBc-AP.
const SCTPPPIdentifier uint32 = 24

// Procedure codes from TS 29.168 section 9.1.
const (
	ProcedureWriteReplaceWarning uint8 = iota
	ProcedureStopWarning
	ProcedureErrorIndication
	ProcedureWriteReplaceWarningIndication
	ProcedureStopWarningIndication
	ProcedurePWSRestartIndication
	ProcedurePWSFailureIndication
)

// IE identifiers from TS 29.168 section 9.2.1.  LTE values are retained here;
// 5GS extension identifiers intentionally are not interpreted by this MME.
const (
	IEBroadcastMessageContent           uint16 = 0
	IECause                             uint16 = 1
	IECriticalityDiagnostics            uint16 = 2
	IEDataCodingScheme                  uint16 = 3
	IEFailureList                       uint16 = 4
	IEMessageIdentifier                 uint16 = 5
	IENumberOfBroadcastsCompletedList   uint16 = 6
	IENumberOfBroadcastsRequested       uint16 = 7
	IERepetitionPeriod                  uint16 = 10
	IESerialNumber                      uint16 = 11
	IEListOfTAIs                        uint16 = 14
	IEWarningAreaList                   uint16 = 15
	IEWarningMessageContent             uint16 = 16
	IEWarningSecurityInformation        uint16 = 17
	IEWarningType                       uint16 = 18
	IEConcurrentWarningMessageIndicator uint16 = 20
	IEExtendedRepetitionPeriod          uint16 = 21
	IEUnknownTrackingAreaList           uint16 = 22
	IEBroadcastScheduledAreaList        uint16 = 23
	IESendWriteReplaceWarningIndication uint16 = 24
	IEBroadcastCancelledAreaList        uint16 = 25
	IESendStopWarningIndication         uint16 = 26
	IEStopAllIndicator                  uint16 = 27
	IEGlobalENBID                       uint16 = 28
	IEBroadcastEmptyAreaList            uint16 = 29
	IERestartedCellList                 uint16 = 30
	IEListOfTAIsRestart                 uint16 = 31
	IEListOfEAIsRestart                 uint16 = 32
	IEFailedCellList                    uint16 = 33
)

type PDUType uint8

const (
	PDUTypeInitiatingMessage PDUType = iota
	PDUTypeSuccessfulOutcome
	PDUTypeUnsuccessfulOutcome
)

// PDU is an APER SBc-AP PDU. Value holds the encoded procedure body.
type PDU struct {
	Type          PDUType
	ProcedureCode uint8
	Criticality   aper.Criticality
	Value         []byte
	Raw           []byte
}

// ProtocolIE is a generic SBc-AP ProtocolIE-Field.
type ProtocolIE struct {
	ID          uint16
	Criticality aper.Criticality
	Value       []byte
}

func Decode(data []byte) (*PDU, error) {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return nil, fmt.Errorf("sbcap: PDU extension bit: %w", err)
	}
	if ext != 0 {
		return nil, fmt.Errorf("sbcap: unsupported extended PDU choice")
	}
	choice, err := r.ReadBits(2)
	if err != nil {
		return nil, fmt.Errorf("sbcap: PDU choice: %w", err)
	}
	if choice > uint64(PDUTypeUnsuccessfulOutcome) {
		return nil, fmt.Errorf("sbcap: invalid PDU choice %d", choice)
	}
	r.AlignToByte()
	procedure, err := r.ReadOctet()
	if err != nil {
		return nil, fmt.Errorf("sbcap: procedure code: %w", err)
	}
	criticality, err := aper.DecodeCriticality(r)
	if err != nil {
		return nil, fmt.Errorf("sbcap: criticality: %w", err)
	}
	value, err := aper.ReadOpenType(r)
	if err != nil {
		return nil, fmt.Errorf("sbcap: procedure value: %w", err)
	}
	return &PDU{Type: PDUType(choice), ProcedureCode: procedure, Criticality: criticality, Value: value, Raw: append([]byte(nil), data...)}, nil
}

func Encode(p *PDU) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBits(uint64(p.Type), 2)
	w.AlignToByte()
	w.WriteOctet(p.ProcedureCode)
	aper.EncodeCriticality(w, p.Criticality)
	aper.WriteOpenType(w, p.Value)
	return w.Bytes()
}

// DecodeIEContainer decodes a procedure body. It accepts both the normal
// procedures (which have an optional protocolExtensions root field) and Error
// Indication (which does not). Unknown extension additions are rejected before
// any business logic sees the PDU.
func DecodeIEContainer(data []byte) ([]ProtocolIE, error) {
	if ies, err := decodeIEContainer(data, true); err == nil {
		return ies, nil
	}
	return decodeIEContainer(data, false)
}

func decodeIEContainer(data []byte, hasProtocolExtensions bool) ([]ProtocolIE, error) {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return nil, fmt.Errorf("sbcap: procedure extension bit: %w", err)
	}
	if ext != 0 {
		return nil, fmt.Errorf("sbcap: procedure extensions are not supported")
	}
	if hasProtocolExtensions {
		// A present extension container is deliberately rejected: LTE extension
		// values are not yet interpreted, and silently dropping one is unsafe.
		present, err := r.ReadBit()
		if err != nil {
			return nil, fmt.Errorf("sbcap: procedure optional bitmap: %w", err)
		}
		if present != 0 {
			return nil, fmt.Errorf("sbcap: protocol extensions are not supported")
		}
	}
	r.AlignToByte()
	count, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
	if err != nil {
		return nil, fmt.Errorf("sbcap: IE count: %w", err)
	}
	ies := make([]ProtocolIE, 0, count)
	for i := int64(0); i < count; i++ {
		id, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("sbcap: IE[%d] id: %w", i, err)
		}
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			return nil, fmt.Errorf("sbcap: IE[%d] criticality: %w", i, err)
		}
		value, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("sbcap: IE[%d] value: %w", i, err)
		}
		ies = append(ies, ProtocolIE{ID: uint16(id), Criticality: crit, Value: value})
	}
	return ies, nil
}

func EncodeIEContainer(ies []ProtocolIE) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // procedure SEQUENCE has no extension additions
	w.WriteBit(0) // protocolExtensions absent
	w.AlignToByte()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(ies)), 0, 65535)
	for _, ie := range ies {
		_ = aper.EncodeConstrainedWholeNumber(w, int64(ie.ID), 0, 65535)
		aper.EncodeCriticality(w, ie.Criticality)
		aper.WriteOpenType(w, ie.Value)
	}
	return w.Bytes()
}

func BuildInitiatingMessage(procedure uint8, criticality aper.Criticality, ies []ProtocolIE) []byte {
	return Encode(&PDU{Type: PDUTypeInitiatingMessage, ProcedureCode: procedure, Criticality: criticality, Value: EncodeIEContainer(ies)})
}

func BuildSuccessfulOutcome(procedure uint8, criticality aper.Criticality, ies []ProtocolIE) []byte {
	return Encode(&PDU{Type: PDUTypeSuccessfulOutcome, ProcedureCode: procedure, Criticality: criticality, Value: EncodeIEContainer(ies)})
}
