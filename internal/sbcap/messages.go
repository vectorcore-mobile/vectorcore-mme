package sbcap

import (
	"fmt"
	"strings"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// InboundDecision is the LTE SBc-AP receive-side error policy result.  The
// caller performs the functional S1AP action only when Continue is true.
type InboundDecision struct {
	Procedure   uint8
	Request     *WarningRequest
	Continue    bool
	Response    uint8 // 0 none, 1 defined class-1 response, 2 Error Indication
	Cause       uint8
	Diagnostics *CriticalityDiagnostics
}

const (
	ResponseNone uint8 = iota
	ResponseClass1
	ResponseErrorIndication
)

// DecideInbound applies the TS 29.168 MME-side decision boundary before any
// eNB request can be emitted.  It intentionally handles only LTE SBc-AP
// procedures implemented by this MME.
func DecideInbound(data []byte) InboundDecision { return DecideInboundWithReceiverState(data, true) }

// DecideInboundWithReceiverState makes the TS 29.168 receiver-state branch
// explicit and testable. A class-1 request is not functionally dispatched
// unless this returns Continue=true.
func DecideInboundWithReceiverState(data []byte, receiverReady bool) InboundDecision {
	p, err := Decode(data)
	if err != nil {
		return InboundDecision{Response: ResponseErrorIndication, Cause: 13} // transfer-syntax-error
	}
	d := diagnosticForPDU(p)
	if p.ProcedureCode == ProcedureErrorIndication {
		// Never form an Error-Indication loop, including for malformed bodies.
		return InboundDecision{Procedure: p.ProcedureCode}
	}
	var req *WarningRequest
	switch p.ProcedureCode {
	case ProcedureWriteReplaceWarning:
		req, err = DecodeWriteReplaceWarningRequest(p)
	case ProcedureStopWarning:
		req, err = DecodeStopWarningRequest(p)
	default:
		if p.Criticality == aper.CriticalityIgnore {
			return InboundDecision{Procedure: p.ProcedureCode}
		}
		return InboundDecision{Procedure: p.ProcedureCode, Response: ResponseErrorIndication, Cause: 5, Diagnostics: &d}
	}
	if err == nil {
		if !receiverReady {
			return InboundDecision{Procedure: p.ProcedureCode, Response: ResponseClass1, Cause: 15, Diagnostics: &d}
		}
		if len(req.NotifyIEs) != 0 {
			d = diagnosticForPDU(p, req.NotifyIEs...)
			return InboundDecision{Procedure: p.ProcedureCode, Request: req, Continue: true, Response: ResponseClass1, Cause: 0, Diagnostics: &d}
		}
		return InboundDecision{Procedure: p.ProcedureCode, Request: req, Continue: true}
	}
	cause := warningErrorCause(err)
	if messageID, serial, ok := WarningIdentity(p); ok {
		_ = messageID
		_ = serial
		return InboundDecision{Procedure: p.ProcedureCode, Response: ResponseClass1, Cause: cause, Diagnostics: &d}
	}
	return InboundDecision{Procedure: p.ProcedureCode, Response: ResponseErrorIndication, Cause: cause, Diagnostics: &d}
}

// ExecuteInboundDecision is the small handler seam used by the MME callback:
// it makes it impossible for a rejecting policy result to reach eNB dispatch.
func ExecuteInboundDecision(d InboundDecision, dispatch func(*WarningRequest)) {
	if d.Continue && d.Request != nil && dispatch != nil {
		dispatch(d.Request)
	}
}

func warningErrorCause(err error) uint8 {
	s := err.Error()
	switch {
	case strings.Contains(s, "missing"):
		return 6
	case strings.Contains(s, "duplicate"), strings.Contains(s, "incorrectly ordered"):
		return 18 // abstract-syntax-error-falsely-constructed-message
	case strings.Contains(s, "erroneously present conditional"):
		return 18
	case strings.Contains(s, "unknown reject-criticality"), strings.Contains(s, "criticality"):
		return 16 // abstract-syntax-error-reject
	case strings.Contains(s, "parameter value"), strings.Contains(s, "repetition period"), strings.Contains(s, "number of broadcasts"):
		return 2 // parameter-value-invalid
	case strings.Contains(s, "receiver state"):
		return 15
	default:
		return 14 // semantic-error
	}
}

// TypeOfError values used in Criticality Diagnostics.
const (
	TypeOfErrorNotUnderstood uint8 = iota
	TypeOfErrorMissing
)

// CriticalityDiagnosticItem identifies one invalid or absent protocol IE.
// Extensions are deliberately not emitted: this implementation only reports
// the root TS 29.168 fields and therefore never claims to understand an
// extension diagnostic.
type CriticalityDiagnosticItem struct {
	IEID          uint16
	IECriticality aper.Criticality
	TypeOfError   uint8
}

// CriticalityDiagnostics is the complete root Criticality-Diagnostics model
// from TS 29.168. Every field is optional on the wire; callers include only
// information that was actually available while decoding the offending PDU.
type CriticalityDiagnostics struct {
	ProcedureCode        *uint8
	TriggeringMessage    *PDUType
	ProcedureCriticality *aper.Criticality
	Items                []CriticalityDiagnosticItem
}

// EncodeCriticalityDiagnostics encodes the root ASN.1 type using its exact
// APER SIZE (1..256) constraint for the IE diagnostic list.
func EncodeCriticalityDiagnostics(d CriticalityDiagnostics) ([]byte, error) {
	if len(d.Items) > 256 {
		return nil, fmt.Errorf("sbcap: too many criticality diagnostic items: %d", len(d.Items))
	}
	for _, item := range d.Items {
		if item.IECriticality > aper.CriticalityNotify {
			return nil, fmt.Errorf("sbcap: invalid diagnostic IE criticality %d", item.IECriticality)
		}
		if item.TypeOfError > TypeOfErrorMissing {
			return nil, fmt.Errorf("sbcap: invalid diagnostic type of error %d", item.TypeOfError)
		}
	}
	w := aper.NewBitWriter()
	w.WriteBit(0) // no extension additions
	if d.ProcedureCode != nil {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	if d.TriggeringMessage != nil {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	if d.ProcedureCriticality != nil {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	if len(d.Items) != 0 {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	if d.ProcedureCode != nil {
		w.AlignToByte()
		w.WriteOctet(*d.ProcedureCode)
	}
	if d.TriggeringMessage != nil {
		w.WriteBits(uint64(*d.TriggeringMessage), 2)
	}
	if d.ProcedureCriticality != nil {
		aper.EncodeCriticality(w, *d.ProcedureCriticality)
	}
	if len(d.Items) != 0 {
		if err := aper.EncodeConstrainedWholeNumber(w, int64(len(d.Items)), 1, 256); err != nil {
			return nil, err
		}
		for _, item := range d.Items {
			w.WriteBit(0) // no item extensions
			aper.EncodeCriticality(w, item.IECriticality)
			if err := aper.EncodeConstrainedWholeNumber(w, int64(item.IEID), 0, 65535); err != nil {
				return nil, err
			}
			aper.EncodeEnumeratedExt(w, int(item.TypeOfError), 2)
		}
	}
	return w.Bytes(), nil
}

// DecodeCriticalityDiagnostics is intentionally strict: trailing data and
// extension additions are rejected so malformed diagnostic payloads are never
// relayed or accepted as valid protocol state.
func DecodeCriticalityDiagnostics(data []byte) (CriticalityDiagnostics, error) {
	var out CriticalityDiagnostics
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return out, err
	}
	if ext != 0 {
		return out, fmt.Errorf("sbcap: Criticality Diagnostics extensions are unsupported")
	}
	present := [4]bool{}
	for i := range present {
		b, err := r.ReadBit()
		if err != nil {
			return out, err
		}
		present[i] = b != 0
	}
	if present[0] {
		r.AlignToByte()
		v, err := r.ReadOctet()
		if err != nil {
			return out, err
		}
		out.ProcedureCode = &v
	}
	if present[1] {
		v, err := r.ReadBits(2)
		if err != nil || v > uint64(PDUTypeUnsuccessfulOutcome) {
			if err != nil {
				return out, err
			}
			return out, fmt.Errorf("sbcap: invalid diagnostic triggering message %d", v)
		}
		p := PDUType(v)
		out.TriggeringMessage = &p
	}
	if present[2] {
		v, err := aper.DecodeCriticality(r)
		if err != nil {
			return out, err
		}
		out.ProcedureCriticality = &v
	}
	if present[3] {
		n, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
		if err != nil {
			return out, err
		}
		out.Items = make([]CriticalityDiagnosticItem, int(n))
		for i := range out.Items {
			itemExt, err := r.ReadBit()
			if err != nil {
				return out, err
			}
			if itemExt != 0 {
				return out, fmt.Errorf("sbcap: diagnostic item extensions are unsupported")
			}
			crit, err := aper.DecodeCriticality(r)
			if err != nil {
				return out, err
			}
			id, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
			if err != nil {
				return out, err
			}
			typ, err := aper.DecodeEnumeratedExt(r, 2)
			if err != nil {
				return out, err
			}
			if typ > int(TypeOfErrorMissing) {
				return out, fmt.Errorf("sbcap: unsupported diagnostic type of error %d", typ)
			}
			out.Items[i] = CriticalityDiagnosticItem{IEID: uint16(id), IECriticality: crit, TypeOfError: uint8(typ)}
		}
	}
	if r.Remaining() > 7 {
		return out, fmt.Errorf("sbcap: trailing data in Criticality Diagnostics")
	}
	return out, nil
}

func diagnosticForPDU(p *PDU, items ...CriticalityDiagnosticItem) CriticalityDiagnostics {
	d := CriticalityDiagnostics{Items: items}
	if p != nil {
		proc, trigger, crit := p.ProcedureCode, p.Type, p.Criticality
		d.ProcedureCode, d.TriggeringMessage, d.ProcedureCriticality = &proc, &trigger, &crit
	}
	return d
}

// WarningRequest is the MME-facing, typed subset of a Write-Replace or Stop
// Warning request. Raw optional IE encodings are retained so the S1AP bridge
// can preserve warning-area and warning-content data without inventing state.
type WarningRequest struct {
	MessageIdentifier        [2]byte
	SerialNumber             [2]byte
	TAIList                  []byte
	WarningAreaList          []byte
	GlobalENBID              []byte
	OptionalIEs              map[uint16][]byte
	IEs                      map[uint16][]byte // APER values retained for S1AP translation.
	SendIndication           bool
	StopAll                  bool
	RepetitionPeriod         *uint16
	ExtendedRepetitionPeriod *uint32
	NumberOfBroadcasts       *uint16
	ConcurrentWarning        bool
	NotifyIEs                []CriticalityDiagnosticItem
}

// TAI is the LTE tracking-area identity used only for selecting live eNBs.
type TAI struct {
	PLMN [3]byte
	TAC  uint16
}

// DecodeTAIList decodes List-of-TAIs. It intentionally does not interpret a
// Warning Area List: that IE must remain available to the receiving eNB for
// final cell selection.
func DecodeTAIList(data []byte) ([]TAI, error) {
	items, err := decodeTAIListTyped(data)
	if err != nil {
		return nil, fmt.Errorf("sbcap: List-of-TAIs: %w", err)
	}
	return items, nil
}

func DecodeWriteReplaceWarningRequest(p *PDU) (*WarningRequest, error) {
	if p == nil || p.Type != PDUTypeInitiatingMessage || p.ProcedureCode != ProcedureWriteReplaceWarning {
		return nil, fmt.Errorf("sbcap: not a Write-Replace Warning Request")
	}
	ies, err := DecodeIEContainer(p.Value)
	if err != nil {
		return nil, err
	}
	req, err := decodeWarningRequest(ies, true)
	if err != nil {
		return nil, fmt.Errorf("sbcap: Write-Replace Warning Request: %w", err)
	}
	return req, nil
}

func DecodeStopWarningRequest(p *PDU) (*WarningRequest, error) {
	if p == nil || p.Type != PDUTypeInitiatingMessage || p.ProcedureCode != ProcedureStopWarning {
		return nil, fmt.Errorf("sbcap: not a Stop Warning Request")
	}
	ies, err := DecodeIEContainer(p.Value)
	if err != nil {
		return nil, err
	}
	req, err := decodeWarningRequest(ies, false)
	if err != nil {
		return nil, fmt.Errorf("sbcap: Stop Warning Request: %w", err)
	}
	return req, nil
}

// WarningIdentity extracts the response correlation IEs without requiring the
// rest of a class-1 request to be semantically valid.
func WarningIdentity(p *PDU) (messageID, serial [2]byte, ok bool) {
	if p == nil {
		return messageID, serial, false
	}
	ies, err := DecodeIEContainer(p.Value)
	if err != nil {
		return messageID, serial, false
	}
	var haveMessageID, haveSerial bool
	for _, ie := range ies {
		if ie.ID == IEMessageIdentifier {
			if v, err := decodeFixed16BitString(ie.Value); err == nil {
				messageID = v
				haveMessageID = true
			}
		}
		if ie.ID == IESerialNumber {
			if v, err := decodeFixed16BitString(ie.Value); err == nil {
				serial = v
				haveSerial = true
			}
		}
	}
	return messageID, serial, haveMessageID && haveSerial
}

// DiagnosticsForPDU returns root diagnostics for use in a response. It keeps
// protocol context separate from warning payloads and is safe for malformed
// requests for which no individual IE can be identified.
func DiagnosticsForPDU(p *PDU, items ...CriticalityDiagnosticItem) CriticalityDiagnostics {
	return diagnosticForPDU(p, items...)
}

func decodeWarningRequest(ies []ProtocolIE, writeReplace bool) (*WarningRequest, error) {
	req := &WarningRequest{OptionalIEs: make(map[uint16][]byte), IEs: make(map[uint16][]byte)}
	seen := make(map[uint16]bool, len(ies))
	lastOrder := 0
	for _, ie := range ies {
		if seen[ie.ID] {
			return nil, fmt.Errorf("duplicate IE %d", ie.ID)
		}
		seen[ie.ID] = true
		if expected, known := warningIECriticality(ie.ID, writeReplace); known {
			if ie.Criticality != expected {
				return nil, fmt.Errorf("IE %d has criticality %s, want %s", ie.ID, ie.Criticality, expected)
			}
			if order := warningIEOrder(ie.ID, writeReplace); order < lastOrder {
				return nil, fmt.Errorf("incorrectly ordered IE %d", ie.ID)
			} else if order != 0 {
				lastOrder = order
			}
		}
		req.IEs[ie.ID] = append([]byte(nil), ie.Value...)
		switch ie.ID {
		case IEMessageIdentifier:
			v, err := decodeFixed16BitString(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("message identifier: %w", err)
			}
			req.MessageIdentifier = v
		case IESerialNumber:
			v, err := decodeFixed16BitString(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("serial number: %w", err)
			}
			req.SerialNumber = v
		case IEListOfTAIs:
			req.TAIList = append([]byte(nil), ie.Value...)
		case IEWarningAreaList:
			req.WarningAreaList = append([]byte(nil), ie.Value...)
		case IEGlobalENBID:
			req.GlobalENBID = append([]byte(nil), ie.Value...)
		case IERepetitionPeriod:
			v, err := decodeInteger(ie.Value, 0, 4096)
			if err != nil {
				return nil, fmt.Errorf("repetition period: %w", err)
			}
			n := uint16(v)
			req.RepetitionPeriod = &n
		case IEExtendedRepetitionPeriod:
			v, err := decodeInteger(ie.Value, 4096, 131071)
			if err != nil {
				return nil, fmt.Errorf("extended repetition period: %w", err)
			}
			n := uint32(v)
			req.ExtendedRepetitionPeriod = &n
		case IENumberOfBroadcastsRequested:
			v, err := decodeInteger(ie.Value, 0, 65535)
			if err != nil {
				return nil, fmt.Errorf("number of broadcasts: %w", err)
			}
			n := uint16(v)
			req.NumberOfBroadcasts = &n
		case IEConcurrentWarningMessageIndicator:
			v, err := decodeConcurrentWarning(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("concurrent warning message indicator: %w", err)
			}
			req.ConcurrentWarning = v
		case IESendWriteReplaceWarningIndication:
			if !writeReplace {
				return nil, fmt.Errorf("erroneously present conditional IE %d for Stop Warning", ie.ID)
			}
			req.SendIndication = true
		case IESendStopWarningIndication:
			if writeReplace {
				return nil, fmt.Errorf("erroneously present conditional IE %d for Write-Replace Warning", ie.ID)
			}
			req.SendIndication = true
		case IEStopAllIndicator:
			if writeReplace {
				return nil, fmt.Errorf("erroneously present conditional IE %d for Write-Replace Warning", ie.ID)
			}
			req.StopAll = true
		default:
			if ie.Criticality == aper.CriticalityReject {
				return nil, fmt.Errorf("unknown reject-criticality IE %d", ie.ID)
			}
			if ie.Criticality == aper.CriticalityNotify {
				req.NotifyIEs = append(req.NotifyIEs, CriticalityDiagnosticItem{IEID: ie.ID, IECriticality: ie.Criticality, TypeOfError: TypeOfErrorNotUnderstood})
			}
			req.OptionalIEs[ie.ID] = append([]byte(nil), ie.Value...)
		}
	}
	if !seen[IEMessageIdentifier] || !seen[IESerialNumber] {
		return nil, fmt.Errorf("missing Message Identifier or Serial Number")
	}
	if writeReplace && (!seen[IERepetitionPeriod] || !seen[IENumberOfBroadcastsRequested]) {
		return nil, fmt.Errorf("missing Repetition Period or Number of Broadcasts Requested")
	}
	if !writeReplace && req.StopAll && (seen[IEListOfTAIs] || seen[IEWarningAreaList] || seen[IEGlobalENBID]) {
		return nil, fmt.Errorf("semantic error: Stop-All Indicator conflicts with a targeted warning area")
	}
	return req, nil
}

func warningIECriticality(id uint16, writeReplace bool) (aper.Criticality, bool) {
	if writeReplace {
		switch id {
		case IEMessageIdentifier, IESerialNumber, IEListOfTAIs, IERepetitionPeriod, IEExtendedRepetitionPeriod, IENumberOfBroadcastsRequested, IEConcurrentWarningMessageIndicator:
			return aper.CriticalityReject, true
		case IEWarningAreaList, IEWarningType, IEWarningSecurityInformation, IEDataCodingScheme, IEWarningMessageContent, IESendWriteReplaceWarningIndication, IEGlobalENBID:
			return aper.CriticalityIgnore, true
		}
	} else {
		switch id {
		case IEMessageIdentifier, IESerialNumber, IEListOfTAIs, IEStopAllIndicator:
			return aper.CriticalityReject, true
		case IEWarningAreaList, IESendStopWarningIndication:
			return aper.CriticalityIgnore, true
		}
	}
	return 0, false
}

func warningIEOrder(id uint16, writeReplace bool) int {
	if writeReplace {
		switch id {
		case IEMessageIdentifier:
			return 1
		case IESerialNumber:
			return 2
		case IEListOfTAIs:
			return 3
		case IEWarningAreaList:
			return 4
		case IERepetitionPeriod:
			return 5
		case IEExtendedRepetitionPeriod:
			return 6
		case IENumberOfBroadcastsRequested:
			return 7
		case IEWarningType:
			return 8
		case IEWarningSecurityInformation:
			return 9
		case IEDataCodingScheme:
			return 10
		case IEWarningMessageContent:
			return 11
		case IEConcurrentWarningMessageIndicator:
			return 13
		case IESendWriteReplaceWarningIndication:
			return 14
		case IEGlobalENBID:
			return 15
		}
	} else {
		switch id {
		case IEMessageIdentifier:
			return 1
		case IESerialNumber:
			return 2
		case IEListOfTAIs:
			return 3
		case IEWarningAreaList:
			return 4
		case IESendStopWarningIndication:
			return 6
		case IEStopAllIndicator:
			return 7
		}
	}
	return 0
}

func decodeConcurrentWarning(data []byte) (bool, error) {
	r := aper.NewBitReader(data)
	v, err := aper.DecodeEnumerated(r, 1) // ENUMERATED { true }
	if err != nil {
		return false, err
	}
	if v != 0 {
		return false, fmt.Errorf("invalid concurrent warning indicator")
	}
	// ENUMERATED { true } has no value bits. Its enclosing APER open type is
	// nevertheless octet-aligned, so interoperable encoders (including
	// OsmoCBC) legitimately carry one zero padding octet.
	for r.Remaining() > 0 {
		b, err := r.ReadBit()
		if err != nil || b != 0 {
			return false, fmt.Errorf("invalid concurrent warning indicator padding")
		}
	}
	return true, nil
}

func encodeConcurrentWarning() ([]byte, error) {
	w := aper.NewBitWriter()
	aper.EncodeEnumerated(w, 0, 1)
	return w.Bytes(), nil
}

func decodeFixed16BitString(data []byte) ([2]byte, error) {
	var out [2]byte
	r := aper.NewBitReader(data)
	v, err := aper.DecodeBitString(r, 16, 16)
	if err != nil {
		return out, err
	}
	if len(v.Bytes) != 2 {
		return out, fmt.Errorf("got %d bytes", len(v.Bytes))
	}
	copy(out[:], v.Bytes)
	return out, nil
}

func decodeInteger(data []byte, min, max int64) (int64, error) {
	r := aper.NewBitReader(data)
	return aper.DecodeConstrainedWholeNumber(r, min, max)
}

// BuildWarningResponse creates the immediate successful outcome required for
// Write-Replace and Stop Warning. Cause is an SBc-AP Cause enumeration value.
func BuildWarningResponse(procedure uint8, messageID, serial [2]byte, cause uint8, extra []ProtocolIE) ([]byte, error) {
	if procedure != ProcedureWriteReplaceWarning && procedure != ProcedureStopWarning {
		return nil, fmt.Errorf("sbcap: response procedure %d", procedure)
	}
	msg, err := encodeFixed16BitString(messageID)
	if err != nil {
		return nil, err
	}
	ser, err := encodeFixed16BitString(serial)
	if err != nil {
		return nil, err
	}
	causeValue, err := encodeInteger(int64(cause), 0, 255)
	if err != nil {
		return nil, err
	}
	ies := []ProtocolIE{
		{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: msg},
		{ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: ser},
		{ID: IECause, Criticality: aper.CriticalityReject, Value: causeValue},
	}
	ies = append(ies, extra...)
	return BuildSuccessfulOutcome(procedure, aper.CriticalityReject, ies), nil
}

// BuildWarningResponseWithDiagnostics adds Criticality Diagnostics to a
// class-1 response. It is used when the correlation IEs were decoded but one
// or more other IEs made the request invalid.
func BuildWarningResponseWithDiagnostics(procedure uint8, messageID, serial [2]byte, cause uint8, d CriticalityDiagnostics) ([]byte, error) {
	encoded, err := EncodeCriticalityDiagnostics(d)
	if err != nil {
		return nil, err
	}
	return BuildWarningResponse(procedure, messageID, serial, cause, []ProtocolIE{{ID: IECriticalityDiagnostics, Criticality: aper.CriticalityIgnore, Value: encoded}})
}

// BuildWarningIndication reports completion/cancellation collection without
// retaining warning lifecycle state in the MME.
func BuildWarningIndication(procedure uint8, messageID, serial [2]byte, areaList []byte) ([]byte, error) {
	return BuildWarningIndicationWithEmptyAreaList(procedure, messageID, serial, areaList, nil)
}

// BuildWarningIndicationWithEmptyAreaList additionally carries the optional
// TS 29.168 Broadcast-Empty-Area-List on a Stop Warning Indication.  The list
// identifies eNBs that accepted the Kill but returned no cancelled cells.
func BuildWarningIndicationWithEmptyAreaList(procedure uint8, messageID, serial [2]byte, areaList, emptyAreaList []byte) ([]byte, error) {
	if procedure != ProcedureWriteReplaceWarning && procedure != ProcedureStopWarning {
		return nil, fmt.Errorf("sbcap: indication procedure %d", procedure)
	}
	if procedure != ProcedureStopWarning && len(emptyAreaList) != 0 {
		return nil, fmt.Errorf("sbcap: Broadcast Empty Area List is valid only for Stop Warning")
	}
	msg, err := encodeFixed16BitString(messageID)
	if err != nil {
		return nil, err
	}
	ser, err := encodeFixed16BitString(serial)
	if err != nil {
		return nil, err
	}
	indication := ProcedureWriteReplaceWarningIndication
	areaID := IEBroadcastScheduledAreaList
	if procedure == ProcedureStopWarning {
		indication, areaID = ProcedureStopWarningIndication, IEBroadcastCancelledAreaList
	}
	ies := []ProtocolIE{{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: msg}, {ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: ser}}
	if len(areaList) != 0 {
		ies = append(ies, ProtocolIE{ID: areaID, Criticality: aper.CriticalityReject, Value: areaList})
	}
	if len(emptyAreaList) != 0 {
		ies = append(ies, ProtocolIE{ID: IEBroadcastEmptyAreaList, Criticality: aper.CriticalityIgnore, Value: emptyAreaList})
	}
	return BuildInitiatingMessage(indication, aper.CriticalityIgnore, ies), nil
}

// BuildErrorIndication builds the TS 29.168 Error Indication PDU. Cause uses
// the SBc-AP Cause enumeration (for example 5=unrecognised-message,
// 6=missing-mandatory-element, 13=transfer-syntax-error, 14=semantic-error).
func BuildErrorIndication(cause uint8) ([]byte, error) {
	return BuildErrorIndicationWithDiagnostics(cause, nil)
}

// BuildErrorIndicationWithDiagnostics builds Error Indication with the
// optional root Criticality-Diagnostics IE when sufficient context exists.
func BuildErrorIndicationWithDiagnostics(cause uint8, d *CriticalityDiagnostics) ([]byte, error) {
	causeValue, err := encodeInteger(int64(cause), 0, 255)
	if err != nil {
		return nil, err
	}
	ies := []ProtocolIE{{ID: IECause, Criticality: aper.CriticalityIgnore, Value: causeValue}}
	if d != nil {
		encoded, err := EncodeCriticalityDiagnostics(*d)
		if err != nil {
			return nil, err
		}
		ies = append(ies, ProtocolIE{ID: IECriticalityDiagnostics, Criticality: aper.CriticalityIgnore, Value: encoded})
	}
	return BuildInitiatingMessage(ProcedureErrorIndication, aper.CriticalityIgnore, ies), nil
}

// BuildPWSNetworkIndication translates typed LTE S1AP indication values into
// SBc-AP.  Although the LTE ASN.1 definitions are structurally equivalent,
// this deliberately decodes and re-encodes every nested value: an S1AP
// open-type must never become an unvalidated CBC payload.
func BuildPWSNetworkIndication(procedure uint8, s1IEs map[uint16][]byte) ([]byte, error) {
	var target uint8
	var values map[uint16][]byte
	switch procedure {
	case 49:
		info, err := DecodeRestartInfo(s1IEs)
		if err != nil {
			return nil, fmt.Errorf("sbcap: PWS Restart Indication: %w", err)
		}
		encoded, err := EncodeRestartInfo(info)
		if err != nil {
			return nil, err
		}
		target, values = ProcedurePWSRestartIndication, encoded
	case 51:
		info, err := DecodeFailureInfo(s1IEs)
		if err != nil {
			return nil, fmt.Errorf("sbcap: PWS Failure Indication: %w", err)
		}
		encoded, err := EncodeFailureInfo(info)
		if err != nil {
			return nil, err
		}
		target, values = ProcedurePWSFailureIndication, encoded
	default:
		return nil, fmt.Errorf("sbcap: unsupported S1AP PWS indication %d", procedure)
	}
	ies := make([]ProtocolIE, 0, len(values))
	for id, value := range values {
		ies = append(ies, ProtocolIE{ID: id, Criticality: aper.CriticalityReject, Value: value})
	}
	return BuildInitiatingMessage(target, aper.CriticalityIgnore, ies), nil
}

func encodeFixed16BitString(v [2]byte) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := aper.EncodeBitString(w, aper.BitString{Bytes: v[:], NumBits: 16}, 16, 16); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func encodeInteger(v, min, max int64) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := aper.EncodeConstrainedWholeNumber(w, v, min, max); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
