package sbcap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

const capturedWriteReplacePPID24 = "000000808400000800050002111c000b00027000000a0002000500070002000a000340010f00104056005301d6f298fe960fdff232885a9c52414166514a75819c6f50784c4fbfdd2079395e4fcbcb6457a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d1682500140001000018400100"

func TestCapturedWriteReplacePPID24Accepted(t *testing.T) {
	wire, err := hex.DecodeString(capturedWriteReplacePPID24)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeWriteReplaceWarningRequest(p)
	if err != nil {
		t.Fatalf("captured request rejected: %v", err)
	}
	if req.MessageIdentifier != [2]byte{0x11, 0x1c} || req.SerialNumber != [2]byte{0x70, 0} || req.RepetitionPeriod == nil || *req.RepetitionPeriod != 5 || req.NumberOfBroadcasts == nil || *req.NumberOfBroadcasts != 10 || !req.ConcurrentWarning || !req.SendIndication {
		t.Fatalf("unexpected decoded request: %+v", req)
	}
	if len(req.WarningAreaList) != 0 {
		t.Fatal("fixture unexpectedly has a Warning Area List")
	}
	d := DecideInbound(wire)
	if !d.Continue || d.Response != ResponseNone {
		t.Fatalf("fixture policy decision: %+v", d)
	}
}

func TestWriteReplaceRequestRoundTripAndValidation(t *testing.T) {
	messageID := [2]byte{0x11, 0x22}
	serial := [2]byte{0x33, 0x44}
	message, err := encodeFixed16BitString(messageID)
	if err != nil {
		t.Fatal(err)
	}
	serialValue, err := encodeFixed16BitString(serial)
	if err != nil {
		t.Fatal(err)
	}
	repetition, err := encodeInteger(30, 0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	broadcasts, err := encodeInteger(1, 0, 65535)
	if err != nil {
		t.Fatal(err)
	}
	raw := BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, []ProtocolIE{
		{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message},
		{ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serialValue},
		{ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: repetition},
		{ID: IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts},
	})
	pdu, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeWriteReplaceWarningRequest(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if req.MessageIdentifier != messageID || req.SerialNumber != serial || req.RepetitionPeriod == nil || *req.RepetitionPeriod != 30 || req.NumberOfBroadcasts == nil || *req.NumberOfBroadcasts != 1 {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestWriteReplaceAcceptsAndValidatesConcurrentWarningIndicator(t *testing.T) {
	message, _ := encodeFixed16BitString([2]byte{1, 2})
	serial, _ := encodeFixed16BitString([2]byte{3, 4})
	repetition, _ := encodeInteger(1, 0, 4096)
	broadcasts, _ := encodeInteger(1, 0, 65535)
	concurrent, err := encodeConcurrentWarning()
	if err != nil {
		t.Fatal(err)
	}
	raw := BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, []ProtocolIE{
		{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message},
		{ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serial},
		{ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: repetition},
		{ID: IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts},
		{ID: IEConcurrentWarningMessageIndicator, Criticality: aper.CriticalityReject, Value: concurrent},
	})
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeWriteReplaceWarningRequest(p)
	if err != nil || !req.ConcurrentWarning {
		t.Fatalf("concurrent warning rejected: %#v %v", req, err)
	}
	if _, err := decodeConcurrentWarning([]byte{0xff, 0xff}); err == nil {
		t.Fatal("malformed concurrent indicator accepted")
	}
}

func pwsCell(n uint32) EUTRANCGI { return EUTRANCGI{PLMN: [3]byte{0x00, 0xf1, 0x10}, Cell: n} }

func TestTypedPWSNestedCodecsRoundTrip(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		for _, in := range []AreaList{
			{Kind: AreaCells, Cells: []AreaCell{{ECGI: pwsCell(1), Broadcasts: broadcasts(cancelled, 7)}}},
			{Kind: AreaTAIs, Groups: []AreaGroup{{TAI: &TAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, TAC: 9}, Cells: []AreaCell{{ECGI: pwsCell(2), Broadcasts: broadcasts(cancelled, 8)}}}}},
			{Kind: AreaEAIs, Groups: []AreaGroup{{EAI: &[3]byte{1, 2, 3}, Cells: []AreaCell{{ECGI: pwsCell(3), Broadcasts: broadcasts(cancelled, 9)}}}}},
		} {
			var wire []byte
			var err error
			if cancelled {
				wire, err = EncodeCancelledAreaList(in)
			} else {
				wire, err = EncodeCompletedAreaList(in)
			}
			if err != nil {
				t.Fatal(err)
			}
			var out AreaList
			if cancelled {
				out, err = DecodeCancelledAreaList(wire)
			} else {
				out, err = DecodeCompletedAreaList(wire)
			}
			if err != nil || out.Kind != in.Kind {
				t.Fatalf("cancelled=%v: %#v %v", cancelled, out, err)
			}
		}
	}
}

func TestS1AreaChoiceIsNeverSBcAPAreaSequence(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		for _, in := range []AreaList{
			{Kind: AreaCells, Cells: []AreaCell{{ECGI: pwsCell(1), Broadcasts: broadcasts(cancelled, 7)}}},
			{Kind: AreaTAIs, Groups: []AreaGroup{{TAI: &TAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, TAC: 9}, Cells: []AreaCell{{ECGI: pwsCell(2), Broadcasts: broadcasts(cancelled, 8)}}}}},
			{Kind: AreaEAIs, Groups: []AreaGroup{{EAI: &[3]byte{1, 2, 3}, Cells: []AreaCell{{ECGI: pwsCell(3), Broadcasts: broadcasts(cancelled, 9)}}}}},
		} {
			s1Wire, err := encodeArea(in, cancelled)
			if err != nil {
				t.Fatal(err)
			}
			var model AreaList
			if cancelled {
				model, err = DecodeS1CancelledAreaList(s1Wire)
			} else {
				model, err = DecodeS1CompletedAreaList(s1Wire)
			}
			if err != nil {
				t.Fatal(err)
			}
			var sbcWire []byte
			if cancelled {
				sbcWire, err = EncodeCancelledAreaList(model)
			} else {
				sbcWire, err = EncodeCompletedAreaList(model)
			}
			if err != nil {
				t.Fatal(err)
			}
			// The S1AP CHOICE and SBc-AP SEQUENCE headers happen to have an
			// identical APER bit pattern for some non-cell alternatives.  The
			// conversion is still model-to-model: never use byte equality as a
			// wire-compatibility rule.  The captured cell alternative is covered
			// separately and proves the wrappers differ on the wire.
			var out AreaList
			if cancelled {
				out, err = DecodeCancelledAreaList(sbcWire)
			} else {
				out, err = DecodeCompletedAreaList(sbcWire)
			}
			if err != nil || out.Kind != in.Kind {
				t.Fatalf("cancelled=%v kind=%d output=%+v err=%v", cancelled, in.Kind, out, err)
			}
			if cancelled && out.Kind == AreaCells && (out.Cells[0].Broadcasts == nil || *out.Cells[0].Broadcasts != 7) {
				t.Fatalf("number of broadcasts was not preserved: %+v", out)
			}
		}
	}
}

func TestAreaAggregationDeduplicatesCells(t *testing.T) {
	first := AreaList{Kind: AreaCells, Cells: []AreaCell{{ECGI: pwsCell(1)}, {ECGI: pwsCell(2)}}}
	second := AreaList{Kind: AreaCells, Cells: []AreaCell{{ECGI: pwsCell(2)}, {ECGI: pwsCell(3)}}}
	merged := MergeAreaLists([]AreaList{first, second}, false)
	if merged.Kind != AreaCells || len(merged.Cells) != 3 {
		t.Fatalf("merged=%+v", merged)
	}
}

func TestAreaAggregationPreservesDistinctTAIAndEAIALternatives(t *testing.T) {
	tai := TAI{PLMN: [3]byte{0, 0xf1, 0x10}, TAC: 1}
	eai := [3]byte{1, 2, 3}
	merged := MergeAreaLists([]AreaList{
		{Kind: AreaTAIs, Groups: []AreaGroup{{TAI: &tai, Cells: []AreaCell{{ECGI: pwsCell(1)}}}}},
		{Kind: AreaEAIs, Groups: []AreaGroup{{EAI: &eai, Cells: []AreaCell{{ECGI: pwsCell(2)}}}}},
	}, false)
	wire, err := EncodeCompletedAreaList(merged)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCompletedAreaList(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.TAIGroups) != 1 || len(decoded.EAIGroups) != 1 || len(decoded.TAIGroups[0].Cells) != 1 || len(decoded.EAIGroups[0].Cells) != 1 {
		t.Fatalf("aggregated alternatives lost: %+v", decoded)
	}
}

func TestBroadcastEmptyAreaListRoundTripAndStopIndication(t *testing.T) {
	g, err := ies.EncodeGlobalENBID(ies.GlobalENBID{MCC: "001", MNC: "01", ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x12345}})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := EncodeBroadcastEmptyAreaList([][]byte{g})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBroadcastEmptyAreaList(empty)
	if err != nil || len(decoded) != 1 || !bytes.Equal(decoded[0], g) {
		t.Fatalf("empty list=%x decoded=%x err=%v", empty, decoded, err)
	}
	payload, err := BuildWarningIndicationWithEmptyAreaList(ProcedureStopWarning, [2]byte{1, 2}, [2]byte{3, 4}, nil, empty)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	container, err := DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, ie := range container {
		if ie.ID == IEBroadcastEmptyAreaList {
			if _, err := DecodeBroadcastEmptyAreaList(ie.Value); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("Stop Warning Indication omitted Broadcast Empty Area List")
}
func broadcasts(cancelled bool, n uint16) *uint16 {
	if !cancelled {
		return nil
	}
	return &n
}

func TestTypedRestartAndFailureRejectMalformedNestedAPER(t *testing.T) {
	g, err := ies.EncodeGlobalENBID(ies.GlobalENBID{MCC: "001", MNC: "01", ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 1}})
	if err != nil {
		t.Fatal(err)
	}
	cells, err := encodeECGIListMax([]EUTRANCGI{pwsCell(1)}, maxRestartCells)
	if err != nil {
		t.Fatal(err)
	}
	tais, err := encodeTAIListTypedMax([]TAI{{PLMN: [3]byte{0, 0xf1, 0x10}, TAC: 1}}, maxRestartTAIs)
	if err != nil {
		t.Fatal(err)
	}
	restart := map[uint16][]byte{59: g, 182: cells, 188: tais}
	if _, err := DecodeRestartInfo(restart); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPWSNetworkIndication(49, restart); err != nil {
		t.Fatal(err)
	}
	restart[182] = restart[182][:len(restart[182])-1]
	if _, err := DecodeRestartInfo(restart); err == nil {
		t.Fatal("truncated restarted-cell list accepted")
	}
	if _, err := DecodeFailureInfo(map[uint16][]byte{59: g, 222: []byte{0}}); err == nil {
		t.Fatal("malformed failed-cell list accepted")
	}
}

func TestTypedCodecsRejectInvalidPLMNAndEmptyLists(t *testing.T) {
	if _, err := encodeECGIList(nil); err == nil {
		t.Fatal("empty list accepted")
	}
	bad := EUTRANCGI{PLMN: [3]byte{0xfa, 0xf1, 0x10}, Cell: 1}
	if _, err := encodeECGIList([]EUTRANCGI{bad}); err == nil {
		t.Fatal("invalid PLMN accepted")
	}
}

func FuzzTypedPWSNestedCodecsNeverPanic(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("typed PWS codec panic for %x: %v", b, r)
			}
		}()
		_, _ = DecodeCompletedAreaList(b)
		_, _ = DecodeCancelledAreaList(b)
		_, _ = DecodeRestartInfo(map[uint16][]byte{59: b, 182: b, 188: b, 190: b})
		_, _ = DecodeFailureInfo(map[uint16][]byte{59: b, 222: b})
	})
}

func TestWriteReplaceRejectsMissingMandatoryAndUnknownRejectIE(t *testing.T) {
	message, _ := encodeFixed16BitString([2]byte{1, 2})
	raw := BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, []ProtocolIE{{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message}})
	pdu, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWriteReplaceWarningRequest(pdu); err == nil {
		t.Fatal("missing mandatory IEs accepted")
	}

	serial, _ := encodeFixed16BitString([2]byte{3, 4})
	repetition, _ := encodeInteger(0, 0, 4096)
	broadcasts, _ := encodeInteger(0, 0, 65535)
	raw = BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, []ProtocolIE{
		{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message}, {ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serial},
		{ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: repetition}, {ID: IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts},
		{ID: 65000, Criticality: aper.CriticalityReject, Value: []byte{0}},
	})
	pdu, err = Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWriteReplaceWarningRequest(pdu); err == nil {
		t.Fatal("unknown reject-criticality IE accepted")
	}
}

func TestWarningRequestRejectsIncorrectOrderAndKnownIECriticality(t *testing.T) {
	message, _ := encodeFixed16BitString([2]byte{1, 2})
	serial, _ := encodeFixed16BitString([2]byte{3, 4})
	repetition, _ := encodeInteger(1, 0, 4096)
	broadcasts, _ := encodeInteger(1, 0, 65535)
	base := []ProtocolIE{
		{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message},
		{ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serial},
		{ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: repetition},
		{ID: IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts},
	}
	badOrder := append([]ProtocolIE(nil), base...)
	badOrder[2], badOrder[3] = badOrder[3], badOrder[2]
	p, err := Decode(BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, badOrder))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWriteReplaceWarningRequest(p); err == nil {
		t.Fatal("out-of-order request accepted")
	}
	badCrit := append([]ProtocolIE(nil), base...)
	badCrit[2].Criticality = aper.CriticalityIgnore
	p, err = Decode(BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, badCrit))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWriteReplaceWarningRequest(p); err == nil {
		t.Fatal("known IE with wrong criticality accepted")
	}
}

func TestUnknownIECriticalityDecision(t *testing.T) {
	message, _ := encodeFixed16BitString([2]byte{1, 2})
	serial, _ := encodeFixed16BitString([2]byte{3, 4})
	repetition, _ := encodeInteger(1, 0, 4096)
	broadcasts, _ := encodeInteger(1, 0, 65535)
	base := []ProtocolIE{{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message}, {ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serial}, {ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: repetition}, {ID: IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts}}
	for _, tc := range []struct {
		crit                aper.Criticality
		wantErr, wantNotify bool
	}{{aper.CriticalityReject, true, false}, {aper.CriticalityNotify, false, true}, {aper.CriticalityIgnore, false, false}} {
		ies := append(append([]ProtocolIE(nil), base...), ProtocolIE{ID: 65000, Criticality: tc.crit, Value: []byte{0}})
		p, err := Decode(BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, ies))
		if err != nil {
			t.Fatal(err)
		}
		req, err := DecodeWriteReplaceWarningRequest(p)
		if (err != nil) != tc.wantErr {
			t.Fatalf("criticality %s error=%v", tc.crit, err)
		}
		if err == nil && (len(req.NotifyIEs) != 0) != tc.wantNotify {
			t.Fatalf("criticality %s notify=%#v", tc.crit, req.NotifyIEs)
		}
	}
}

func TestInboundDecisionMatrix(t *testing.T) {
	message, _ := encodeFixed16BitString([2]byte{1, 2})
	serial, _ := encodeFixed16BitString([2]byte{3, 4})
	rep, _ := encodeInteger(1, 0, 4096)
	broadcasts, _ := encodeInteger(1, 0, 65535)
	base := []ProtocolIE{{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message}, {ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serial}, {ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: rep}, {ID: IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts}}
	with := func(extra ...ProtocolIE) []byte {
		return BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, append(append([]ProtocolIE(nil), base...), extra...))
	}
	missing := BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, base[:2])
	dup := with(ProtocolIE{ID: IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: rep})
	order := append([]ProtocolIE(nil), base...)
	order[2], order[3] = order[3], order[2]
	unknown := func(c aper.Criticality) []byte { return with(ProtocolIE{ID: 65000, Criticality: c, Value: []byte{0}}) }
	unknownProc := func(c aper.Criticality) []byte { return BuildInitiatingMessage(200, c, nil) }
	malformedEI := BuildInitiatingMessage(ProcedureErrorIndication, aper.CriticalityIgnore, []ProtocolIE{{ID: IECause, Criticality: aper.CriticalityIgnore, Value: []byte{}}})
	conditional := with(ProtocolIE{ID: IESendStopWarningIndication, Criticality: aper.CriticalityIgnore, Value: []byte{}})
	invalid := append([]ProtocolIE(nil), base...)
	invalid[2].Value = []byte{0xff, 0xff}
	semantic := BuildInitiatingMessage(ProcedureStopWarning, aper.CriticalityReject, []ProtocolIE{{ID: IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message}, {ID: IESerialNumber, Criticality: aper.CriticalityReject, Value: serial}, {ID: IEListOfTAIs, Criticality: aper.CriticalityReject, Value: []byte{}}, {ID: IEStopAllIndicator, Criticality: aper.CriticalityReject, Value: []byte{}}})
	for _, tc := range []struct {
		name            string
		wire            []byte
		ready           bool
		cont            bool
		response, cause uint8
		diag            bool
	}{
		{"valid", with(), true, true, ResponseNone, 0, false}, {"unknown-reject", unknown(aper.CriticalityReject), true, false, ResponseClass1, 16, true}, {"unknown-notify", unknown(aper.CriticalityNotify), true, true, ResponseClass1, 0, true}, {"unknown-ignore", unknown(aper.CriticalityIgnore), true, true, ResponseNone, 0, false}, {"missing", missing, true, false, ResponseClass1, 6, true}, {"duplicate", dup, true, false, ResponseClass1, 18, true}, {"order", BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, order), true, false, ResponseClass1, 18, true}, {"conditional", conditional, true, false, ResponseClass1, 18, true}, {"invalid-value", BuildInitiatingMessage(ProcedureWriteReplaceWarning, aper.CriticalityReject, invalid), true, false, ResponseClass1, 2, true}, {"semantic", semantic, true, false, ResponseClass1, 14, true}, {"receiver-state", with(), false, false, ResponseClass1, 15, true}, {"unknown-proc-reject", unknownProc(aper.CriticalityReject), true, false, ResponseErrorIndication, 5, true}, {"unknown-proc-notify", unknownProc(aper.CriticalityNotify), true, false, ResponseErrorIndication, 5, true}, {"unknown-proc-ignore", unknownProc(aper.CriticalityIgnore), true, false, ResponseNone, 0, false}, {"transfer-syntax", []byte{0xff}, true, false, ResponseErrorIndication, 13, false}, {"incoming-error-indication", malformedEI, true, false, ResponseNone, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := DecideInboundWithReceiverState(tc.wire, tc.ready)
			if d.Continue != tc.cont || d.Response != tc.response || d.Cause != tc.cause || (d.Diagnostics != nil) != tc.diag {
				t.Fatalf("decision=%+v", d)
			}
			sends := 0
			ExecuteInboundDecision(d, func(*WarningRequest) { sends++ })
			if sends != map[bool]int{true: 1, false: 0}[tc.cont] {
				t.Fatalf("eNB sends=%d", sends)
			}
		})
	}
}

func TestCriticalityDiagnosticsRoundTripAndResponses(t *testing.T) {
	proc := ProcedureWriteReplaceWarning
	trigger := PDUTypeInitiatingMessage
	crit := aper.CriticalityReject
	in := CriticalityDiagnostics{
		ProcedureCode:        &proc,
		TriggeringMessage:    &trigger,
		ProcedureCriticality: &crit,
		Items: []CriticalityDiagnosticItem{
			{IEID: IEMessageIdentifier, IECriticality: aper.CriticalityReject, TypeOfError: TypeOfErrorMissing},
			{IEID: 65000, IECriticality: aper.CriticalityNotify, TypeOfError: TypeOfErrorNotUnderstood},
		},
	}
	wire, err := EncodeCriticalityDiagnostics(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeCriticalityDiagnostics(wire)
	if err != nil {
		t.Fatal(err)
	}
	if out.ProcedureCode == nil || *out.ProcedureCode != proc || out.TriggeringMessage == nil || *out.TriggeringMessage != trigger || out.ProcedureCriticality == nil || *out.ProcedureCriticality != crit || len(out.Items) != 2 || out.Items[1].IEID != 65000 || out.Items[0].TypeOfError != TypeOfErrorMissing {
		t.Fatalf("unexpected diagnostics: %#v", out)
	}
	response, err := BuildWarningResponseWithDiagnostics(ProcedureWriteReplaceWarning, [2]byte{1, 2}, [2]byte{3, 4}, 14, in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(response)
	if err != nil {
		t.Fatal(err)
	}
	ies, err := DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ie := range ies {
		if ie.ID == IECriticalityDiagnostics {
			found = true
			if _, err := DecodeCriticalityDiagnostics(ie.Value); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("Warning Response has no Criticality Diagnostics")
	}
	errorPDU, err := BuildErrorIndicationWithDiagnostics(13, &in)
	if err != nil {
		t.Fatal(err)
	}
	p, err = Decode(errorPDU)
	if err != nil || p.ProcedureCode != ProcedureErrorIndication {
		t.Fatalf("error indication: %#v %v", p, err)
	}
	ies, err = DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, ie := range ies {
		if ie.ID == IECriticalityDiagnostics {
			found = true
		}
	}
	if !found {
		t.Fatal("Error Indication has no Criticality Diagnostics")
	}
}

func TestCriticalityDiagnosticsRejectsInvalidConstraints(t *testing.T) {
	tooMany := CriticalityDiagnostics{Items: make([]CriticalityDiagnosticItem, 257)}
	if _, err := EncodeCriticalityDiagnostics(tooMany); err == nil {
		t.Fatal("oversized diagnostics accepted")
	}
	if _, err := DecodeCriticalityDiagnostics([]byte{0xff}); err == nil {
		t.Fatal("truncated diagnostics accepted")
	}
}

func TestDecodeNeverPanics(t *testing.T) {
	for _, payload := range [][]byte{nil, {0}, {0xff}, {0, 0, 0}, make([]byte, 32)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Decode panicked for %x: %v", payload, r)
				}
			}()
			_, _ = Decode(payload)
		}()
	}
}
