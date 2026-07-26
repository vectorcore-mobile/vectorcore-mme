package s1ap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/sbcap"
)

const (
	ericssonWriteReplaceResponseFixture = "2024001e000003006f0002111c0070000270000078400b0000000013415300c80010"
	invalidSBcAPScheduledAreaFixture    = "0003401e00000300050002111c000b000270000017000b0000000013415300c80010"
	osmoCBCInvalidIndicationFixture     = "000240080000010001400105"
)

func TestPWSConcurrentWarningIsTypedAndReencoded(t *testing.T) {
	message, err := encodePWSIdentity([2]byte{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	serial, err := encodePWSIdentity([2]byte{3, 4})
	if err != nil {
		t.Fatal(err)
	}
	repetition := encodePWSInteger(1, 0, 4096)
	broadcasts := encodePWSInteger(1, 0, 65535)
	concurrent := []byte{0} // zero value bits carried as open-type padding.
	raw := sbcap.BuildInitiatingMessage(sbcap.ProcedureWriteReplaceWarning, aper.CriticalityReject, []sbcap.ProtocolIE{
		{ID: sbcap.IEMessageIdentifier, Criticality: aper.CriticalityReject, Value: message},
		{ID: sbcap.IESerialNumber, Criticality: aper.CriticalityReject, Value: serial},
		{ID: sbcap.IERepetitionPeriod, Criticality: aper.CriticalityReject, Value: repetition},
		{ID: sbcap.IENumberOfBroadcastsRequested, Criticality: aper.CriticalityReject, Value: broadcasts},
		{ID: sbcap.IEConcurrentWarningMessageIndicator, Criticality: aper.CriticalityReject, Value: concurrent},
	})
	p, err := sbcap.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, err := sbcap.DecodeWriteReplaceWarningRequest(p)
	if err != nil || !req.ConcurrentWarning {
		t.Fatalf("decode: %#v %v", req, err)
	}
	encoded, err := (&Server{}).buildPWSRequest(sbcap.ProcedureWriteReplaceWarning, req)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := pdu.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	ies, err := pdu.DecodeIEContainer(s1.Value)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ie := range ies {
		if ie.ID == ieConcurrentWarningIndicator {
			found = true
			if len(ie.Value) != 1 || ie.Value[0] != 0 {
				t.Fatalf("concurrent indicator wire form = %x", ie.Value)
			}
		}
	}
	if !found {
		t.Fatal("S1AP concurrent indicator missing")
	}
}

func TestWriteReplaceCapturedConcurrentIndicatorRegression(t *testing.T) {
	// Frame from vcmme.sbc-ap-test3.pcap before the fix: the final IE was
	// 008e0000 (zero-length open type). The corrected PDU must end 008e000100.
	malformed, err := hex.DecodeString("0024007e000007006f0002111c007200020005007600010f00770056005301d6f298fe960fdff232885a9c52414166514a75819c6f50784c4fbfdd2079395e4fcbcb6457a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d168341a8d46a3d1682500700002700000730002000a008e0000")
	if err != nil {
		t.Fatal(err)
	}
	p, err := pdu.Decode(malformed)
	if err != nil {
		t.Fatal(err)
	}
	ies, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, ie := range ies {
		if ie.ID == ieConcurrentWarningIndicator {
			if _, err := decodeConcurrentWarningS1AP(ie.Value); err == nil {
				t.Fatal("zero-length concurrent indicator accepted")
			}
		}
	}
	if _, err := decodeConcurrentWarningS1AP([]byte{1}); err == nil {
		t.Fatal("non-zero padding accepted")
	}
	if ok, err := decodeConcurrentWarningS1AP([]byte{0}); err != nil || !ok {
		t.Fatalf("valid padding: %v %v", ok, err)
	}
	// Build a minimal typed request and assert the complete ProtocolIE trailer.
	req := &sbcap.WarningRequest{IEs: map[uint16][]byte{sbcap.IEMessageIdentifier: mustPWSIdentity(t, [2]byte{0x11, 0x1c}), sbcap.IESerialNumber: mustPWSIdentity(t, [2]byte{0x70, 0}), sbcap.IERepetitionPeriod: encodePWSInteger(5, 0, 4096), sbcap.IENumberOfBroadcastsRequested: encodePWSInteger(10, 0, 65535)}, ConcurrentWarning: true}
	wire, err := (&Server{}).buildPWSRequest(sbcap.ProcedureWriteReplaceWarning, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire); got[len(got)-10:] != "008e000100" {
		t.Fatalf("S1AP IE 142 trailer = %s", got[len(got)-10:])
	}
}

func TestEricssonWriteReplaceResponseCompletedAreaFixture(t *testing.T) {
	wire, err := hex.DecodeString(ericssonWriteReplaceResponseFixture)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pdu.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != pdu.PDUTypeSuccessfulOutcome || p.ProcedureCode != pdu.ProcWriteReplaceWarning {
		t.Fatalf("PDU=%+v", p)
	}
	ies, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	var area []byte
	for _, ie := range ies {
		if ie.ID == 120 {
			area = ie.Value
		}
	}
	if len(area) == 0 {
		t.Fatal("IE 120 missing")
	}
	decoded, err := sbcap.DecodeS1CompletedAreaList(area)
	if err != nil {
		t.Fatalf("IE 120 decode: %v (%x)", err, area)
	}
	if len(decoded.Cells) != 1 || decoded.Cells[0].ECGI.PLMN != [3]byte{0x13, 0x41, 0x53} || decoded.Cells[0].ECGI.Cell != 0x000c8001 {
		t.Fatalf("area=%+v", decoded)
	}
}

func TestEricssonCompletedAreaMapsChoiceToSBcAPScheduledSequence(t *testing.T) {
	response, err := hex.DecodeString(ericssonWriteReplaceResponseFixture)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pdu.Decode(response)
	if err != nil {
		t.Fatal(err)
	}
	ies, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	var s1Area []byte
	for _, ie := range ies {
		if ie.ID == 120 {
			s1Area = ie.Value
			break
		}
	}
	if got, want := hex.EncodeToString(s1Area), "0000000013415300c80010"; got != want {
		t.Fatalf("S1AP IE 120 = %s, want %s", got, want)
	}
	model, err := sbcap.DecodeS1CompletedAreaList(s1Area)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Cells) != 1 || model.Cells[0].ECGI.PLMN != [3]byte{0x13, 0x41, 0x53} || model.Cells[0].ECGI.Cell != 0x000c8001 {
		t.Fatalf("S1AP model = %+v", model)
	}
	sbcArea, err := sbcap.EncodeCompletedAreaList(model)
	if err != nil {
		t.Fatal(err)
	}
	// TS 29.168's SEQUENCE extension/presence bitmap is 01000b: the cell
	// list is present and the TAI, EAI and extension fields are absent.  APER
	// pads it to 0x40 before the constrained list size.
	if got, want := hex.EncodeToString(sbcArea), "4000000013415300c80010"; got != want {
		t.Fatalf("SBc-AP Scheduled Area List = %s, want %s", got, want)
	}
	if bytes.Equal(sbcArea, s1Area) {
		t.Fatalf("S1AP CHOICE was reused as SBc-AP SEQUENCE: %x", sbcArea)
	}
	decoded, err := sbcap.DecodeCompletedAreaList(sbcArea)
	if err != nil {
		t.Fatalf("SBc-AP scheduled-area decode: %v (%x)", err, sbcArea)
	}
	if len(decoded.Cells) != 1 || decoded.Cells[0].ECGI != model.Cells[0].ECGI {
		t.Fatalf("SBc-AP model = %+v", decoded)
	}
	indication, err := sbcap.BuildWarningIndication(sbcap.ProcedureWriteReplaceWarning, [2]byte{0x11, 0x1c}, [2]byte{0x70, 0}, sbcArea)
	if err != nil {
		t.Fatal(err)
	}
	ind, err := sbcap.Decode(indication)
	if err != nil {
		t.Fatalf("complete SBc-AP indication: %v", err)
	}
	indIEs, err := sbcap.DecodeIEContainer(ind.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, ie := range indIEs {
		if ie.ID == sbcap.IEBroadcastScheduledAreaList {
			if _, err := sbcap.DecodeCompletedAreaList(ie.Value); err != nil {
				t.Fatalf("indication IE 23: %v", err)
			}
			return
		}
	}
	t.Fatal("SBc-AP indication omitted IE 23")
}

func TestCapturedInvalidChoiceInSBcAPScheduledAreaIsRejected(t *testing.T) {
	// This was emitted by the MME before the protocol-specific wrapper fix:
	// IE 23 carries the byte-identical S1AP BroadcastCompletedAreaList CHOICE.
	invalid, err := hex.DecodeString(invalidSBcAPScheduledAreaFixture)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sbcap.Decode(invalid)
	if err != nil {
		t.Fatal(err)
	}
	ies, err := sbcap.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, ie := range ies {
		if ie.ID == sbcap.IEBroadcastScheduledAreaList {
			if _, err := sbcap.DecodeCompletedAreaList(ie.Value); err == nil {
				t.Fatalf("accepted S1AP CHOICE as SBc-AP SEQUENCE: %x", ie.Value)
			}
			break
		}
	}
	// Preserve the peer's standards-consistent rejection as a regression
	// fixture too.  It must remain a syntactically valid SBc-AP Error Indication.
	errPDU, err := sbcap.Decode(mustDecodeHex(t, osmoCBCInvalidIndicationFixture))
	if err != nil {
		t.Fatalf("OsmoCBC Error Indication fixture: %v", err)
	}
	if errPDU.ProcedureCode != sbcap.ProcedureErrorIndication {
		t.Fatalf("OsmoCBC procedure = %d", errPDU.ProcedureCode)
	}
}

func TestPWSResponseCompletesAndDeduplicatesEricssonRetransmission(t *testing.T) {
	wire, _ := hex.DecodeString(ericssonWriteReplaceResponseFixture)
	p, err := pdu.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	ies, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	var indications [][]byte
	s := &Server{pwsTransactionBases: make(map[string]struct{}), pwsIndication: func(_ string, b []byte) { indications = append(indications, append([]byte(nil), b...)) }}
	tx := &pwsTransaction{baseKey: pwsResponseKey(sbcap.ProcedureWriteReplaceWarning, [2]byte{0x11, 0x1c}, [2]byte{0x70, 0}), peer: "cbc-a", procedure: sbcap.ProcedureWriteReplaceWarning, messageID: [2]byte{0x11, 0x1c}, serial: [2]byte{0x70, 0}, pending: map[string]struct{}{"192.168.105.247:36422": {}}}
	s.pwsTransactionBases[tx.baseKey] = struct{}{}
	s.pwsTransactions.Store(tx.baseKey, tx)
	s.handlePWSResponse("192.168.105.247:36422", pdu.ProcWriteReplaceWarning, ies)
	if len(indications) != 1 {
		t.Fatalf("indications=%d", len(indications))
	}
	ind, err := sbcap.Decode(indications[0])
	if err != nil {
		t.Fatal(err)
	}
	indIEs, err := sbcap.DecodeIEContainer(ind.Value)
	if err != nil {
		t.Fatal(err)
	}
	var area []byte
	for _, ie := range indIEs {
		if ie.ID == sbcap.IEBroadcastScheduledAreaList {
			area = ie.Value
		}
	}
	if len(area) == 0 {
		t.Fatal("completed area omitted")
	}
	decoded, err := sbcap.DecodeCompletedAreaList(area)
	if err != nil || len(decoded.Cells) != 1 {
		t.Fatalf("SBcAP area=%+v err=%v", decoded, err)
	}
	// SCTP retransmission of the same successful outcome must be a no-op.
	s.handlePWSResponse("192.168.105.247:36422", pdu.ProcWriteReplaceWarning, ies)
	if len(indications) != 1 {
		t.Fatalf("duplicate created %d indications", len(indications))
	}
}

func TestPWSResponseAggregatesMultipleENBAreas(t *testing.T) {
	messageID, serial := [2]byte{0x11, 0x1c}, [2]byte{0x70, 0}
	firstRemote, secondRemote := "192.0.2.1:36422", "192.0.2.2:36422"
	var indications [][]byte
	s := &Server{pwsTransactionBases: make(map[string]struct{}), pwsIndication: func(_ string, b []byte) { indications = append(indications, append([]byte(nil), b...)) }}
	tx := &pwsTransaction{baseKey: pwsResponseKey(sbcap.ProcedureWriteReplaceWarning, messageID, serial), peer: "cbc-a", procedure: sbcap.ProcedureWriteReplaceWarning, messageID: messageID, serial: serial, pending: map[string]struct{}{firstRemote: {}, secondRemote: {}}}
	s.pwsTransactionBases[tx.baseKey] = struct{}{}
	s.pwsTransactions.Store(tx.baseKey, tx)
	response := func(cell uint32) []pdu.ProtocolIE {
		area, err := sbcap.EncodeS1CompletedAreaList(sbcap.AreaList{Kind: sbcap.AreaCells, Cells: []sbcap.AreaCell{{ECGI: sbcap.EUTRANCGI{PLMN: [3]byte{0, 0xf1, 0x10}, Cell: cell}}}})
		if err != nil {
			t.Fatal(err)
		}
		return []pdu.ProtocolIE{{ID: ieMessageIdentifier, Value: mustPWSIdentity(t, messageID)}, {ID: ieSerialNumber, Value: mustPWSIdentity(t, serial)}, {ID: 120, Value: area}}
	}
	s.handlePWSResponse(firstRemote, pdu.ProcWriteReplaceWarning, response(1))
	if len(indications) != 0 {
		t.Fatal("transaction completed before every selected eNB replied")
	}
	s.handlePWSResponse(secondRemote, pdu.ProcWriteReplaceWarning, response(2))
	if len(indications) != 1 {
		t.Fatalf("indications=%d", len(indications))
	}
	p, err := sbcap.Decode(indications[0])
	if err != nil {
		t.Fatal(err)
	}
	container, err := sbcap.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, ie := range container {
		if ie.ID == sbcap.IEBroadcastScheduledAreaList {
			area, err := sbcap.DecodeCompletedAreaList(ie.Value)
			if err != nil || len(area.Cells) != 2 {
				t.Fatalf("aggregated area=%+v err=%v", area, err)
			}
			return
		}
	}
	t.Fatal("aggregated indication omitted area list")
}

func TestKillResponseAreaAndEmptyAreaMapping(t *testing.T) {
	remote := "192.0.2.10:36422"
	global := ies.GlobalENBID{MCC: "001", MNC: "01", ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x12345}}
	messageID, serial := [2]byte{0x11, 0x1c}, [2]byte{0x70, 0}
	newServer := func() (*Server, *pwsTransaction, *[][]byte) {
		indications := make([][]byte, 0, 1)
		s := &Server{pwsTransactionBases: make(map[string]struct{}), pwsIndication: func(_ string, b []byte) { indications = append(indications, append([]byte(nil), b...)) }}
		s.enbs.Store(remote, &ENBContext{RemoteAddr: remote, GlobalENBID: global, SetupComplete: true})
		tx := &pwsTransaction{baseKey: pwsResponseKey(sbcap.ProcedureStopWarning, messageID, serial), peer: "cbc-a", procedure: sbcap.ProcedureStopWarning, messageID: messageID, serial: serial, pending: map[string]struct{}{remote: {}}}
		s.pwsTransactionBases[tx.baseKey] = struct{}{}
		s.pwsTransactions.Store(tx.baseKey, tx)
		return s, tx, &indications
	}

	t.Run("cancelled-area", func(t *testing.T) {
		s, _, indications := newServer()
		broadcasts := uint16(3)
		s1Area, err := sbcap.EncodeS1CancelledAreaList(sbcap.AreaList{Kind: sbcap.AreaCells, Cells: []sbcap.AreaCell{{ECGI: sbcap.EUTRANCGI{PLMN: [3]byte{0, 0xf1, 0x10}, Cell: 4}, Broadcasts: &broadcasts}}})
		if err != nil {
			t.Fatal(err)
		}
		s.handlePWSResponse(remote, pdu.ProcKill, []pdu.ProtocolIE{{ID: ieMessageIdentifier, Value: mustPWSIdentity(t, messageID)}, {ID: ieSerialNumber, Value: mustPWSIdentity(t, serial)}, {ID: 141, Value: s1Area}})
		if len(*indications) != 1 {
			t.Fatalf("indications=%d", len(*indications))
		}
		assertStopIndicationArea(t, (*indications)[0], true, false)
	})

	t.Run("empty-area", func(t *testing.T) {
		s, _, indications := newServer()
		s.handlePWSResponse(remote, pdu.ProcKill, []pdu.ProtocolIE{{ID: ieMessageIdentifier, Value: mustPWSIdentity(t, messageID)}, {ID: ieSerialNumber, Value: mustPWSIdentity(t, serial)}})
		if len(*indications) != 1 {
			t.Fatalf("indications=%d", len(*indications))
		}
		assertStopIndicationArea(t, (*indications)[0], false, true)
	})
}

func assertStopIndicationArea(t *testing.T, wire []byte, wantCancelled, wantEmpty bool) {
	t.Helper()
	p, err := sbcap.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	container, err := sbcap.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	var cancelled, empty bool
	for _, ie := range container {
		switch ie.ID {
		case sbcap.IEBroadcastCancelledAreaList:
			cancelled = true
			area, err := sbcap.DecodeCancelledAreaList(ie.Value)
			if err != nil || len(area.Cells) != 1 || area.Cells[0].Broadcasts == nil || *area.Cells[0].Broadcasts != 3 {
				t.Fatalf("cancelled area=%+v err=%v", area, err)
			}
		case sbcap.IEBroadcastEmptyAreaList:
			empty = true
			ids, err := sbcap.DecodeBroadcastEmptyAreaList(ie.Value)
			if err != nil || len(ids) != 1 {
				t.Fatalf("empty area=%x ids=%x err=%v", ie.Value, ids, err)
			}
		}
	}
	if cancelled != wantCancelled || empty != wantEmpty {
		t.Fatalf("cancelled=%v empty=%v, want %v/%v", cancelled, empty, wantCancelled, wantEmpty)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPWSIdentity(t *testing.T, v [2]byte) []byte {
	t.Helper()
	b, err := encodePWSIdentity(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodePWSIdentity(v [2]byte) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := aper.EncodeBitString(w, aper.BitString{Bytes: v[:], NumBits: 16}, 16, 16); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func encodePWSInteger(v, min, max int64) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, v, min, max)
	return w.Bytes()
}
