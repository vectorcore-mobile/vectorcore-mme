package s1ap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type normalizedERABSetupRequest struct {
	ProcedureCode uint8
	Criticality   aper.Criticality
	MMEUES1APID   uint32
	ENBUES1APID   uint32
	UEAMBR        []byte
	Items         []normalizedERABSetupItem
}

type normalizedERABSetupItem struct {
	SingleContainerIEID          uint16
	SingleContainerCriticality   aper.Criticality
	EBI                          uint8
	QCI                          uint8
	ARPPriority                  uint8
	PreemptionCapability         bool
	PreemptionVulnerability      bool
	TransportAddressBits         int
	SGWS1UIPv4                   string
	SGWS1UTEID                   uint32
	GBRQosInformationPresent     bool
	MaxBitrateDL                 uint64
	MaxBitrateUL                 uint64
	GuaranteedBitrateDL          uint64
	GuaranteedBitrateUL          uint64
	NASPDUPresent                bool
	NASPDU                       []byte
	RawFirstByte                 byte
	RawItemBody                  []byte
	DecodedWithoutTrailingOctets bool
}

func TestDecodePeerERABSetupRequestMultipleBearers(t *testing.T) {
	req := decodePeerERABSetupRequestFixture(t, "peer_erab_setup_request_multi.hex")
	if req.ProcedureCode != pdu.ProcERABSetup {
		t.Fatalf("procedure code got %d, want %d", req.ProcedureCode, pdu.ProcERABSetup)
	}
	if len(req.Items) != 3 {
		t.Fatalf("item count got %d, want 3", len(req.Items))
	}
	expected := []struct {
		ebi    uint8
		qci    uint8
		teid   uint32
		nasLen int
		gbr    bool
	}{
		{6, 5, 0xf187cfec, 118, false},
		{7, 2, 0x1571f5dd, 55, true},
		{8, 1, 0xa4745cb4, 55, true},
	}
	for i, want := range expected {
		got := req.Items[i]
		if got.SingleContainerIEID != pdu.IEERABToBeSetupItemBearerSUReq {
			t.Fatalf("item %d IE ID got %d, want %d", i, got.SingleContainerIEID, pdu.IEERABToBeSetupItemBearerSUReq)
		}
		if got.EBI != want.ebi || got.QCI != want.qci || got.SGWS1UTEID != want.teid {
			t.Fatalf("item %d got ebi=%d qci=%d teid=%#x, want ebi=%d qci=%d teid=%#x",
				i, got.EBI, got.QCI, got.SGWS1UTEID, want.ebi, want.qci, want.teid)
		}
		if got.SGWS1UIPv4 != "10.90.250.59" {
			t.Fatalf("item %d SGW IP got %s, want 10.90.250.59", i, got.SGWS1UIPv4)
		}
		if len(got.NASPDU) != want.nasLen {
			t.Fatalf("item %d NAS length got %d, want %d", i, len(got.NASPDU), want.nasLen)
		}
		if got.GBRQosInformationPresent != want.gbr {
			t.Fatalf("item %d GBR present got %v, want %v", i, got.GBRQosInformationPresent, want.gbr)
		}
		if want.gbr && (got.MaxBitrateDL != 128000 || got.MaxBitrateUL != 128000 || got.GuaranteedBitrateDL != 128000 || got.GuaranteedBitrateUL != 128000) {
			t.Fatalf("item %d GBR got DL/UL MBR=%d/%d GBR=%d/%d, want all 128000", i, got.MaxBitrateDL, got.MaxBitrateUL, got.GuaranteedBitrateDL, got.GuaranteedBitrateUL)
		}
	}
}

func TestBuildERABSetupRequestMatchesPeerDefaultBearerSemantics(t *testing.T) {
	peer := decodePeerERABSetupRequestFixture(t, "peer_erab_setup_request_multi.hex")
	item := peer.Items[0]
	builtRaw, _, err := BuildERABSetupRequest(peer.MMEUES1APID, peer.ENBUES1APID, nil, []ERABSetupItem{{
		EBI:                     item.EBI,
		QCI:                     item.QCI,
		ARPPriority:             item.ARPPriority,
		PreemptionCapability:    item.PreemptionCapability,
		PreemptionVulnerability: item.PreemptionVulnerability,
		SGWS1UIPv4:              net.ParseIP(item.SGWS1UIPv4),
		SGWS1UTEID:              item.SGWS1UTEID,
		NASPDU:                  append([]byte(nil), item.NASPDU...),
	}})
	if err != nil {
		t.Fatalf("BuildERABSetupRequest: %v", err)
	}
	built := decodeERABSetupRequest(t, builtRaw)
	if len(built.Items) != 1 {
		t.Fatalf("built item count got %d, want 1", len(built.Items))
	}
	if !sameBearerSemantics(built.Items[0], item) {
		t.Fatalf("built item semantics differ:\n got %+v\nwant %+v", built.Items[0], item)
	}
	if !bytes.Equal(built.Items[0].RawItemBody, item.RawItemBody) {
		t.Fatalf("built EBI 6 item body differs from reference fixture:\n got %x\nwant %x",
			built.Items[0].RawItemBody, item.RawItemBody)
	}
}

func TestBuildERABSetupRequestMatchesPeerDedicatedBearerSemantics(t *testing.T) {
	peer := decodePeerERABSetupRequestFixture(t, "peer_erab_setup_request_multi.hex")
	tests := []struct {
		idx               int
		qci               uint8
		rawARP            uint8
		arpPriority       uint8
		preemptCapability bool
		preemptVulnerable bool
	}{
		{idx: 1, qci: 2, rawARP: 16, arpPriority: 4, preemptCapability: true, preemptVulnerable: true},
		{idx: 2, qci: 1, rawARP: 8, arpPriority: 2, preemptCapability: true, preemptVulnerable: true},
	}
	for _, tt := range tests {
		item := peer.Items[tt.idx]
		builtRaw, _, err := BuildERABSetupRequest(peer.MMEUES1APID, peer.ENBUES1APID, nil, []ERABSetupItem{{
			EBI:                     item.EBI,
			QCI:                     item.QCI,
			ARPPriority:             tt.arpPriority,
			PreemptionCapability:    tt.preemptCapability,
			PreemptionVulnerability: tt.preemptVulnerable,
			BearerQoS:               encodeBearerQoSForTest(tt.qci, tt.rawARP, 128000, 128000, 128000, 128000),
			SGWS1UIPv4:              net.ParseIP(item.SGWS1UIPv4),
			SGWS1UTEID:              item.SGWS1UTEID,
			NASPDU:                  append([]byte(nil), item.NASPDU...),
		}})
		if err != nil {
			t.Fatalf("BuildERABSetupRequest item %d: %v", tt.idx, err)
		}
		built := decodeERABSetupRequest(t, builtRaw)
		if len(built.Items) != 1 {
			t.Fatalf("built item count got %d, want 1", len(built.Items))
		}
		if !sameBearerSemantics(built.Items[0], item) {
			t.Fatalf("built dedicated item %d semantics differ:\n got %+v\nwant %+v", tt.idx, built.Items[0], item)
		}
		if !bytes.Equal(built.Items[0].RawItemBody, item.RawItemBody) {
			t.Fatalf("built dedicated item %d body differs from reference fixture:\n got %x\nwant %x",
				tt.idx, built.Items[0].RawItemBody, item.RawItemBody)
		}
	}
}

func TestERABGBRBitrateConvertsS11KilobitsToS1APBits(t *testing.T) {
	tests := []struct {
		name       string
		s11Kbps    uint64
		wantS1AP   uint64
		wantOnWire uint64
	}{
		{name: "minimum non-zero", s11Kbps: 1, wantS1AP: 1_000, wantOnWire: 1_000},
		{name: "Nokia IMS GBR", s11Kbps: 128, wantS1AP: 128_000, wantOnWire: 128_000},
		{name: "one hundred Mbps", s11Kbps: 100_000, wantS1AP: 100_000_000, wantOnWire: 100_000_000},
		{name: "S1AP maximum saturation", s11Kbps: 11_000_000, wantS1AP: 11_000_000_000, wantOnWire: 10_000_000_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := make([]byte, 22)
			raw[1] = 2
			for _, off := range []int{2, 7, 12, 17} {
				copy(raw[off:off+5], encodeBearerQoSKilobitsForTest(tt.s11Kbps))
			}
			info, present := deriveGBRQosInformation(raw)
			if !present {
				t.Fatal("GBR QoS not present")
			}
			if info.MaxBitrateDL != tt.wantS1AP || info.MaxBitrateUL != tt.wantS1AP || info.GuaranteedBitrateDL != tt.wantS1AP || info.GuaranteedBitrateUL != tt.wantS1AP {
				t.Fatalf("derived GBR got DL/UL MBR=%d/%d GBR=%d/%d, want all %d", info.MaxBitrateDL, info.MaxBitrateUL, info.GuaranteedBitrateDL, info.GuaranteedBitrateUL, tt.wantS1AP)
			}
			w := aper.NewBitWriter()
			encodeBitRateForERABSetup(w, info.MaxBitrateDL)
			decoded, err := aper.DecodeConstrainedWholeNumber(aper.NewBitReader(w.Bytes()), 0, 10_000_000_000)
			if err != nil {
				t.Fatalf("decode encoded S1AP bitrate: %v", err)
			}
			if uint64(decoded) != tt.wantOnWire {
				t.Fatalf("encoded S1AP bitrate got %d, want %d", decoded, tt.wantOnWire)
			}
		})
	}
}

func TestERABGBRQoSDiagnosticRoundTrip(t *testing.T) {
	want := erabGBRQosInformation{
		MaxBitrateDL:        128_000,
		MaxBitrateUL:        128_000,
		GuaranteedBitrateDL: 128_000,
		GuaranteedBitrateUL: 128_000,
	}
	encoded, got, ok := encodeAndDecodeERABGBRQoSForDebug(want)
	if !ok || got != want {
		t.Fatalf("GBR diagnostic round trip got %+v ok=%t, want %+v true", got, ok, want)
	}
	if len(encoded) == 0 {
		t.Fatal("GBR diagnostic encoding is empty")
	}
}

func TestBuildCurrentIMSDefaultBearerERABSetupDecodes(t *testing.T) {
	nasPDU := bytes.Repeat([]byte{0x27}, 70)
	raw, _, err := BuildERABSetupRequest(1, 0x4003e, nil, []ERABSetupItem{{
		EBI:                     6,
		QCI:                     5,
		ARPPriority:             8,
		PreemptionCapability:    false,
		PreemptionVulnerability: true,
		SGWS1UIPv4:              net.ParseIP("10.90.250.59"),
		SGWS1UTEID:              0x570c0dad,
		NASPDU:                  nasPDU,
	}})
	if err != nil {
		t.Fatalf("BuildERABSetupRequest: %v", err)
	}
	req := decodeERABSetupRequest(t, raw)
	if len(req.Items) != 1 {
		t.Fatalf("item count got %d, want 1", len(req.Items))
	}
	got := req.Items[0]
	if got.EBI != 6 || got.QCI != 5 || got.ARPPriority != 8 || got.SGWS1UTEID != 0x570c0dad {
		t.Fatalf("decoded current IMS item got %+v", got)
	}
	if got.RawFirstByte != 0x0c {
		t.Fatalf("first E-RAB item body byte got %#02x, want 0x0c", got.RawFirstByte)
	}
}

func TestBuildERABSetupRequestUsesProvidedUEAMBR(t *testing.T) {
	raw, _, err := BuildERABSetupRequest(1, 2, &UEAggregateMaximumBitrate{
		Downlink: 1530000,
		Uplink:   3850000,
	}, []ERABSetupItem{{
		EBI:                     6,
		QCI:                     5,
		ARPPriority:             8,
		PreemptionVulnerability: true,
		SGWS1UIPv4:              net.ParseIP("10.90.250.59"),
		SGWS1UTEID:              0x570c0dad,
		NASPDU:                  []byte{0x27, 0x62, 0x00, 0xc2},
	}})
	if err != nil {
		t.Fatalf("BuildERABSetupRequest: %v", err)
	}
	req := decodeERABSetupRequest(t, raw)
	want := ies.EncodeUEAggregateMaxBitrate(1530000, 3850000)
	if !bytes.Equal(req.UEAMBR, want) {
		t.Fatalf("UE AMBR got %x, want %x", req.UEAMBR, want)
	}
}

func TestMalformedCurrentERABSetupFixtureIsRejected(t *testing.T) {
	req := decodeERABSetupRequest(t, mustReadHexFixture(t, "vectorcore_erab_setup_malformed.hex"))
	if len(req.Items) != 1 {
		t.Fatalf("item count got %d, want 1", len(req.Items))
	}
	got := req.Items[0]
	if got.RawFirstByte != 0x46 {
		t.Fatalf("malformed first item body byte got %#02x, want 0x46", got.RawFirstByte)
	}
	if sameBearerCore(got, 6, 5, "10.90.250.59", 0x570c0dad, 70) {
		t.Fatalf("malformed VectorCore packet unexpectedly decoded as the intended EBI 6 bearer")
	}
}

func TestERABSetupUsesCorrectSingleContainerIEID(t *testing.T) {
	req := decodePeerERABSetupRequestFixture(t, "peer_erab_setup_request_multi.hex")
	for i, item := range req.Items {
		if item.SingleContainerIEID != pdu.IEERABToBeSetupItemBearerSUReq {
			t.Fatalf("item %d IE ID got %d, want %d", i, item.SingleContainerIEID, pdu.IEERABToBeSetupItemBearerSUReq)
		}
	}
}

func TestERABSetupGTPTEIDNetworkByteOrder(t *testing.T) {
	_, erabList, err := BuildERABSetupRequest(1, 2, nil, []ERABSetupItem{{
		EBI:                     6,
		QCI:                     5,
		ARPPriority:             8,
		PreemptionVulnerability: true,
		SGWS1UIPv4:              net.ParseIP("10.90.250.59"),
		SGWS1UTEID:              0x570c0dad,
		NASPDU:                  []byte{0x07, 0x42},
	}})
	if err != nil {
		t.Fatalf("BuildERABSetupRequest: %v", err)
	}
	if !bytes.Contains(erabList, []byte{0x57, 0x0c, 0x0d, 0xad}) {
		t.Fatalf("encoded E-RAB list %x does not contain TEID in network byte order", erabList)
	}
}

func TestDecodePeerERABSetupResponseList(t *testing.T) {
	raw := mustReadHexFixture(t, "peer_erab_setup_response.hex")
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode peer response PDU: %v", err)
	}
	if p.Type != pdu.PDUTypeSuccessfulOutcome || p.ProcedureCode != pdu.ProcERABSetup {
		t.Fatalf("response got type=%s proc=%d, want successful E-RAB Setup", p.Type, p.ProcedureCode)
	}
	ieList, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		t.Fatalf("decode response IE list: %v", err)
	}
	var setupList []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABSetupListBearerSURes {
			setupList = ie.Value
		}
	}
	if len(setupList) == 0 {
		t.Fatalf("peer response missing E-RAB setup list")
	}
	results, err := decodeERABSetupResponseList(setupList)
	if err != nil {
		t.Fatalf("decodeERABSetupResponseList: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("result count got %d, want 3", len(results))
	}
	tests := []struct {
		idx  int
		ebi  uint8
		teid uint32
	}{
		{0, 6, 0x2476d51d},
		{1, 7, 0xa8b9f5cf},
		{2, 8, 0x26af56c5},
	}
	for _, tt := range tests {
		got := results[tt.idx]
		if got.EBI != tt.ebi {
			t.Fatalf("result %d EBI got %d, want %d", tt.idx, got.EBI, tt.ebi)
		}
		if got.ENBS1UTEID != tt.teid {
			t.Fatalf("result %d TEID got %#x, want %#x", tt.idx, got.ENBS1UTEID, tt.teid)
		}
		if ip := got.ENBS1UAddr.String(); ip != "192.168.105.247" {
			t.Fatalf("result %d IP got %s, want 192.168.105.247", tt.idx, ip)
		}
	}
}

func TestDecodeMultiItemERABSetupResponse(t *testing.T) {
	raw := mustReadHexFixture(t, "peer_erab_setup_response.hex")
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode PDU: %v", err)
	}
	ieList, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		t.Fatalf("decode IE list: %v", err)
	}
	resp, _, _, _, _, setupPresent, _, failedPresent, _, err := decodeERABSetupResponse(p, ieList)
	if err != nil {
		t.Fatalf("decodeERABSetupResponse: %v", err)
	}
	if !setupPresent {
		t.Fatal("setup list missing")
	}
	if failedPresent {
		t.Fatal("failed list unexpectedly present")
	}
	if len(resp.Successful) != 3 {
		t.Fatalf("successful result count got %d, want 3", len(resp.Successful))
	}
}

func TestERABSetupResponseWrongPairSendsErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.9.1:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 1
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
		{ID: pdu.IEERABSetupListBearerSURes, Criticality: aper.CriticalityIgnore, Value: encodeERABSetupResponseListForTest([]ERABSetupSuccess{
			{EBI: 6, ENBS1UAddr: net.ParseIP("192.168.105.247").To4(), ENBS1UTEID: 0xa8b9f5cf},
		})},
	}

	srv.handleERABSetupResponse(addr, &pdu.PDU{
		Type:          pdu.PDUTypeSuccessfulOutcome,
		ProcedureCode: pdu.ProcERABSetup,
		Criticality:   aper.CriticalityIgnore,
	}, nil, ieList)

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownPairUES1APID)
}

func TestDecodeERABSetupResponseWithOnlyFailureList(t *testing.T) {
	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABSetup, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(40)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(77)},
		{ID: pdu.IEERABFailedToSetupListBearerSURes, Criticality: aper.CriticalityIgnore, Value: encodeERABFailedToSetupListForTest([]ERABSetupFailure{
			{EBI: 7, CauseGroup: uint8(ies.CauseGroupRadioNetwork), Cause: uint32(ies.CauseRadioNetworkUnspecified)},
			{EBI: 8, CauseGroup: uint8(ies.CauseGroupTransport), Cause: 1},
		})},
	})
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode PDU: %v", err)
	}
	ieList, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		t.Fatalf("decode IE list: %v", err)
	}
	resp, _, _, _, _, setupPresent, _, failedPresent, _, err := decodeERABSetupResponse(p, ieList)
	if err != nil {
		t.Fatalf("decodeERABSetupResponse: %v", err)
	}
	if setupPresent {
		t.Fatal("setup list unexpectedly present")
	}
	if !failedPresent {
		t.Fatal("failed list missing")
	}
	if len(resp.Successful) != 0 {
		t.Fatalf("successful result count got %d, want 0", len(resp.Successful))
	}
	if len(resp.Failed) != 2 {
		t.Fatalf("failed result count got %d, want 2", len(resp.Failed))
	}
	if resp.Failed[0].EBI != 7 || resp.Failed[1].EBI != 8 {
		t.Fatalf("failed EBIs got %+v", resp.Failed)
	}
}

func TestDecodeERABSetupResponseWithSuccessAndFailureLists(t *testing.T) {
	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABSetup, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(40)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(77)},
		{ID: pdu.IEERABSetupListBearerSURes, Criticality: aper.CriticalityIgnore, Value: encodeERABSetupResponseListForTest([]ERABSetupSuccess{
			{EBI: 7, ENBS1UAddr: net.ParseIP("192.168.105.247").To4(), ENBS1UTEID: 0xa8b9f5cf},
		})},
		{ID: pdu.IEERABFailedToSetupListBearerSURes, Criticality: aper.CriticalityIgnore, Value: encodeERABFailedToSetupListForTest([]ERABSetupFailure{
			{EBI: 8, CauseGroup: uint8(ies.CauseGroupRadioNetwork), Cause: uint32(ies.CauseRadioNetworkUnspecified)},
		})},
	})
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode PDU: %v", err)
	}
	ieList, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		t.Fatalf("decode IE list: %v", err)
	}
	resp, _, _, _, _, _, _, _, _, err := decodeERABSetupResponse(p, ieList)
	if err != nil {
		t.Fatalf("decodeERABSetupResponse: %v", err)
	}
	if len(resp.Successful) != 1 || len(resp.Failed) != 1 {
		t.Fatalf("got %d successful and %d failed, want 1 and 1", len(resp.Successful), len(resp.Failed))
	}
	if resp.Successful[0].EBI != 7 || resp.Failed[0].EBI != 8 {
		t.Fatalf("decoded response got success=%+v failed=%+v", resp.Successful, resp.Failed)
	}
}

func TestConcurrentIMSAndDedicatedERABProceduresCorrelateByEBI(t *testing.T) {
	ue := uecontext.NewContext(40)
	ue.S1BindingGeneration = 9
	ue.PendingERABProcedures["ims"] = &uecontext.PendingERABProcedure{
		TransactionID:       "ims",
		ProcedureKind:       "ims_default_bearer",
		ExpectedEBIs:        map[uint8]struct{}{6: {}},
		S1BindingGeneration: 9,
	}
	ue.PendingERABProcedures["dedicated"] = &uecontext.PendingERABProcedure{
		TransactionID:       "dedicated",
		ProcedureKind:       "dedicated_create_bearer",
		ExpectedEBIs:        map[uint8]struct{}{7: {}, 8: {}},
		S1BindingGeneration: 9,
	}

	ue.Lock()
	proc, reason, ambiguous := matchPendingERABProcedureLocked(ue, map[uint8]struct{}{7: {}, 8: {}})
	ue.Unlock()
	if ambiguous {
		t.Fatal("matcher reported ambiguity for exact dedicated match")
	}
	if proc == nil || proc.TransactionID != "dedicated" {
		t.Fatalf("matched procedure got %+v, want dedicated", proc)
	}
	if reason != "exact_expected_ebi_set" {
		t.Fatalf("match reason got %q, want exact_expected_ebi_set", reason)
	}
}

func TestEBI6ResponseDoesNotCompleteEBI7And8Transaction(t *testing.T) {
	ue := uecontext.NewContext(40)
	ue.S1BindingGeneration = 9
	ue.PendingERABProcedures["ims"] = &uecontext.PendingERABProcedure{
		TransactionID:       "ims",
		ProcedureKind:       "ims_default_bearer",
		ExpectedEBIs:        map[uint8]struct{}{6: {}},
		S1BindingGeneration: 9,
	}
	ue.PendingERABProcedures["dedicated"] = &uecontext.PendingERABProcedure{
		TransactionID:       "dedicated",
		ProcedureKind:       "dedicated_create_bearer",
		ExpectedEBIs:        map[uint8]struct{}{7: {}, 8: {}},
		S1BindingGeneration: 9,
	}

	ue.Lock()
	proc, _, _ := matchPendingERABProcedureLocked(ue, map[uint8]struct{}{6: {}})
	ue.Unlock()
	if proc == nil || proc.TransactionID != "ims" {
		t.Fatalf("matched procedure got %+v, want ims", proc)
	}
}

func TestEBI7And8ResponseDoesNotCompleteIMSDefaultBearer(t *testing.T) {
	ue := uecontext.NewContext(40)
	ue.S1BindingGeneration = 9
	ue.PendingERABProcedures["ims"] = &uecontext.PendingERABProcedure{
		TransactionID:       "ims",
		ProcedureKind:       "ims_default_bearer",
		ExpectedEBIs:        map[uint8]struct{}{6: {}},
		S1BindingGeneration: 9,
	}
	ue.PendingERABProcedures["dedicated"] = &uecontext.PendingERABProcedure{
		TransactionID:       "dedicated",
		ProcedureKind:       "dedicated_create_bearer",
		ExpectedEBIs:        map[uint8]struct{}{7: {}, 8: {}},
		S1BindingGeneration: 9,
	}

	ue.Lock()
	proc, _, _ := matchPendingERABProcedureLocked(ue, map[uint8]struct{}{7: {}})
	ue.Unlock()
	if proc == nil || proc.TransactionID != "dedicated" {
		t.Fatalf("matched procedure got %+v, want dedicated", proc)
	}
}

func encodeERABSetupResponseListForTest(items []ERABSetupSuccess) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
	w.AlignToByte()
	for _, item := range items {
		body := encodeERABSetupResponseItemForTest(item)
		w.WriteOctets(encodeSingleContainerIEForTest(pdu.IEERABSetupItemBearerSURes, aper.CriticalityIgnore, body))
	}
	return w.Bytes()
}

func encodeERABFailedToSetupListForTest(items []ERABSetupFailure) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
	w.AlignToByte()
	for _, item := range items {
		body := encodeERABFailedToSetupItemForTest(item)
		w.WriteOctets(encodeSingleContainerIEForTest(0, aper.CriticalityIgnore, body))
	}
	return w.Bytes()
}

func encodeSingleContainerIEForTest(id uint16, crit aper.Criticality, body []byte) []byte {
	inner := pdu.EncodeIEContainer([]pdu.ProtocolIE{{ID: id, Criticality: crit, Value: body}})
	return inner[2:]
}

func encodeERABSetupResponseItemForTest(item ERABSetupSuccess) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	w.WriteOctets(item.ENBS1UAddr.To4())
	w.AlignToByte()
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, item.ENBS1UTEID)
	w.WriteOctets(b)
	return w.Bytes()
}

func encodeERABFailedToSetupItemForTest(item ERABSetupFailure) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)
	copyCauseBits(w, ies.EncodeCause(ies.CauseGroup(item.CauseGroup), uint8(item.Cause)))
	return w.Bytes()
}

func copyCauseBits(w *aper.BitWriter, encoded []byte) {
	r := aper.NewBitReader(encoded)
	for i := 0; i < len(encoded)*8; i++ {
		bit, err := r.ReadBit()
		if err != nil {
			panic(err)
		}
		w.WriteBit(bit)
	}
}

func decodePeerERABSetupRequestFixture(t *testing.T, name string) normalizedERABSetupRequest {
	t.Helper()
	return decodeERABSetupRequest(t, mustReadHexFixture(t, name))
}

func decodeERABSetupRequest(t *testing.T, raw []byte) normalizedERABSetupRequest {
	t.Helper()
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode E-RAB Setup PDU: %v", err)
	}
	if p.Type != pdu.PDUTypeInitiatingMessage || p.ProcedureCode != pdu.ProcERABSetup {
		t.Fatalf("PDU got type=%s proc=%d, want initiating E-RAB Setup", p.Type, p.ProcedureCode)
	}
	ieList, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		t.Fatalf("decode E-RAB Setup IE list: %v", err)
	}
	out := normalizedERABSetupRequest{
		ProcedureCode: p.ProcedureCode,
		Criticality:   p.Criticality,
	}
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			out.MMEUES1APID, _ = ies.DecodeMMEUEApID(ie.Value)
		case pdu.IEENBS1APID:
			out.ENBUES1APID, _ = ies.DecodeENBUEApID(ie.Value)
		case pdu.IEUEAggregateMaxBitrate:
			out.UEAMBR = append([]byte(nil), ie.Value...)
		case pdu.IEERABToBeSetupListBearerSUReq:
			out.Items = decodeERABSetupRequestList(t, ie.Value)
		}
	}
	return out
}

func decodeERABSetupRequestList(t *testing.T, data []byte) []normalizedERABSetupItem {
	t.Helper()
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		t.Fatalf("decode E-RAB setup request list count: %v", err)
	}
	r.AlignToByte()
	items := make([]normalizedERABSetupItem, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			t.Fatalf("decode request item %d IE ID: %v", i, err)
		}
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			t.Fatalf("decode request item %d criticality: %v", i, err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			t.Fatalf("read request item %d open type: %v", i, err)
		}
		item := decodeERABSetupRequestItem(t, itemBytes)
		item.SingleContainerIEID = uint16(ieID)
		item.SingleContainerCriticality = crit
		items = append(items, item)
	}
	return items
}

func decodeERABSetupRequestItem(t *testing.T, data []byte) normalizedERABSetupItem {
	t.Helper()
	if len(data) == 0 {
		t.Fatalf("empty E-RAB setup request item")
	}
	r := aper.NewBitReader(data)
	item := normalizedERABSetupItem{
		RawFirstByte: data[0],
		RawItemBody:  append([]byte(nil), data...),
	}
	seqExt, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode E-RAB item extension bit: %v", err)
	}
	if seqExt != 0 {
		t.Fatalf("E-RAB item extension bit got %d, want 0", seqExt)
	}
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode E-RAB item iE-Extensions presence: %v", err)
	}
	erabExt, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode E-RAB ID extension bit: %v", err)
	}
	if erabExt != 0 {
		t.Fatalf("E-RAB ID extension bit got %d, want 0", erabExt)
	}
	ebi, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		t.Fatalf("decode E-RAB ID: %v", err)
	}
	item.EBI = uint8(ebi)

	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode QoS extension bit got %d err=%v, want 0 nil", ext, err)
	}
	gbrPresent, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode QoS GBR presence: %v", err)
	}
	item.GBRQosInformationPresent = gbrPresent == 1
	if ieExtPresent, err := r.ReadBit(); err != nil || ieExtPresent != 0 {
		t.Fatalf("decode QoS IE extension presence got %d err=%v, want 0 nil", ieExtPresent, err)
	}
	qci, err := aper.DecodeConstrainedWholeNumber(r, 0, 255)
	if err != nil {
		t.Fatalf("decode QCI: %v", err)
	}
	item.QCI = uint8(qci)
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode ARP extension bit got %d err=%v, want 0 nil", ext, err)
	}
	if ieExtPresent, err := r.ReadBit(); err != nil || ieExtPresent != 0 {
		t.Fatalf("decode ARP IE extension presence got %d err=%v, want 0 nil", ieExtPresent, err)
	}
	arp, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		t.Fatalf("decode ARP priority: %v", err)
	}
	item.ARPPriority = uint8(arp)
	pc, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		t.Fatalf("decode preemption capability: %v", err)
	}
	pv, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		t.Fatalf("decode preemption vulnerability: %v", err)
	}
	item.PreemptionCapability = pc == 1
	item.PreemptionVulnerability = pv == 1
	if item.GBRQosInformationPresent {
		if ext, err := r.ReadBit(); err != nil || ext != 0 {
			t.Fatalf("decode GBR extension got %d err=%v, want 0 nil", ext, err)
		}
		if ieExtPresent, err := r.ReadBit(); err != nil || ieExtPresent != 0 {
			t.Fatalf("decode GBR IE extension presence got %d err=%v, want 0 nil", ieExtPresent, err)
		}
		values := [4]uint64{}
		for i := range values {
			value, err := aper.DecodeConstrainedWholeNumber(r, 0, 10000000000)
			if err != nil {
				t.Fatalf("decode GBR bitrate %d: %v", i, err)
			}
			values[i] = uint64(value)
		}
		item.MaxBitrateDL, item.MaxBitrateUL = values[0], values[1]
		item.GuaranteedBitrateDL, item.GuaranteedBitrateUL = values[2], values[3]
	}

	addrExt, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode transportLayerAddress extension bit: %v", err)
	}
	var addrBits int64
	if addrExt == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(r, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(r, 0, 65535)
	}
	if err != nil {
		t.Fatalf("decode transportLayerAddress bit length: %v", err)
	}
	item.TransportAddressBits = int(addrBits)
	r.AlignToByte()
	addrBytes, err := r.ReadOctets(int((addrBits + 7) / 8))
	if err != nil {
		t.Fatalf("decode transportLayerAddress: %v", err)
	}
	item.SGWS1UIPv4 = net.IP(addrBytes[:4]).String()
	teidBytes, err := r.ReadOctets(4)
	if err != nil {
		t.Fatalf("decode GTP TEID: %v", err)
	}
	item.SGWS1UTEID = binary.BigEndian.Uint32(teidBytes)
	if r.Remaining() > 0 {
		nasLen, err := aper.DecodeUnconstrainedLength(r)
		if err != nil {
			t.Fatalf("decode NAS-PDU length: %v", err)
		}
		nas, err := r.ReadOctets(nasLen)
		if err != nil {
			t.Fatalf("decode NAS-PDU: %v", err)
		}
		item.NASPDUPresent = true
		item.NASPDU = nas
	}
	item.DecodedWithoutTrailingOctets = r.Remaining() == 0
	return item
}

func sameBearerSemantics(a, b normalizedERABSetupItem) bool {
	return a.EBI == b.EBI &&
		a.QCI == b.QCI &&
		a.ARPPriority == b.ARPPriority &&
		a.PreemptionCapability == b.PreemptionCapability &&
		a.PreemptionVulnerability == b.PreemptionVulnerability &&
		a.TransportAddressBits == b.TransportAddressBits &&
		a.SGWS1UIPv4 == b.SGWS1UIPv4 &&
		a.SGWS1UTEID == b.SGWS1UTEID &&
		a.GBRQosInformationPresent == b.GBRQosInformationPresent &&
		a.MaxBitrateDL == b.MaxBitrateDL &&
		a.MaxBitrateUL == b.MaxBitrateUL &&
		a.GuaranteedBitrateDL == b.GuaranteedBitrateDL &&
		a.GuaranteedBitrateUL == b.GuaranteedBitrateUL &&
		bytes.Equal(a.NASPDU, b.NASPDU)
}

func sameBearerCore(item normalizedERABSetupItem, ebi, qci uint8, ip string, teid uint32, nasLen int) bool {
	return item.EBI == ebi &&
		item.QCI == qci &&
		item.SGWS1UIPv4 == ip &&
		item.SGWS1UTEID == teid &&
		len(item.NASPDU) == nasLen
}

func mustReadHexFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r
		default:
			return -1
		}
	}, string(raw))
	if len(clean)%2 != 0 {
		t.Fatalf("%s has odd-length hex", name)
	}
	out, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("%s invalid hex: %v", name, err)
	}
	return out
}

func TestReadPeerFixtureJSONFiles(t *testing.T) {
	for _, name := range []string{
		"peer_erab_setup_request_multi.json",
		"peer_erab_setup_response.json",
	} {
		if _, err := os.ReadFile("testdata/" + name); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
	}
}

func Example_erabSetupFirstDivergence() {
	peer := mustDecodeHexForExample("0000110080850c0005040f800a5afa3bf187cfec")
	oldVectorCore := mustDecodeHexForExample("0000110055460005210f800a5afa3b570c0dad")
	fmt.Printf("peer item body first byte: 0x%02x\n", peer[6])
	fmt.Printf("old vectorcore item body first byte: 0x%02x\n", oldVectorCore[5])
	// Output:
	// peer item body first byte: 0x0c
	// old vectorcore item body first byte: 0x46
}

func mustDecodeHexForExample(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func encodeBearerQoSForTest(qci, arp uint8, mbrUL, mbrDL, gbrUL, gbrDL uint64) []byte {
	out := make([]byte, 22)
	out[0] = arp
	out[1] = qci
	copy(out[2:7], encodeBearerQoSBitrateForTest(mbrUL))
	copy(out[7:12], encodeBearerQoSBitrateForTest(mbrDL))
	copy(out[12:17], encodeBearerQoSBitrateForTest(gbrUL))
	copy(out[17:22], encodeBearerQoSBitrateForTest(gbrDL))
	return out
}

func encodeBearerQoSBitrateForTest(v uint64) []byte {
	if v%1000 != 0 {
		panic("Bearer QoS test bitrate must be a whole kbit/s")
	}
	v /= 1000
	return encodeBearerQoSKilobitsForTest(v)
}

func encodeBearerQoSKilobitsForTest(v uint64) []byte {
	out := make([]byte, 5)
	for i := 4; i >= 0; i-- {
		out[i] = byte(v & 0xff)
		v >>= 8
	}
	return out
}
