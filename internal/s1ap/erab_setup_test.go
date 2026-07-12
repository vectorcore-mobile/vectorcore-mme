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
	NASPDUPresent                bool
	NASPDU                       []byte
	RawFirstByte                 byte
	RawItemBody                  []byte
	DecodedWithoutTrailingOctets bool
}

func TestDecodeCiscoERABSetupRequestMultipleBearers(t *testing.T) {
	req := decodeCiscoERABSetupRequestFixture(t, "cisco_erab_setup_request_multi.hex")
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
	}
}

func TestBuildERABSetupRequestMatchesCiscoDefaultBearerSemantics(t *testing.T) {
	cisco := decodeCiscoERABSetupRequestFixture(t, "cisco_erab_setup_request_multi.hex")
	item := cisco.Items[0]
	builtRaw, _, err := BuildERABSetupRequest(cisco.MMEUES1APID, cisco.ENBUES1APID, nil, []ERABSetupItem{{
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
		t.Fatalf("built EBI 6 item body differs from Cisco:\n got %x\nwant %x",
			built.Items[0].RawItemBody, item.RawItemBody)
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
	req := decodeCiscoERABSetupRequestFixture(t, "cisco_erab_setup_request_multi.hex")
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

func TestDecodeCiscoERABSetupResponseList(t *testing.T) {
	raw := mustReadHexFixture(t, "cisco_erab_setup_response.hex")
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode Cisco response PDU: %v", err)
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
		t.Fatalf("Cisco response missing E-RAB setup list")
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
		if ip := got.ENBS1UIPv4.String(); ip != "192.168.105.247" {
			t.Fatalf("result %d IP got %s, want 192.168.105.247", tt.idx, ip)
		}
	}
}

func decodeCiscoERABSetupRequestFixture(t *testing.T, name string) normalizedERABSetupRequest {
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
	if item.GBRQosInformationPresent {
		decodeCiscoGBRBearerTail(t, data, r.BytesConsumed(), &item)
		return item
	}

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

func decodeCiscoGBRBearerTail(t *testing.T, data []byte, start int, item *normalizedERABSetupItem) {
	t.Helper()
	idx := bytes.Index(data[start:], []byte{0x0a, 0x5a, 0xfa, 0x3b})
	if idx < 0 {
		t.Fatalf("GBR E-RAB item missing Cisco SGW S1-U IPv4 marker")
	}
	ipOff := start + idx
	if ipOff+4+4+1 > len(data) {
		t.Fatalf("GBR E-RAB item truncated before TEID/NAS")
	}
	item.TransportAddressBits = 32
	item.SGWS1UIPv4 = net.IP(data[ipOff : ipOff+4]).String()
	item.SGWS1UTEID = binary.BigEndian.Uint32(data[ipOff+4 : ipOff+8])
	nasLenOff := ipOff + 8
	nasLen := int(data[nasLenOff])
	if nasLenOff+1+nasLen != len(data) {
		t.Fatalf("GBR E-RAB NAS length got %d at offset %d for item length %d", nasLen, nasLenOff, len(data))
	}
	item.NASPDUPresent = true
	item.NASPDU = append([]byte(nil), data[nasLenOff+1:]...)
	item.DecodedWithoutTrailingOctets = true
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

func TestReadCiscoFixtureJSONFiles(t *testing.T) {
	for _, name := range []string{
		"cisco_erab_setup_request_multi.json",
		"cisco_erab_setup_response.json",
	} {
		if _, err := os.ReadFile("testdata/" + name); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
	}
}

func Example_erabSetupFirstDivergence() {
	cisco := mustDecodeHexForExample("0000110080850c0005040f800a5afa3bf187cfec")
	oldVectorCore := mustDecodeHexForExample("0000110055460005210f800a5afa3b570c0dad")
	fmt.Printf("cisco item body first byte: 0x%02x\n", cisco[6])
	fmt.Printf("old vectorcore item body first byte: 0x%02x\n", oldVectorCore[5])
	// Output:
	// cisco item body first byte: 0x0c
	// old vectorcore item body first byte: 0x46
}

func mustDecodeHexForExample(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
