package gtpv2

import (
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
)

func loadHexFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	clean := strings.Join(strings.Fields(string(raw)), "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("DecodeString(%s): %v", path, err)
	}
	return b
}

func TestDecodeNokiaCreateBearerMultipleContextsAllocatesEBIs(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/cisco_nokia/create_bearer_two_zero_ebi.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeCreateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeCreateBearerRequest: %v", err)
	}
	if req.TEID != 0x802f4007 || req.SeqNum != 0x10e {
		t.Fatalf("ids got teid=0x%x seq=0x%x", req.TEID, req.SeqNum)
	}
	if req.LinkedEBI != 6 {
		t.Fatalf("linked EBI got %d, want 6", req.LinkedEBI)
	}
	if len(req.Bearers) != 2 {
		t.Fatalf("bearers got %d, want 2", len(req.Bearers))
	}
	for i, b := range req.Bearers {
		if b.RequestedEBI != 0 || !b.NeedsEBIAllocation {
			t.Fatalf("bearer %d requested EBI got %d alloc=%v, want zero allocation", i, b.RequestedEBI, b.NeedsEBIAllocation)
		}
		if b.QCI == 0 || len(b.TFT) == 0 || b.SGWS1UTEID == 0 || !net.IP(b.SGWS1UIP).Equal(net.ParseIP("10.90.250.59").To4()) {
			t.Fatalf("bearer %d incomplete decode: %+v", i, b)
		}
	}
	if err := AssignRequestedBearerIDs(req.Bearers, map[uint8]bool{5: true, 6: true}); err != nil {
		t.Fatalf("AssignRequestedBearerIDs: %v", err)
	}
	if req.Bearers[0].EBI != 7 || req.Bearers[1].EBI != 8 {
		t.Fatalf("allocated EBIs got %d/%d, want 7/8", req.Bearers[0].EBI, req.Bearers[1].EBI)
	}
}

func TestDecodeSonimCreateBearerAllocatesNextFreeEBI(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/cisco_sonim/create_bearer_one_zero_ebi.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeCreateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeCreateBearerRequest: %v", err)
	}
	if req.LinkedEBI != 6 || len(req.Bearers) != 1 {
		t.Fatalf("got linked=%d bearers=%d, want linked=6 bearers=1", req.LinkedEBI, len(req.Bearers))
	}
	if req.Bearers[0].RequestedEBI != 0 || !req.Bearers[0].NeedsEBIAllocation {
		t.Fatalf("requested EBI got %d alloc=%v", req.Bearers[0].RequestedEBI, req.Bearers[0].NeedsEBIAllocation)
	}
	used := map[uint8]bool{5: true, 6: true, 7: true, 8: true, 9: true}
	if err := AssignRequestedBearerIDs(req.Bearers, used); err != nil {
		t.Fatalf("AssignRequestedBearerIDs: %v", err)
	}
	if req.Bearers[0].EBI != 10 {
		t.Fatalf("allocated EBI got %d, want 10", req.Bearers[0].EBI)
	}
}

func TestCreateBearerResponseIncludesENBFTEID(t *testing.T) {
	out := EncodeCreateBearerResponse(0x12345678, 0x101, CauseRequestAccepted, []CreateBearerBearer{{
		EBI:        7,
		ENBS1UTEID: 0xaabbccdd,
		ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
	}})
	msg, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	if msg.Type != MsgCreateBearerResponse || msg.TEID != 0x12345678 || msg.SeqNum != 0x101 {
		t.Fatalf("response header got type=%d teid=0x%x seq=0x%x", msg.Type, msg.TEID, msg.SeqNum)
	}
	children, err := FindGroupedIEs(FindIE(msg.IEs, IETypeBearerContext, 0))
	if err != nil {
		t.Fatalf("FindGroupedIEs: %v", err)
	}
	f, err := DecodeFTEID(FindIE(children, IETypeFTEID, 0))
	if err != nil {
		t.Fatalf("DecodeFTEID: %v", err)
	}
	if f.InterfaceType != IFTypeS1UENB || f.TEID != 0xaabbccdd || !f.IP.Equal(net.ParseIP("192.168.105.247").To4()) {
		t.Fatalf("FTEID got %+v", f)
	}
}

func TestDecodeNokiaUpdateBearerDeleteFilters(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/cisco_nokia/update_bearer_delete_filters.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeUpdateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeUpdateBearerRequest: %v", err)
	}
	if req.TEID != 0x802f4007 || req.SeqNum != 0x114 || len(req.Bearers) != 1 {
		t.Fatalf("got teid=0x%x seq=0x%x bearers=%d", req.TEID, req.SeqNum, len(req.Bearers))
	}
	b := req.Bearers[0]
	if b.EBI != 9 {
		t.Fatalf("EBI got %d, want 9", b.EBI)
	}
	wantTFT := "a404050607"
	if hex.EncodeToString(b.TFT) != wantTFT {
		t.Fatalf("TFT got %s, want %s", hex.EncodeToString(b.TFT), wantTFT)
	}
}

func TestDecodeSonimUpdateBearerReplaceFilters(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/cisco_sonim/update_bearer_replace_filters.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeUpdateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeUpdateBearerRequest: %v", err)
	}
	if len(req.Bearers) != 1 || req.Bearers[0].EBI != 10 {
		t.Fatalf("got bearers=%d first=%+v", len(req.Bearers), req.Bearers[0])
	}
	if len(req.Bearers[0].TFT) < 2 || req.Bearers[0].TFT[0] != 0x88 {
		t.Fatalf("unexpected TFT prefix %x", req.Bearers[0].TFT)
	}
}

func TestDecodeSonimDeleteBearerRequest(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/cisco_sonim/delete_bearer_ebi11.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeDeleteBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeDeleteBearerRequest: %v", err)
	}
	if req.TEID != 0x80210006 || req.SeqNum != 0x130 {
		t.Fatalf("ids got teid=0x%x seq=0x%x", req.TEID, req.SeqNum)
	}
	if len(req.EBIs) != 1 || req.EBIs[0] != 11 {
		t.Fatalf("EBIs got %v, want [11]", req.EBIs)
	}
}
