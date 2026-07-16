package gtpv2

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	return b
}

func TestReferenceFrame17DecodeMatchesReference(t *testing.T) {
	raw := mustDecodeHex(t, "5821009d803de008129a0800020002001000570009008bc04dad7b0a5afa3b5700090187801080060a5afa5c4f000500010a96039c7f000100004800080000000f0a000005fa4e002e0080000d040a5afa0a000d040a5afa0c000c040a5afa328021100301001081060a5afa0a83060a5afa0c00100205785d0025004900010006020002001000570009008169eb85ee0a5afa3b570009028580a580060a5afa5c485f00ad803de0080002390049000100065d004c00490001000054000f002130300b100a96039cffffffff301157000900812df38f080a5afa3b570009018580a5a0060a5afa5c50001600100200000000800000000080000000008000000000805d004c00490001000054000f002130350b100a96039cffffffff3011570009008160f1b7390a5afa3b570009018580a5c0060a5afa5c5000160008010000000080000000008000000000800000000080")
	msgs, err := DecodeAll(raw)
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("message count got %d, want 2", len(msgs))
	}

	csrsp, err := DecodeCreateSessionResponse(msgs[0])
	if err != nil {
		t.Fatalf("DecodeCreateSessionResponse: %v", err)
	}
	if csrsp.Cause != CauseRequestAccepted || csrsp.SGWC_TEID != 0xc04dad7b || !csrsp.SGWC_IP.Equal(net.ParseIP("10.90.250.59").To4()) {
		t.Fatalf("CSRsp core fields got %+v", csrsp)
	}
	if csrsp.PGWC_TEID != 0x80108006 || !csrsp.PGWC_IP.Equal(net.ParseIP("10.90.250.92").To4()) {
		t.Fatalf("CSRsp PGW-C fields got teid=0x%x ip=%v", csrsp.PGWC_TEID, csrsp.PGWC_IP)
	}
	if csrsp.EBI != 6 || csrsp.SGWU_TEID != 0x69eb85ee || !csrsp.SGWU_IP.Equal(net.ParseIP("10.90.250.59").To4()) {
		t.Fatalf("CSRsp SGW-U fields got %+v", csrsp)
	}
	if csrsp.PGWU_TEID != 0x80a58006 || !csrsp.PGWU_IP.Equal(net.ParseIP("10.90.250.92").To4()) {
		t.Fatalf("CSRsp PGW-U fields got teid=0x%x ip=%v", csrsp.PGWU_TEID, csrsp.PGWU_IP)
	}
	if got, want := csrsp.UEIPv4.String(), "10.150.3.156"; got != want {
		t.Fatalf("UEIPv4 got %s, want %s", got, want)
	}
	if csrsp.APNRestriction != APNRestrictionNoRestriction {
		t.Fatalf("APN restriction got %d, want %d", csrsp.APNRestriction, APNRestrictionNoRestriction)
	}
	if csrsp.AMBRUplink != 3850 || csrsp.AMBRDownlink != 1530 {
		t.Fatalf("AMBR got up=%d down=%d, want 3850/1530", csrsp.AMBRUplink, csrsp.AMBRDownlink)
	}
	wantPCO := mustDecodeHex(t, "80000d040a5afa0a000d040a5afa0c000c040a5afa328021100301001081060a5afa0a83060a5afa0c0010020578")
	if !bytes.Equal(csrsp.PCO, wantPCO) {
		t.Fatalf("CSRsp PCO got %x, want %x", csrsp.PCO, wantPCO)
	}

	cbrq, err := DecodeCreateBearerRequest(msgs[1])
	if err != nil {
		t.Fatalf("DecodeCreateBearerRequest: %v", err)
	}
	if cbrq.TEID != 0x803de008 || cbrq.SeqNum != 0x239 || cbrq.LinkedEBI != 6 {
		t.Fatalf("CBRq header got teid=0x%x seq=0x%x linked=%d", cbrq.TEID, cbrq.SeqNum, cbrq.LinkedEBI)
	}
	if len(cbrq.Bearers) != 2 {
		t.Fatalf("CBRq bearer count got %d, want 2", len(cbrq.Bearers))
	}
	if cbrq.Bearers[0].PGWS5S8UTEID != 0x80a5a006 || !net.IP(cbrq.Bearers[0].PGWS5S8UIP).Equal(net.ParseIP("10.90.250.92").To4()) {
		t.Fatalf("CBRq bearer0 PGW-U got teid=0x%x ip=%v", cbrq.Bearers[0].PGWS5S8UTEID, cbrq.Bearers[0].PGWS5S8UIP)
	}
	if cbrq.Bearers[1].PGWS5S8UTEID != 0x80a5c006 || !net.IP(cbrq.Bearers[1].PGWS5S8UIP).Equal(net.ParseIP("10.90.250.92").To4()) {
		t.Fatalf("CBRq bearer1 PGW-U got teid=0x%x ip=%v", cbrq.Bearers[1].PGWS5S8UTEID, cbrq.Bearers[1].PGWS5S8UIP)
	}
}

func TestReferenceFrame18EncodeMatchesReference(t *testing.T) {
	cbrsp := EncodeCreateBearerResponseWithMeta(0xc04dad7b, 0x239, CauseRequestAccepted, []CreateBearerBearer{
		{
			EBI:        7,
			ENBS1UTEID: 0xd68bc10f,
			ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
			SGWS1UTEID: 0x2df38f08,
			SGWS1UIP:   net.ParseIP("10.90.250.59").To4(),
		},
		{
			EBI:        8,
			ENBS1UTEID: 0xb9df33db,
			ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
			SGWS1UTEID: 0x60f1b739,
			SGWS1UIP:   net.ParseIP("10.90.250.59").To4(),
		},
	}, &CreateBearerResponseMeta{
		IncludeULI: true,
		ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
		ULITAC:     1,
		ULIECI:     0x000c8001,
	})
	mbr := (&ModifyBearerRequest{
		SGWC_TEID:             0xc04dad7b,
		EBI:                   6,
		ENBU_TEID:             0x885fb60a,
		ENBU_IP:               net.ParseIP("192.168.105.247").To4(),
		IncludeIndicationCRSI: true,
		OmitRATType:           true,
	}).Encode(0x129c08)
	got, err := EncodePiggybacked(cbrsp, mbr)
	if err != nil {
		t.Fatalf("EncodePiggybacked: %v", err)
	}
	want := mustDecodeHex(t, "58600071c04dad7b0002390002000200100056000d00181351340001135134000c80015d00250049000100070200020010005700090080d68bc10fc0a869f757000901812df38f080a5afa3b5d00250049000100080200020010005700090080b9df33dbc0a869f7570009018160f1b7390a5afa3b4822002ac04dad7b129c08004d00080000100000000000005d00120049000100065700090080885fb60ac0a869f7")
	if !bytes.Equal(got, want) {
		t.Fatalf("frame18 mismatch\n got  %x\n want %x", got, want)
	}
}

func TestReferenceFrame20DecodeMatchesReference(t *testing.T) {
	raw := mustDecodeHex(t, "4823002a803de008129c08000200020010005d0018004900010006020002001000570009008169eb85ee0a5afa3b")
	msg, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	resp, err := DecodeModifyBearerResponse(msg)
	if err != nil {
		t.Fatalf("DecodeModifyBearerResponse: %v", err)
	}
	if resp.Cause != CauseRequestAccepted || resp.EBI != 6 || resp.BearerCause != CauseRequestAccepted {
		t.Fatalf("MBRsp causes got %+v", resp)
	}
	if resp.SGWU_TEID != 0x69eb85ee || !resp.SGWU_IP.Equal(net.ParseIP("10.90.250.59").To4()) {
		t.Fatalf("MBRsp SGW-U got teid=0x%x ip=%v", resp.SGWU_TEID, resp.SGWU_IP)
	}
}
