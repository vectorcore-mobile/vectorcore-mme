package s1ap

import (
	"bytes"
	"net"
	"testing"

	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// dcnrCapableUENetworkCapability is a raw UE Network Capability IE value
// (TS 24.301 §9.9.3.34) with the DCNR bit set (octet 9 bit 5).
var dcnrCapableUENetworkCapability = []byte{0xf0, 0x70, 0x00, 0x00, 0x00, 0x00, 0x10}

// noDCNRUENetworkCapability has no octet 9 at all, so DCNR defaults false.
var noDCNRUENetworkCapability = []byte{0xf0, 0x70}

func setupAttachAcceptTestUE(t *testing.T, srv *Server, remoteAddr string, ueNetCap []byte, accessRestriction gateway.AccessRestrictionData) *uecontext.Context {
	t.Helper()
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.ENBS1APID = 1
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.Lock()
	ue.TAI = tai
	ue.KASME = make([]byte, 32)
	ue.KNASint = fakeKeys()
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = security.AlgIDEIA2
	ue.EncAlg = 0
	ue.DLNASCount = 1
	ue.PDNRequestPTI = 1
	ue.APN = "internet"
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	ue.UENetworkCapability = ueNetCap
	ue.AccessRestrictionData = accessRestriction
	ue.Unlock()
	return ue
}

func TestAttachAcceptSetsRestrictDCNRWhenUEDeclaresSupportAndHSSRestricts(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.11:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := setupAttachAcceptTestUE(t, srv, remoteAddr, dcnrCapableUENetworkCapability, gateway.AccessRestrictNRAsSecondaryRATInEUTRAN)

	srv.HandleCSRResult(ue.MMEUES1APID, &gtpv2.CreateSessionResponse{
		Cause:     gtpv2.CauseRequestAccepted,
		SGWC_TEID: 0x100,
		SGWC_IP:   net.ParseIP("10.0.0.2"),
		SGWU_TEID: 0x200,
		SGWU_IP:   net.ParseIP("10.0.0.3"),
		UEIPv4:    net.ParseIP("10.45.0.10"),
		EBI:       5,
	}, nil)

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromInitialContextSetup(t, msg)
	if !bytes.Contains(nasPDU[6:], []byte{0x64, 0x02, 0x00, 0x20}) {
		t.Fatalf("Attach Accept missing RestrictDCNR EPS Network Feature Support IE: %x", nasPDU[6:])
	}
}

func TestAttachAcceptOmitsRestrictDCNRWhenUEDidNotDeclareSupport(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.12:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := setupAttachAcceptTestUE(t, srv, remoteAddr, noDCNRUENetworkCapability, gateway.AccessRestrictNRAsSecondaryRATInEUTRAN)

	srv.HandleCSRResult(ue.MMEUES1APID, &gtpv2.CreateSessionResponse{
		Cause:     gtpv2.CauseRequestAccepted,
		SGWC_TEID: 0x100,
		SGWC_IP:   net.ParseIP("10.0.0.2"),
		SGWU_TEID: 0x200,
		SGWU_IP:   net.ParseIP("10.0.0.3"),
		UEIPv4:    net.ParseIP("10.45.0.10"),
		EBI:       5,
	}, nil)

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromInitialContextSetup(t, msg)
	if bytes.Contains(nasPDU[6:], []byte{0x64, 0x02, 0x00, 0x20}) {
		t.Fatalf("Attach Accept unexpectedly set RestrictDCNR for a UE that never declared DCNR support: %x", nasPDU[6:])
	}
}

func TestAttachAcceptOmitsRestrictDCNRWhenHSSDoesNotRestrict(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.13:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := setupAttachAcceptTestUE(t, srv, remoteAddr, dcnrCapableUENetworkCapability, 0)

	srv.HandleCSRResult(ue.MMEUES1APID, &gtpv2.CreateSessionResponse{
		Cause:     gtpv2.CauseRequestAccepted,
		SGWC_TEID: 0x100,
		SGWC_IP:   net.ParseIP("10.0.0.2"),
		SGWU_TEID: 0x200,
		SGWU_IP:   net.ParseIP("10.0.0.3"),
		UEIPv4:    net.ParseIP("10.45.0.10"),
		EBI:       5,
	}, nil)

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromInitialContextSetup(t, msg)
	if bytes.Contains(nasPDU[6:], []byte{0x64, 0x02, 0x00, 0x20}) {
		t.Fatalf("Attach Accept unexpectedly set RestrictDCNR when HSS did not restrict: %x", nasPDU[6:])
	}
}

func TestInitialContextSetupIncludesHandoverRestrictionListWhenNRRestricted(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.14:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x010206
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0xf0}
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.TAI = tai
	ue.AccessRestrictionData = gateway.AccessRestrictNRAsSecondaryRATInEUTRAN

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x01020304, SGWU_IP: []byte{10, 0, 0, 1}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}

	var got []byte
	found := false
	for _, ie := range ieList {
		if ie.ID == pdu.IEHandoverRestrictionList {
			got = ie.Value
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Initial Context Setup Request missing Handover Restriction List IE")
	}
	gotPLMN, nrRestricted, err := ies.DecodeHandoverRestrictionList(got)
	if err != nil {
		t.Fatalf("DecodeHandoverRestrictionList: %v", err)
	}
	if gotPLMN != tai.PLMN {
		t.Fatalf("servingPLMN got %x, want %x", gotPLMN, tai.PLMN)
	}
	if !nrRestricted {
		t.Fatal("nrRestricted got false, want true")
	}
}

func TestInitialContextSetupOmitsHandoverRestrictionListWhenNotRestricted(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.15:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x010207
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0xf0}
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.TAI = tai

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x01020304, SGWU_IP: []byte{10, 0, 0, 1}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}

	for _, ie := range ieList {
		if ie.ID == pdu.IEHandoverRestrictionList {
			t.Fatal("Initial Context Setup Request unexpectedly includes Handover Restriction List IE")
		}
	}
}
