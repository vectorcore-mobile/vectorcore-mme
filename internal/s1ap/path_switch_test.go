package s1ap

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// ── Mock S11 with configurable MBR result ────────────────────────────────────

type mbrMockS11 struct {
	mu       sync.Mutex
	mbrErr   error    // error returned from SendMBR (nil = success)
	mbrCalls []uint32 // mmeUEIDs passed to SendMBR
	reqs     []*gtpv2.ModifyBearerRequest
}

func (m *mbrMockS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (m *mbrMockS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }
func (m *mbrMockS11) SendMBR(mmeUEID uint32, req *gtpv2.ModifyBearerRequest) error {
	m.mu.Lock()
	m.mbrCalls = append(m.mbrCalls, mmeUEID)
	m.reqs = append(m.reqs, req)
	err := m.mbrErr
	m.mu.Unlock()
	return err
}

func newMBRMock(mbrErr error) *mbrMockS11 {
	return &mbrMockS11{mbrErr: mbrErr}
}

// ── Test helpers ─────────────────────────────────────────────────────────────

// makeConnectedUEWithBearer creates an EMM-REGISTERED + ECM-CONNECTED UE with a full S11 session.
func makeConnectedUEWithBearer(srv *Server, addr string) *uecontext.Context {
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBS1APID = 100
	ue.IMSI = "001010099900042"
	ue.DefaultEBI = 5
	ue.SGWC_TEID = 0xAABB1122
	ue.SGWC_IP = net.ParseIP("10.99.1.1").To4()
	ue.SGWU_TEID = 0xCCDD3344
	ue.SGWU_IP = net.ParseIP("10.99.1.2").To4()
	ue.ENBU_TEID = 0xDEAD0001
	ue.ENBU_IP = net.ParseIP("10.0.0.1").To4()
	ue.UEIPv4 = net.ParseIP("10.1.2.3").To4()
	ue.KASME = make([]byte, 32)
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	// Pre-computed NH/NCC (would normally be set by SendInitialContextSetup)
	ue.NH = bytes.Repeat([]byte{0xAB}, 32)
	ue.NCC = 1
	ue.Unlock()
	return ue
}

func buildPathSwitchUplinkListBytes(bearers ...pathSwitchBearer) []byte {
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, int64(len(bearers)), 1, 256)
	ow.AlignToByte()
	for _, bearer := range bearers {
		iw := aper.NewBitWriter()
		iw.WriteBit(0)
		iw.WriteBit(0)
		_ = aper.EncodeConstrainedWholeNumber(iw, int64(bearer.EBI), 0, 15)
		iw.WriteBit(0)
		_ = aper.EncodeConstrainedWholeNumber(iw, 32, 1, 160)
		iw.AlignToByte()
		ipv4 := bearer.IP.To4()
		if ipv4 == nil {
			ipv4 = []byte{0, 0, 0, 0}
		}
		iw.WriteOctets(ipv4)
		iw.AlignToByte()
		iw.WriteOctet(byte(bearer.TEID >> 24))
		iw.WriteOctet(byte(bearer.TEID >> 16))
		iw.WriteOctet(byte(bearer.TEID >> 8))
		iw.WriteOctet(byte(bearer.TEID))
		itemBody := iw.Bytes()

		innerIE := pdu.EncodeIEContainer([]pdu.ProtocolIE{
			{ID: 176, Criticality: aper.CriticalityIgnore, Value: itemBody},
		})
		if len(innerIE) >= 2 {
			innerIE = innerIE[2:]
		}
		ow.WriteOctets(innerIE)
	}
	return ow.Bytes()
}

// buildPathSwitchIEList constructs the top-level IE list for a Path Switch Request PDU.
func buildPathSwitchIEList(mmeUEID, enbUEID uint32, ebi uint8, teid uint32, ip net.IP) []pdu.ProtocolIE {
	uplinkList := buildPathSwitchUplinkListBytes(pathSwitchBearer{EBI: ebi, TEID: teid, IP: ip})
	return []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IEERABToBeSwitchedInUplinkList, Criticality: aper.CriticalityReject, Value: uplinkList},
	}
}

func buildPathSwitchIEListMulti(mmeUEID, enbUEID uint32, bearers ...pathSwitchBearer) []pdu.ProtocolIE {
	uplinkList := buildPathSwitchUplinkListBytes(bearers...)
	return []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IEERABToBeSwitchedInUplinkList, Criticality: aper.CriticalityReject, Value: uplinkList},
	}
}

// drain reads all available items from ch with a short timeout.
func drainPS(ch chan []byte) [][]byte {
	var out [][]byte
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case b := <-ch:
			out = append(out, b)
		case <-deadline:
			return out
		}
	}
}

// newPathSwitchTestServer creates a server with a configurable S11 mock.
func newPathSwitchTestServer(s11 S11Client) *Server {
	srv := newTestServer(s11)
	return srv
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestPathSwitch_UENotFound(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.1:36412"
	ch := setupSendCapture(srv, addr)

	ieList := buildPathSwitchIEList(0xDEAD, 200, 5, 0x11223344, net.ParseIP("10.0.1.1"))
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	// Should receive a Failure PDU
	select {
	case raw := <-ch:
		if len(raw) < 4 {
			t.Fatal("Failure PDU too short")
		}
		// PDU type byte: UnsuccessfulOutcome = 0x40
		if raw[0] != 0x40 {
			t.Errorf("expected UnsuccessfulOutcome PDU (0x40), got 0x%02X", raw[0])
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("no Failure PDU received for unknown UE")
	}

	if len(mock.mbrCalls) != 0 {
		t.Errorf("MBR should not be called for unknown UE; got %d calls", len(mock.mbrCalls))
	}
}

func TestPathSwitch_NoBearer(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.2:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.SGWC_TEID = 0 // no bearer
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := buildPathSwitchIEList(mmeID, 201, 5, 0x11223344, net.ParseIP("10.0.1.1"))
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	select {
	case raw := <-ch:
		if len(raw) < 4 || raw[0] != 0x40 {
			t.Errorf("expected UnsuccessfulOutcome PDU, got %02X...", raw[0])
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("no Failure PDU received for UE without bearer")
	}
}

func TestPathSwitch_S11Success(t *testing.T) {
	mock := newMBRMock(nil) // MBR succeeds
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.3:36412"
	ch := setupSendCapture(srv, addr)

	ue := makeConnectedUEWithBearer(srv, addr)
	mmeID := ue.MMEUES1APID
	const newENBUEID uint32 = 300
	newTEID := uint32(0x99887766)
	newIP := net.ParseIP("10.1.2.99").To4()

	ieList := buildPathSwitchIEList(mmeID, newENBUEID, 5, newTEID, newIP)
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	// Expect Ack PDU (SuccessfulOutcome = 0x20)
	var ackPDU []byte
	select {
	case ackPDU = <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no Ack PDU received after successful Path Switch")
	}
	if len(ackPDU) < 4 || ackPDU[0] != 0x20 {
		t.Errorf("expected SuccessfulOutcome PDU (0x20), got 0x%02X", ackPDU[0])
	}

	// Verify SecurityContext IE (119 = 0x0077) is present in the PDU.
	found := false
	for i := 0; i+1 < len(ackPDU); i++ {
		if uint16(ackPDU[i])<<8|uint16(ackPDU[i+1]) == pdu.IESecurityContext {
			found = true
			break
		}
	}
	if !found {
		t.Error("SecurityContext IE (119) not found in Path Switch Ack PDU")
	}

	// Verify UE context was updated.
	ue.Lock()
	updatedENBUEID := ue.ENBS1APID
	updatedTEID := ue.ENBU_TEID
	updatedIP := ue.ENBU_IP
	ue.Unlock()

	if updatedENBUEID != newENBUEID {
		t.Errorf("ENBS1APID: got %d, want %d", updatedENBUEID, newENBUEID)
	}
	if updatedTEID != newTEID {
		t.Errorf("ENBU_TEID: got %#x, want %#x", updatedTEID, newTEID)
	}
	if !updatedIP.Equal(newIP) {
		t.Errorf("ENBU_IP: got %v, want %v", updatedIP, newIP)
	}

	if len(mock.mbrCalls) != 1 || mock.mbrCalls[0] != mmeID {
		t.Errorf("MBR calls: got %v, want [%d]", mock.mbrCalls, mmeID)
	}
	if len(mock.reqs) != 1 || len(mock.reqs[0].Bearers) != 1 {
		t.Fatalf("MBR bearer count: got %+v", mock.reqs)
	}
	if got := mock.reqs[0].Bearers[0]; got.EBI != 5 || got.ENBU_TEID != newTEID || !got.ENBU_IP.Equal(newIP) {
		t.Errorf("MBR bearer: got %+v", got)
	}
}

func TestPathSwitch_IncludesHandoverRestrictionListWhenNRRestricted(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.5:36412"
	ch := setupSendCapture(srv, addr)

	ue := makeConnectedUEWithBearer(srv, addr)
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.Lock()
	ue.TAI = tai
	ue.AccessRestrictionData = gateway.AccessRestrictNRAsSecondaryRATInEUTRAN
	ue.Unlock()
	mmeID := ue.MMEUES1APID

	ieList := buildPathSwitchIEList(mmeID, 300, 5, 0x99887766, net.ParseIP("10.1.2.99").To4())
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	var ackPDU []byte
	select {
	case ackPDU = <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no Ack PDU received after successful Path Switch")
	}
	p, err := pdu.Decode(ackPDU)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	gotIEs, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}
	var got []byte
	found := false
	for _, ie := range gotIEs {
		if ie.ID == pdu.IEHandoverRestrictionList {
			got = ie.Value
			found = true
		}
	}
	if !found {
		t.Fatal("Path Switch Ack missing Handover Restriction List IE")
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

func TestPathSwitch_OmitsHandoverRestrictionListWhenNotRestricted(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.6:36412"
	ch := setupSendCapture(srv, addr)

	ue := makeConnectedUEWithBearer(srv, addr)
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.Lock()
	ue.TAI = tai
	ue.Unlock()
	mmeID := ue.MMEUES1APID

	ieList := buildPathSwitchIEList(mmeID, 300, 5, 0x99887766, net.ParseIP("10.1.2.99").To4())
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	var ackPDU []byte
	select {
	case ackPDU = <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no Ack PDU received after successful Path Switch")
	}
	p, err := pdu.Decode(ackPDU)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	gotIEs, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}
	for _, ie := range gotIEs {
		if ie.ID == pdu.IEHandoverRestrictionList {
			t.Fatal("Path Switch Ack unexpectedly includes Handover Restriction List IE")
		}
	}
}

func TestPathSwitch_S11Failure(t *testing.T) {
	mock := newMBRMock(errors.New("s11: S-GW unreachable"))
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.4:36412"
	ch := setupSendCapture(srv, addr)

	ue := makeConnectedUEWithBearer(srv, addr)
	mmeID := ue.MMEUES1APID
	oldTEID := uint32(0xDEAD0001)
	oldIP := net.ParseIP("10.0.0.1").To4()

	ieList := buildPathSwitchIEList(mmeID, 400, 5, 0x55443322, net.ParseIP("10.1.99.1"))
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	// Expect Failure PDU
	select {
	case raw := <-ch:
		if len(raw) < 4 || raw[0] != 0x40 {
			t.Errorf("expected UnsuccessfulOutcome (0x40), got 0x%02X", raw[0])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no Failure PDU received after S11 error")
	}

	// UE context must be unchanged.
	ue.Lock()
	teid := ue.ENBU_TEID
	ip := ue.ENBU_IP
	ue.Unlock()
	if teid != oldTEID {
		t.Errorf("ENBU_TEID changed on MBR failure: got %#x, want %#x", teid, oldTEID)
	}
	if !ip.Equal(oldIP) {
		t.Errorf("ENBU_IP changed on MBR failure: got %v, want %v", ip, oldIP)
	}
}

func TestPathSwitch_MultiBearerSuccess(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.6:36412"
	ch := setupSendCapture(srv, addr)

	ue := makeConnectedUEWithBearer(srv, addr)
	mmeID := ue.MMEUES1APID

	ue.Lock()
	ue.PDNs["internet"] = &uecontext.PDNContext{
		APN:             "internet",
		DefaultEBI:      ue.DefaultEBI,
		SGWU_TEID:       ue.SGWU_TEID,
		SGWU_IP:         append(net.IP(nil), ue.SGWU_IP...),
		ERABEstablished: true,
	}
	ue.DedicatedBearers[6] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     6,
		LinkedEBI:       ue.DefaultEBI,
		SGWS1UTEID:      0x44556677,
		SGWS1UIP:        net.ParseIP("10.99.1.3").To4(),
		ERABEstablished: true,
	}
	ue.Unlock()

	defaultBearer := pathSwitchBearer{EBI: 5, TEID: 0x01020304, IP: net.ParseIP("10.10.0.1").To4()}
	dedicatedBearer := pathSwitchBearer{EBI: 6, TEID: 0x05060708, IP: net.ParseIP("10.10.0.2").To4()}
	ieList := buildPathSwitchIEListMulti(mmeID, 600, defaultBearer, dedicatedBearer)
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	select {
	case raw := <-ch:
		if len(raw) < 4 || raw[0] != 0x20 {
			t.Fatalf("expected SuccessfulOutcome PDU, got %02X", raw[0])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no Ack PDU received after multi-bearer Path Switch")
	}

	if len(mock.reqs) != 1 {
		t.Fatalf("expected one MBR, got %d", len(mock.reqs))
	}
	if len(mock.reqs[0].Bearers) != 2 {
		t.Fatalf("expected two bearer updates, got %d", len(mock.reqs[0].Bearers))
	}
	if mock.reqs[0].Bearers[0].EBI != 5 || mock.reqs[0].Bearers[1].EBI != 6 {
		t.Fatalf("unexpected bearer EBIs: %+v", mock.reqs[0].Bearers)
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.ENBU_TEID != defaultBearer.TEID || !ue.ENBU_IP.Equal(defaultBearer.IP) {
		t.Fatalf("default bearer root state not updated: teid=%#x ip=%v", ue.ENBU_TEID, ue.ENBU_IP)
	}
	if pdn := ue.PDNs["internet"]; pdn == nil || pdn.ENBU_TEID != defaultBearer.TEID || !pdn.ENBU_IP.Equal(defaultBearer.IP) {
		t.Fatalf("pdn bearer state not updated: %+v", pdn)
	}
	if bearer := ue.DedicatedBearers[6]; bearer == nil || bearer.ENBS1UTEID != dedicatedBearer.TEID || !bearer.ENBS1UIP.Equal(dedicatedBearer.IP) {
		t.Fatalf("dedicated bearer state not updated: %+v", bearer)
	}
}

func TestPathSwitch_NH_Advanced(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.0.5:36412"
	setupSendCapture(srv, addr)

	ue := makeConnectedUEWithBearer(srv, addr)
	mmeID := ue.MMEUES1APID

	ue.Lock()
	origNH := append([]byte(nil), ue.NH...)
	origNCC := ue.NCC
	ue.Unlock()

	ieList := buildPathSwitchIEList(mmeID, 500, 5, 0xAABBCCDD, net.ParseIP("10.2.3.4"))
	srv.handlePathSwitchRequest(addr, &pdu.PDU{ProcedureCode: pdu.ProcPathSwitchRequest}, ieList)

	// Wait for the goroutine to complete (Ack gets sent).
	time.Sleep(300 * time.Millisecond)

	ue.Lock()
	newNH := ue.NH
	newNCC := ue.NCC
	kasme := ue.KASME
	ue.Unlock()

	// NCC must have incremented mod 8.
	wantNCC := (origNCC + 1) % 8
	if newNCC != wantNCC {
		t.Errorf("NCC: got %d, want %d", newNCC, wantNCC)
	}

	// NH must have changed (derived from orig NH).
	expectedNextNH, err := security.DeriveNH(kasme, origNH)
	if err != nil {
		t.Fatalf("DeriveNH failed: %v", err)
	}
	if !bytes.Equal(newNH, expectedNextNH) {
		t.Errorf("NH not correctly advanced after path switch")
	}
}

// ── Unit tests for encode/decode helpers ─────────────────────────────────────

func TestDecodePathSwitchERABs_IPv4(t *testing.T) {
	wantEBI := uint8(5)
	wantTEID := uint32(0xCAFEBEEF)
	wantIP := net.ParseIP("192.168.1.99").To4()

	data := buildPathSwitchUplinkListBytes(pathSwitchBearer{EBI: wantEBI, TEID: wantTEID, IP: wantIP})
	ebi, teid, ip, err := decodePathSwitchERABs(data)
	if err != nil {
		t.Fatalf("decodePathSwitchERABs error: %v", err)
	}
	if ebi != wantEBI {
		t.Errorf("ebi: got %d, want %d", ebi, wantEBI)
	}
	if teid != wantTEID {
		t.Errorf("teid: got %#x, want %#x", teid, wantTEID)
	}
	if !ip.Equal(wantIP) {
		t.Errorf("ip: got %v, want %v", ip, wantIP)
	}
}

func TestDecodePathSwitchERABs_Empty(t *testing.T) {
	_, _, _, err := decodePathSwitchERABs(nil)
	if err == nil {
		t.Error("expected error for nil data, got nil")
	}
	_, _, _, err = decodePathSwitchERABs([]byte{})
	if err == nil {
		t.Error("expected error for empty data, got nil")
	}
}

func TestEncodeSecurityContextIE(t *testing.T) {
	nh := bytes.Repeat([]byte{0xAA}, 32)
	ncc := uint8(3)
	b := encodeSecurityContextIE(nh, ncc)

	// Expected layout:
	//   The fixed-size BIT STRING follows immediately after the 3-bit NCC, so there is
	//   no byte alignment between nextHopChainingCount and nextHopParameter.
	//   For NH bytes 0xAA = 10101010..., the first output octet is:
	//   [ext=0][opt=0][ncc=011][nh bits 101] = 0b00011101 = 0x1D
	//   The shifted 0xAA bitstream then yields 0x55 bytes and a final 0x50 pad octet.
	if len(b) != 33 {
		t.Fatalf("length: got %d, want 33", len(b))
	}
	if b[0] != 0x1D {
		t.Errorf("byte[0]: got 0x%02X, want 0x1D", b[0])
	}
	for i := 1; i < 32; i++ {
		if b[i] != 0x55 {
			t.Errorf("shifted NH byte[%d]: got 0x%02X, want 0x55", i, b[i])
		}
	}
	if b[32] != 0x50 {
		t.Errorf("final padded byte: got 0x%02X, want 0x50", b[32])
	}
}

func TestEncodeSecurityContextIE_NCC0(t *testing.T) {
	nh := make([]byte, 32) // all zeros
	b := encodeSecurityContextIE(nh, 0)
	if len(b) != 33 {
		t.Fatalf("length: got %d, want 33", len(b))
	}
	// ncc=0: byte[0] = 0b00000000 = 0x00
	if b[0] != 0x00 {
		t.Errorf("byte[0] for NCC=0: got 0x%02X, want 0x00", b[0])
	}
}

func TestEncodeSecurityContextIE_NCC7(t *testing.T) {
	nh := make([]byte, 32)
	b := encodeSecurityContextIE(nh, 7)
	if len(b) != 33 {
		t.Fatalf("length: got %d, want 33", len(b))
	}
	// ncc=7=0b111: byte[0] = [0][0][1][1][1][0][0][0] = 0x38
	if b[0] != 0x38 {
		t.Errorf("byte[0] for NCC=7: got 0x%02X, want 0x38", b[0])
	}
}

func TestDeriveNH_ChainedDerivation(t *testing.T) {
	kasme := make([]byte, 32)
	for i := range kasme {
		kasme[i] = byte(i)
	}
	// First NH from KeNB (KeNB = all zeros for simplicity)
	keNB := make([]byte, 32)
	nh1, err := security.DeriveNH(kasme, keNB)
	if err != nil {
		t.Fatalf("DeriveNH(kasme, keNB): %v", err)
	}
	if len(nh1) != 32 {
		t.Fatalf("DeriveNH output length: got %d, want 32", len(nh1))
	}

	// Second NH from NH1
	nh2, err := security.DeriveNH(kasme, nh1)
	if err != nil {
		t.Fatalf("DeriveNH(kasme, nh1): %v", err)
	}
	if bytes.Equal(nh1, nh2) {
		t.Error("consecutive NH values must differ")
	}
}

func TestDeriveNH_InvalidLength(t *testing.T) {
	_, err := security.DeriveNH(make([]byte, 16), make([]byte, 32))
	if err == nil {
		t.Error("expected error for short KASME")
	}
	_, err = security.DeriveNH(make([]byte, 32), make([]byte, 16))
	if err == nil {
		t.Error("expected error for short syncInput")
	}
}

func TestPathSwitch_MetricsDoNotPanic(t *testing.T) {
	// Verifies metric label calls don't panic.
	srv := newPathSwitchTestServer(newMBRMock(nil))
	const addr = "10.20.0.99:36412"
	setupSendCapture(srv, addr)

	// Unknown UE — triggers ue_not_found label.
	srv.handlePathSwitchRequest(addr, &pdu.PDU{}, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(0)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(0)},
	})
	// No panic = pass.
}

func TestPathSwitch_DecodeRoundtrip(t *testing.T) {
	// Build bytes for several EBIs and confirm round-trip decode.
	cases := []struct {
		ebi  uint8
		teid uint32
		ip   net.IP
	}{
		{5, 0x00000001, net.ParseIP("10.0.0.1").To4()},
		{0, 0xFFFFFFFF, net.ParseIP("192.168.255.255").To4()},
		{15, 0xABCD1234, net.ParseIP("172.16.0.42").To4()},
	}
	for _, tc := range cases {
		data := buildPathSwitchUplinkListBytes(pathSwitchBearer{EBI: tc.ebi, TEID: tc.teid, IP: tc.ip})
		gotEBI, gotTEID, gotIP, err := decodePathSwitchERABs(data)
		if err != nil {
			t.Errorf("ebi=%d: decode error: %v", tc.ebi, err)
			continue
		}
		if gotEBI != tc.ebi {
			t.Errorf("ebi=%d: got %d", tc.ebi, gotEBI)
		}
		if gotTEID != tc.teid {
			t.Errorf("ebi=%d: teid got %#x, want %#x", tc.ebi, gotTEID, tc.teid)
		}
		if !gotIP.Equal(tc.ip) {
			t.Errorf("ebi=%d: ip got %v, want %v", tc.ebi, gotIP, tc.ip)
		}
	}
}

func TestDecodePathSwitchERABList_MultiItem(t *testing.T) {
	want := []pathSwitchBearer{
		{EBI: 5, TEID: 0x11111111, IP: net.ParseIP("10.0.0.1").To4()},
		{EBI: 6, TEID: 0x22222222, IP: net.ParseIP("10.0.0.2").To4()},
	}
	got, err := decodePathSwitchERABList(buildPathSwitchUplinkListBytes(want...))
	if err != nil {
		t.Fatalf("decodePathSwitchERABList error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d bearers, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].EBI != want[i].EBI || got[i].TEID != want[i].TEID || !got[i].IP.Equal(want[i].IP) {
			t.Fatalf("bearer[%d]: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestHandleDisconnect_DoesNotEvictHandoverUE(t *testing.T) {
	// After a path switch, the UE is on a new eNB (addr2). Disconnect of addr1
	// (old eNB) must not evict the UE.
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr1 = "10.20.1.1:36412"
	const addr2 = "10.20.1.2:36412"
	registerTestENB(srv, addr1)
	registerTestENB(srv, addr2)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr2 // UE is now on addr2 after handover
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.SGWC_TEID = 0xBEEF0001
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	srv.handleDisconnect(addr1) // disconnect the OLD eNB

	// UE must still be in the manager (it belongs to addr2)
	if _, ok := srv.ueManager.GetByMMEID(mmeID); !ok {
		t.Fatal("UE evicted when old eNB (addr1) disconnected; UE was already on addr2")
	}
	if len(mock.dsrCalls) != 0 {
		t.Errorf("DSR called when unrelated eNB disconnected: %d calls", len(mock.dsrCalls))
	}
}

// TestSendInitialContextSetup_DeriveNH checks that SendInitialContextSetup stores NH+NCC.
// Uses a UE with a pre-populated KASME and verifies the side-effect on ue.NH / ue.NCC.
func TestSendInitialContextSetup_DeriveNH(t *testing.T) {
	mock := newMBRMock(nil)
	srv := newPathSwitchTestServer(mock)
	const addr = "10.20.2.1:36412"
	setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 99
	ue.EMMState = emm.StateRegistered
	ue.KASME = make([]byte, 32) // all zeros — deterministic DeriveKeNB and DeriveNH
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.UENetworkCapability = make([]byte, 2)
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	// SendInitialContextSetup should derive NH and set NCC=1 as a side-effect.
	if err := srv.SendInitialContextSetup(mmeID, nil, &BearerInfo{EBI: 5, SGWU_TEID: 1, SGWU_IP: []byte{10, 0, 0, 1}}); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}

	ue.Lock()
	nh := ue.NH
	ncc := ue.NCC
	ue.Unlock()

	if len(nh) != 32 {
		t.Errorf("NH length after ICS: got %d, want 32", len(nh))
	}
	if ncc != 1 {
		t.Errorf("NCC after ICS: got %d, want 1", ncc)
	}
}

// TestUEContextRelease_PreservesNH verifies that handleUEContextReleaseComplete
// (going ECM-IDLE) keeps NH/NCC intact for future re-connection.
func TestUEContextRelease_PreservesNH(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.20.3.1:36412"
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "001010099900099"
	ue.SGWC_TEID = 0xBEEF1234
	ue.DefaultEBI = 5
	ue.NH = bytes.Repeat([]byte{0xCC}, 32)
	ue.NCC = 3
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
	}
	srv.handleUEContextReleaseComplete(addr, nil, ieList)

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE removed from manager (expected ECM-IDLE retention)")
	}
	found.Lock()
	nh := found.NH
	ncc := found.NCC
	found.Unlock()
	if len(nh) != 32 || nh[0] != 0xCC {
		t.Errorf("NH not preserved on ECM-IDLE: %v", nh)
	}
	if ncc != 3 {
		t.Errorf("NCC not preserved on ECM-IDLE: got %d, want 3", ncc)
	}
}

// Ensure uecontext.Context has NH/NCC fields (compile check).
var _ = func() {
	ue := &uecontext.Context{}
	_ = ue.NH
	_ = ue.NCC
}
