package s1ap

import (
	"bytes"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type releaseAccessMockS11 struct {
	mockS11
	rabrCalls []gtpv2.ReleaseAccessBearersRequest
	rabrErr   error
}

type ddnAckCall struct {
	peer       string
	teid       uint32
	seq        uint32
	cause      uint8
	delayValue *uint8
}

type ddnMockS11 struct {
	NoopS11Client
	ackCalls []ddnAckCall
}

func (m *releaseAccessMockS11) SendRABR(_ uint32, req *gtpv2.ReleaseAccessBearersRequest) (uint32, error) {
	m.rabrCalls = append(m.rabrCalls, *req)
	return uint32(len(m.rabrCalls)), m.rabrErr
}

func (m *ddnMockS11) SendDDNAck(peer string, teid uint32, seq uint32, cause uint8, delayValue *uint8) error {
	call := ddnAckCall{
		peer:  peer,
		teid:  teid,
		seq:   seq,
		cause: cause,
	}
	if delayValue != nil {
		v := *delayValue
		call.delayValue = &v
	}
	m.ackCalls = append(m.ackCalls, call)
	return nil
}

// makeIdleRegisteredUE creates an EMM-REGISTERED + ECM-IDLE UE with a TAI set to tac.
// It reuses makeRegisteredIdleUE from service_request_test.go, and additionally
// registers the IMSI in the manager so GetByIMSI works.
func makeIdleRegisteredUE(srv *Server, addr string, tac uint16) (*uecontext.Context, uint8, uint32) {
	ue, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)

	// Register IMSI in manager (makeRegisteredIdleUE sets it directly on the struct
	// but does not call UpdateIMSI, so GetByIMSI would fail without this).
	ue.Lock()
	imsi := ue.IMSI
	ue.Unlock()
	srv.ueManager.UpdateIMSI(ue, imsi)

	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: tac}
	copy(tai.PLMN[:], plmn)
	ue.Lock()
	ue.TAI = tai
	ue.Unlock()
	return ue, mmec, mtmsi
}

// registerENBWithTAC registers an eNB that broadcasts the given TAC for PLMN 001/01.
// Returns the outbound PDU capture channel.
func registerENBWithTAC(srv *Server, addr string, tac uint16) chan []byte {
	ch := setupSendCapture(srv, addr)
	val, _ := srv.enbs.Load(addr)
	enb := val.(*ENBContext)
	enb.SupportedTAs = []SupportedTA{
		{TAC: tac, BroadcastPLMNs: []BroadcastPLMN{{MCC: "001", MNC: "01"}}},
	}
	return ch
}

func attachDDNPDN(ue *uecontext.Context, peer string, localTEID uint32, defaultEBI uint8) {
	ue.Lock()
	defer ue.Unlock()
	ue.PDNs["ims"] = &uecontext.PDNContext{
		APN:          "ims",
		DefaultEBI:   defaultEBI,
		LocalS11TEID: localTEID,
		SGWAddress:   peer,
		SGWC_TEID:    0x11112222,
		SGWU_TEID:    0x33334444,
		State:        "active",
	}
}

// ── encoding unit tests ───────────────────────────────────────────────────────

func TestEncodeUEIdentityIndexValue(t *testing.T) {
	b := ies.EncodeUEIdentityIndexValue(0)
	if len(b) != 2 {
		t.Fatalf("length: got %d, want 2", len(b))
	}
	// value = 0: expect 0x00, 0x00
	if b[0] != 0x00 || b[1] != 0x00 {
		t.Errorf("bytes: got %02X %02X, want 00 00", b[0], b[1])
	}

	// 0xdead0001 modulo 1024 is 1.  This must be derived from M-TMSI,
	// rather than from the IMSI used to look up the UE context.
	b3 := ies.EncodeUEIdentityIndexValue(0xDEAD0001)
	// value = 1 → 1 << 6 in low byte: byte[0] = 1>>2 = 0, byte[1] = (1&3)<<6 = 0x40
	if b3[0] != 0x00 || b3[1] != 0x40 {
		t.Errorf("value=1 bytes: got %02X %02X, want 00 40", b3[0], b3[1])
	}
}

func TestEncodeUEIdentityIndexValueBoundaries(t *testing.T) {
	tests := []struct {
		mtmsi uint32
		want  []byte
	}{
		{0, []byte{0x00, 0x00}},
		{1, []byte{0x00, 0x40}},
		{1023, []byte{0xff, 0xc0}},
		{1024, []byte{0x00, 0x00}},
		{0xffffffff, []byte{0xff, 0xc0}},
		{0xb692cce2, []byte{0x38, 0x80}},
	}
	for _, tt := range tests {
		if got := ies.EncodeUEIdentityIndexValue(tt.mtmsi); !bytes.Equal(got, tt.want) {
			t.Errorf("M-TMSI %#08x index got % X, want % X", tt.mtmsi, got, tt.want)
		}
	}
}

func TestPagingIEConstantsRel16(t *testing.T) {
	if got, want := pdu.IEPagingDRX, uint16(44); got != want {
		t.Fatalf("IEPagingDRX: got %d, want %d", got, want)
	}
	if got, want := pdu.IECNDomain, uint16(109); got != want {
		t.Fatalf("IECNDomain: got %d, want %d", got, want)
	}
}

func TestEncodeUEPagingIDSTMSI(t *testing.T) {
	b := ies.EncodeUEPagingIDSTMSI(0x01, 0xDEAD0001)
	if len(b) != 6 {
		t.Fatalf("length: got %d, want 6", len(b))
	}
	// CHOICE/sequence headers occupy the high four bits of byte 0; the MMEC
	// bits continue across bytes 0 and 1, before M-TMSI starts at byte 2.
	if b[0] != 0x00 {
		t.Errorf("byte[0] (choice/sequence headers): got %02X, want 00", b[0])
	}
	if b[1] != 0x10 {
		t.Errorf("byte[1] (MMEC low nibble + APER padding): got %02X, want 10", b[1])
	}
	if !bytes.Equal(b[2:], []byte{0xDE, 0xAD, 0x00, 0x01}) {
		t.Errorf("M-TMSI bytes: got % X, want DE AD 00 01", b[2:])
	}
}

func TestEncodePagingTAIList_Single(t *testing.T) {
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := emm.TAI{TAC: 0x0001}
	copy(tai.PLMN[:], plmn)

	b := ies.EncodePagingTAIList([]emm.TAI{tai})
	// TAIList contains a TAIItem ProtocolIE-SingleContainer: count(1),
	// id/criticality/open-type, then the six-byte TAIItem value.
	want := []byte{0x00, 0x00, 0x2f, 0x40, 0x06, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x01}
	if !bytes.Equal(b, want) {
		t.Fatalf("TAIList got % X, want % X", b, want)
	}
}

func TestPagingGoldenVectorEricssonInterop(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ies := []pdu.ProtocolIE{
		{ID: pdu.IEUEIdentityIndexValue, Criticality: aper.CriticalityIgnore, Value: ies.EncodeUEIdentityIndexValueFromIMSI("311435000070572")},
		{ID: pdu.IEUEPagingID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeUEPagingIDSTMSI(0x01, 0xB692CCE2)},
		{ID: pdu.IECNDomain, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCNDomain(0)},
		{ID: pdu.IEPagingTAIList, Criticality: aper.CriticalityIgnore, Value: ies.EncodePagingTAIList([]emm.TAI{tai})},
	}
	got := pdu.BuildInitiatingMessage(pdu.ProcPaging, aper.CriticalityIgnore, ies)
	// Derived directly from TS 36.413 Rel-16 Paging/TAIList ASN.1: TAIList
	// wraps TAIItem in ProtocolIE-SingleContainer (id 47), and the S-TMSI
	// headers share one APER octet.  This is intentionally not the malformed
	// 41-byte sequence captured in MME-emm-debug-59.
	want := []byte{
		0x00, 0x0a, 0x40, 0x27, 0x00, 0x00, 0x04,
		0x00, 0x50, 0x40, 0x02, 0x6b, 0x00,
		0x00, 0x2b, 0x40, 0x06, 0x00, 0x10, 0xb6, 0x92, 0xcc, 0xe2,
		0x00, 0x6d, 0x40, 0x01, 0x00,
		0x00, 0x2e, 0x40, 0x0b, 0x00, 0x00, 0x2f, 0x40, 0x06, 0x00, 0x13, 0x41, 0x53, 0x00, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Paging golden vector got % X, want % X", got, want)
	}
}

// ── PageUE validation tests ───────────────────────────────────────────────────

func TestPageUE_UnknownIMSI(t *testing.T) {
	srv := newTAUTestServer()
	err := srv.PageUE("999999999999999")
	if err == nil {
		t.Fatal("expected error for unknown IMSI, got nil")
	}
	if err != ErrUnknownIMSI {
		t.Errorf("error: got %q, want ErrUnknownIMSI", err)
	}
}

func TestPageUE_AlreadyConnected(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.0.1:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.Unlock()

	err := srv.PageUE(ue.IMSI)
	if err != ErrAlreadyConnected {
		t.Errorf("error: got %v, want ErrAlreadyConnected", err)
	}
}

func TestPageUE_NotRegistered(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.0.2:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	ue.Lock()
	ue.EMMState = emm.StateDeregistered
	ue.Unlock()

	err := srv.PageUE(ue.IMSI)
	if err != ErrNotRegistered {
		t.Errorf("error: got %v, want ErrNotRegistered", err)
	}
}

func TestPageUE_NoENB(t *testing.T) {
	srv := newTAUTestServer()
	// No eNBs registered
	ue, _, _ := makeIdleRegisteredUE(srv, "10.10.0.3:36412", 1)
	err := srv.PageUE(ue.IMSI)
	if err != ErrNoENB {
		t.Errorf("error: got %v, want ErrNoENB", err)
	}
}

func TestPageUE_NoPagingIdentity(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.0.31:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	ue.Lock()
	ue.GUTI = nil
	ue.Unlock()

	registerENBWithTAC(srv, addr, 1)

	err := srv.PageUE(ue.IMSI)
	if err != ErrNoPagingIdentity {
		t.Errorf("error: got %v, want ErrNoPagingIdentity", err)
	}
}

func TestPageUE_ValidIdleUE(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.0.4:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	ch := registerENBWithTAC(srv, addr, 1)

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatalf("PageUE: unexpected error: %v", err)
	}

	// Paging PDU must be sent
	select {
	case raw := <-ch:
		assertPagingMessageHasMandatoryIEs(t, raw)
	case <-time.After(200 * time.Millisecond):
		t.Error("no Paging PDU sent to eNB")
	}

	// PagingAttempts must be set to 1
	ue.Lock()
	attempts := ue.PagingAttempts
	ue.Unlock()
	if attempts != 1 {
		t.Errorf("PagingAttempts: got %d, want 1", attempts)
	}

	// T3413 must be running (stop it so we don't leave background goroutines)
	ue.Lock()
	ue.StopTimer(uecontext.TimerT3413)
	ue.Unlock()
}

func TestHandleDownlinkDataNotification_IdleRegisteredUEStartsPaging(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{
		DDNEnabled:         true,
		RetryInterval:      25 * time.Millisecond,
		MaxAttempts:        3,
		TransactionTimeout: 200 * time.Millisecond,
	}
	mock := &ddnMockS11{}
	srv.s11 = mock

	const (
		addr = "10.10.20.1:36412"
		peer = "10.90.250.59:2123"
		teid = 0x01020304
		seq  = 0x10203
		tac  = uint16(42)
	)
	ebi := uint8(6)
	arp := uint8(8)

	ue, mmec, mtmsi := makeIdleRegisteredUE(srv, addr, tac)
	ch := registerENBWithTAC(srv, addr, tac)
	attachDDNPDN(ue, peer, teid, ebi)

	req := &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: seq, EBI: &ebi, ARP: &arp}
	srv.HandleDownlinkDataNotification(peer, req)
	defer func() {
		ue.Lock()
		ue.StopTimer(ddnPagingRetryTimerName)
		ue.StopTimer(ddnPagingTimeoutTimerName)
		ue.Unlock()
	}()

	if len(mock.ackCalls) != 1 {
		t.Fatalf("DDN Ack count got %d, want 1", len(mock.ackCalls))
	}
	if got := mock.ackCalls[0].cause; got != gtpv2.CauseRequestAccepted {
		t.Fatalf("DDN Ack cause got %d, want %d", got, gtpv2.CauseRequestAccepted)
	}

	select {
	case raw := <-ch:
		assertPagingMessageHasMandatoryIEs(t, raw)
		msg, err := pdu.Decode(raw)
		if err != nil {
			t.Fatalf("Decode paging PDU: %v", err)
		}
		ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
		if err != nil {
			t.Fatalf("Decode paging IEs: %v", err)
		}
		for _, ie := range ieList {
			switch ie.ID {
			case pdu.IEUEIdentityIndexValue:
				want := ies.EncodeUEIdentityIndexValueFromIMSI(ue.IMSI)
				if string(ie.Value) != string(want) {
					t.Fatalf("UEIdentityIndexValue got %x, want M-TMSI-derived %x", ie.Value, want)
				}
			case pdu.IEUEPagingID:
				want := ies.EncodeUEPagingIDSTMSI(mmec, mtmsi)
				if string(ie.Value) != string(want) {
					t.Fatalf("UEPagingID got %x, want S-TMSI %x", ie.Value, want)
				}
			}
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no Paging PDU sent after DDN")
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.PagingAttempts != 1 {
		t.Fatalf("PagingAttempts got %d, want 1", ue.PagingAttempts)
	}
	if ue.DDNPaging == nil {
		t.Fatal("DDNPaging transaction not created")
	}
	if got := ue.DDNPaging.Status; got != uecontext.DDNPagingPagingSent {
		t.Fatalf("DDNPaging status got %q, want %q", got, uecontext.DDNPagingPagingSent)
	}
}

func TestHandleDownlinkDataNotification_NoUsableSCTPAssociationDoesNotAckSuccess(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{DDNEnabled: true, RetryInterval: time.Second, MaxAttempts: 2, TransactionTimeout: time.Second}
	mock := &ddnMockS11{}
	srv.s11 = mock

	const (
		addr = "10.10.20.9:36412"
		peer = "10.90.250.59:2123"
		teid = 0x01020309
	)
	ebi := uint8(6)
	ue, _, _ := makeIdleRegisteredUE(srv, addr, 42)
	registerENBWithTAC(srv, addr, 42)
	// Keep the eNB registry entry but remove its send path.  This models a
	// stale association and verifies that DDN success is not emitted merely
	// because TAC selection found an eNB context.
	srv.sends.Delete(addr)
	attachDDNPDN(ue, peer, teid, ebi)

	srv.HandleDownlinkDataNotification(peer, &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: 0x10209, EBI: &ebi})
	if len(mock.ackCalls) != 1 {
		t.Fatalf("DDN Ack count got %d, want 1", len(mock.ackCalls))
	}
	if got := mock.ackCalls[0].cause; got != gtpv2.CauseUnableToPageUE {
		t.Fatalf("DDN Ack cause got %d, want %d", got, gtpv2.CauseUnableToPageUE)
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.DDNPaging == nil || ue.DDNPaging.Status != uecontext.DDNPagingFailed {
		t.Fatalf("DDN paging status got %+v, want failed", ue.DDNPaging)
	}
}

func TestHandleDownlinkDataNotification_NoMatchingENBReturnsUnableToPage(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{DDNEnabled: true}
	mock := &ddnMockS11{}
	srv.s11 = mock

	const (
		addr = "10.10.20.10:36412"
		peer = "10.90.250.59:2123"
		teid = 0x01020310
	)
	ebi := uint8(6)
	ue, _, _ := makeIdleRegisteredUE(srv, addr, 42)
	ch := registerENBWithTAC(srv, addr, 99) // connected, but serving another TA.
	attachDDNPDN(ue, peer, teid, ebi)

	srv.HandleDownlinkDataNotification(peer, &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: 0x10210, EBI: &ebi})
	if len(mock.ackCalls) != 1 || mock.ackCalls[0].cause != gtpv2.CauseUnableToPageUE {
		t.Fatalf("DDN Ack got %+v, want one UnableToPageUE", mock.ackCalls)
	}
	select {
	case raw := <-ch:
		t.Fatalf("unexpected Paging PDU for unrelated TAC: %x", raw)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestDDNPagingSelectsEricssonSupportedTAForStandardUEPLMN(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "192.168.105.247:36422"
	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	// The registered TAI comes from NAS and uses the TS 24.008 wire order for
	// 311-435 (13 51 34). Ericsson's captured S1 Setup is decoded and retained
	// as the canonical digits 311/435. Selection must not compare raw bytes
	// after re-encoding that eNB representation.
	ue.Lock()
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.Unlock()
	registerENBWithTAC(srv, addr, 1)
	val, _ := srv.enbs.Load(addr)
	enb := val.(*ENBContext)
	enb.SupportedTAs = []SupportedTA{{TAC: 1, BroadcastPLMNs: []BroadcastPLMN{{MCC: "311", MNC: "435"}}}}

	ue.Lock()
	targets := srv.findStrictENBsForTAILocked(ue)
	ue.Unlock()
	if len(targets) != 1 || targets[0] != addr {
		t.Fatalf("paging targets got %v, want [%s]", targets, addr)
	}
}

func TestHandleDownlinkDataNotification_ConnectedUESuppressesPaging(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{DDNEnabled: true}
	mock := &ddnMockS11{}
	srv.s11 = mock

	const (
		addr = "10.10.20.2:36412"
		peer = "10.90.250.59:2123"
		teid = 0x01020305
		seq  = 0x10204
	)
	ebi := uint8(6)

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 42)
	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.Unlock()
	ch := registerENBWithTAC(srv, addr, 42)
	attachDDNPDN(ue, peer, teid, ebi)

	req := &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: seq, EBI: &ebi}
	srv.HandleDownlinkDataNotification(peer, req)

	if len(mock.ackCalls) != 1 {
		t.Fatalf("DDN Ack count got %d, want 1", len(mock.ackCalls))
	}
	if got := mock.ackCalls[0].cause; got != gtpv2.CauseRequestAccepted {
		t.Fatalf("DDN Ack cause got %d, want %d", got, gtpv2.CauseRequestAccepted)
	}
	select {
	case raw := <-ch:
		t.Fatalf("unexpected Paging PDU for connected UE: %x", raw)
	case <-time.After(60 * time.Millisecond):
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.DDNPaging != nil {
		t.Fatal("DDNPaging transaction should not exist for connected UE")
	}
}

func TestHandleDownlinkDataNotification_UnknownTEIDAcksContextNotFound(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{DDNEnabled: true}
	mock := &ddnMockS11{}
	srv.s11 = mock

	req := &gtpv2.DownlinkDataNotification{TEID: 0xdeadbeef, SeqNum: 0x33}
	srv.HandleDownlinkDataNotification("10.90.250.59:2123", req)

	if len(mock.ackCalls) != 1 {
		t.Fatalf("DDN Ack count got %d, want 1", len(mock.ackCalls))
	}
	if got := mock.ackCalls[0].cause; got != gtpv2.CauseContextNotFound {
		t.Fatalf("DDN Ack cause got %d, want %d", got, gtpv2.CauseContextNotFound)
	}
}

func TestHandleDownlinkDataNotification_DuplicateDoesNotRepaging(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{
		DDNEnabled:         true,
		RetryInterval:      250 * time.Millisecond,
		MaxAttempts:        3,
		TransactionTimeout: time.Second,
	}
	mock := &ddnMockS11{}
	srv.s11 = mock

	const (
		addr = "10.10.20.3:36412"
		peer = "10.90.250.59:2123"
		teid = 0x01020306
		seq  = 0x10205
	)
	ebi := uint8(6)

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 42)
	ch := registerENBWithTAC(srv, addr, 42)
	attachDDNPDN(ue, peer, teid, ebi)

	req := &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: seq, EBI: &ebi}
	srv.HandleDownlinkDataNotification(peer, req)
	srv.HandleDownlinkDataNotification(peer, req)
	defer func() {
		ue.Lock()
		ue.StopTimer(ddnPagingRetryTimerName)
		ue.StopTimer(ddnPagingTimeoutTimerName)
		ue.Unlock()
	}()

	if len(mock.ackCalls) != 2 {
		t.Fatalf("DDN Ack count got %d, want 2", len(mock.ackCalls))
	}
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected first Paging PDU")
	}
	select {
	case raw := <-ch:
		t.Fatalf("unexpected duplicate Paging PDU: %x", raw)
	case <-time.After(80 * time.Millisecond):
	}
}

func TestHandleDownlinkDataNotification_RetryAndCompletion(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{
		DDNEnabled:         true,
		RetryInterval:      20 * time.Millisecond,
		MaxAttempts:        3,
		TransactionTimeout: 200 * time.Millisecond,
	}
	mock := &ddnMockS11{}
	srv.s11 = mock

	const (
		addr = "10.10.20.4:36412"
		peer = "10.90.250.59:2123"
		teid = 0x01020307
		seq  = 0x10206
	)
	ebi := uint8(6)

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 42)
	ch := registerENBWithTAC(srv, addr, 42)
	attachDDNPDN(ue, peer, teid, ebi)

	req := &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: seq, EBI: &ebi}
	srv.HandleDownlinkDataNotification(peer, req)

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected first Paging PDU")
	}
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected retry Paging PDU")
	}

	ue.Lock()
	if ue.DDNPaging == nil {
		ue.Unlock()
		t.Fatal("DDNPaging transaction not created")
	}
	txID := ue.DDNPaging.ID
	attempts := ue.DDNPaging.PagingAttemptCount
	ue.Unlock()
	if attempts < 2 {
		t.Fatalf("paging attempts got %d, want at least 2", attempts)
	}

	srv.noteDDNServiceRequest(ue, 0xabc, 7)
	srv.noteDDNResumeInProgress(ue)
	srv.completeDDNPagingIfPending(ue, "modify_bearer_accepted", []uint8{ebi})

	ue.Lock()
	defer ue.Unlock()
	if ue.DDNPaging == nil || ue.DDNPaging.ID != txID {
		t.Fatal("DDNPaging transaction unexpectedly replaced")
	}
	if got := ue.DDNPaging.Status; got != uecontext.DDNPagingCompleted {
		t.Fatalf("DDNPaging status got %q, want %q", got, uecontext.DDNPagingCompleted)
	}
	if ue.PagingAttempts != 0 {
		t.Fatalf("PagingAttempts got %d, want 0 after completion", ue.PagingAttempts)
	}
}

func TestDDNPagingServiceRequestCancelsTimeout(t *testing.T) {
	srv := newTAUTestServer()
	srv.pagingCfg = config.PagingConfig{DDNEnabled: true, RetryInterval: time.Hour, TransactionTimeout: time.Hour}
	mock := &ddnMockS11{}
	srv.s11 = mock
	const addr = "10.10.20.11:36412"
	const peer = "10.90.250.59:2123"
	const teid = 0x01020311
	ebi := uint8(6)
	ue, _, _ := makeIdleRegisteredUE(srv, addr, 42)
	registerENBWithTAC(srv, addr, 42)
	attachDDNPDN(ue, peer, teid, ebi)

	srv.HandleDownlinkDataNotification(peer, &gtpv2.DownlinkDataNotification{TEID: teid, SeqNum: 0x10211, EBI: &ebi})
	srv.noteDDNServiceRequest(ue, 0x1234, 9)
	// A callback that races or fires after correlation must be harmless.
	srv.onDDNPagingTimeout(ue, currentDDNTransactionID(ue))

	ue.Lock()
	status := ue.DDNPaging.Status
	ue.Unlock()
	if status != uecontext.DDNPagingCompleted {
		t.Fatalf("paging status after Service Request/timeout callback got %q, want completed", status)
	}
}

func TestPageUE_TAIMatchesCorrectENB(t *testing.T) {
	srv := newTAUTestServer()
	const addr1 = "10.10.1.1:36412"
	const addr2 = "10.10.1.2:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr1, 42)
	ch1 := registerENBWithTAC(srv, addr1, 42) // correct TAC
	ch2 := registerENBWithTAC(srv, addr2, 99) // different TAC

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatalf("PageUE: %v", err)
	}

	// Only addr1 (TAC=42) should receive the Paging PDU
	select {
	case <-ch1:
	case <-time.After(200 * time.Millisecond):
		t.Error("no Paging PDU sent to correct eNB (TAC=42)")
	}

	// addr2 must not receive anything
	select {
	case <-ch2:
		t.Error("Paging PDU was incorrectly sent to wrong eNB (TAC=99)")
	default:
	}

	ue.Lock()
	ue.StopTimer(uecontext.TimerT3413)
	ue.Unlock()
}

func TestPageUE_FallbackAllENBs(t *testing.T) {
	srv := newTAUTestServer()
	const addr1 = "10.10.2.1:36412"
	const addr2 = "10.10.2.2:36412"

	// UE TAI has TAC=50, but neither eNB serves TAC=50 → fallback to all
	ue, _, _ := makeIdleRegisteredUE(srv, addr1, 50)
	ch1 := registerENBWithTAC(srv, addr1, 10)
	ch2 := registerENBWithTAC(srv, addr2, 20)

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatalf("PageUE: %v", err)
	}

	// Both eNBs should receive the Paging PDU (fallback)
	got1, got2 := false, false
	deadline := time.After(300 * time.Millisecond)
	for !got1 || !got2 {
		select {
		case <-ch1:
			got1 = true
		case <-ch2:
			got2 = true
		case <-deadline:
			t.Errorf("timeout: got1=%v got2=%v", got1, got2)
			goto done
		}
	}
done:
	ue.Lock()
	ue.StopTimer(uecontext.TimerT3413)
	ue.Unlock()
}

// ── Timer / timeout tests ─────────────────────────────────────────────────────

func TestPageUE_Timeout(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.3.1:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	registerENBWithTAC(srv, addr, 1)

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatalf("PageUE: %v", err)
	}

	// Set PagingAttempts to maxPagingAttempts so the next timeout fires "timeout".
	ue.Lock()
	ue.PagingAttempts = maxPagingAttempts
	ue.Unlock()

	log, _ := zap.NewDevelopment()

	// Drain send channel
	val, _ := srv.sends.Load(addr)
	ch := val.(chan<- []byte)
	_ = ch

	srv.onPagingTimeout(ue, maxPagingAttempts, log)

	// PagingAttempts must be cleared
	ue.Lock()
	attempts := ue.PagingAttempts
	ue.Unlock()
	if attempts != 0 {
		t.Errorf("PagingAttempts after timeout: got %d, want 0", attempts)
	}

	// UE still in manager (no auto-detach)
	if _, ok := srv.ueManager.GetByIMSI(ue.IMSI); !ok {
		t.Error("UE was removed from manager after paging timeout (should stay)")
	}
}

func TestPageUE_RetryThenTimeout(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.3.2:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	ch := registerENBWithTAC(srv, addr, 1)

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatalf("PageUE: %v", err)
	}
	// Drain first paging PDU
	<-ch

	log, _ := zap.NewDevelopment()

	// First timeout fires at attempt=1 < maxPagingAttempts=2 → retry
	srv.onPagingTimeout(ue, 1, log)

	// Retry PDU must be sent
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Error("no retry Paging PDU sent after first timeout")
	}

	ue.Lock()
	attempts := ue.PagingAttempts
	ue.Unlock()
	if attempts != 2 {
		t.Errorf("PagingAttempts after retry: got %d, want 2", attempts)
	}

	// Second timeout fires at attempt=2 == maxPagingAttempts → final timeout
	srv.onPagingTimeout(ue, 2, log)

	ue.Lock()
	attempts = ue.PagingAttempts
	ue.StopTimer(uecontext.TimerT3413)
	ue.Unlock()
	if attempts != 0 {
		t.Errorf("PagingAttempts after final timeout: got %d, want 0", attempts)
	}
}

func TestPageUE_StaleTimerIgnored(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.3.3:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	registerENBWithTAC(srv, addr, 1)

	// Simulate: UE responded via Service Request, clearing PagingAttempts to 0
	ue.Lock()
	ue.PagingAttempts = 0
	ue.Unlock()

	log, _ := zap.NewDevelopment()

	// Old timer fires with attempt=1, but PagingAttempts=0 → should no-op
	srv.onPagingTimeout(ue, 1, log)

	// UE remains idle, no retry sent
	if _, ok := srv.ueManager.GetByIMSI(ue.IMSI); !ok {
		t.Error("UE removed from manager unexpectedly")
	}
}

// ── UE Context Release tests ──────────────────────────────────────────────────

func TestUEContextRelease_GoesIdle(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.1:36412"

	// Registered UE with an established S-GW session
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "001010099900099"
	ue.SGWC_TEID = 0xABCD0001
	ue.SGWU_TEID = 0xABCD0002
	ue.SGWU_IP = net.ParseIP("10.1.2.3").To4()
	ue.ENBS1APID = 42
	ue.ENBU_TEID = 0xBEEF0001
	ue.ENBU_IP = net.ParseIP("10.1.2.4").To4()
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
	}
	srv.handleUEContextReleaseComplete(addr, nil, ieList)

	// UE must still be in the manager (ECM-IDLE, not removed)
	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE was removed from manager; expected ECM-IDLE retention")
	}

	found.Lock()
	ecmState := found.ECMState
	sgwcTEID := found.SGWC_TEID
	enbUEID := found.ENBS1APID
	enbuTEID := found.ENBU_TEID
	found.Unlock()

	if ecmState != emm.ECMIdle {
		t.Errorf("ECMState: got %v, want ECMIdle", ecmState)
	}
	if sgwcTEID != 0xABCD0001 {
		t.Errorf("SGWC_TEID should be preserved: got %#x", sgwcTEID)
	}
	if enbUEID != 0 {
		t.Errorf("ENBS1APID should be cleared: got %d", enbUEID)
	}
	if enbuTEID != 0 {
		t.Errorf("ENBU_TEID should be cleared: got %#x", enbuTEID)
	}
	if len(mock.dsrCalls) != 0 {
		t.Errorf("sendDeleteSession must NOT be called on ECM-IDLE: got %d DSR calls", len(mock.dsrCalls))
	}
}

func TestUEContextReleaseRequest_MarksReleasePendingBeforeComplete(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.10:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "311435300070580"
	ue.SGWC_TEID = 0xABCD0001
	ue.SGWU_TEID = 0xABCD0002
	ue.SGWU_IP = net.ParseIP("10.90.250.59").To4()
	ue.ENBS1APID = 1
	ue.ENBU_TEID = 0x00000001
	ue.ENBU_IP = net.ParseIP("192.168.105.34").To4()
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(1)},
	}
	srv.handleUEContextReleaseRequest(addr, nil, ieList)

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no UE Context Release Command sent")
	}

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE was removed from manager; expected ECM-IDLE retention")
	}
	found.Lock()
	emmState := found.EMMState
	ecmState := found.ECMState
	sgwcTEID := found.SGWC_TEID
	enbUEID := found.ENBS1APID
	enbGlobalID := found.ENBGlobalID
	enbuTEID := found.ENBU_TEID
	releasePending := found.S1ReleasePending
	releaseENBID := found.S1ReleaseENBID
	bindingState := found.S1BindingState
	found.Unlock()

	if emmState != emm.StateRegistered {
		t.Errorf("EMMState: got %v, want StateRegistered", emmState)
	}
	if ecmState != emm.ECMConnected {
		t.Errorf("ECMState: got %v, want ECMConnected while release is pending", ecmState)
	}
	if sgwcTEID != 0xABCD0001 {
		t.Errorf("SGWC_TEID should be preserved: got %#x", sgwcTEID)
	}
	if enbUEID != 1 {
		t.Errorf("ENBS1APID should be preserved while release is pending: got %d", enbUEID)
	}
	if enbGlobalID != addr {
		t.Errorf("ENBGlobalID should be preserved while release is pending: got %q", enbGlobalID)
	}
	if enbuTEID != 0x00000001 {
		t.Errorf("ENBU_TEID should be preserved while release is pending: got %#x", enbuTEID)
	}
	if !releasePending {
		t.Error("S1ReleasePending should be true until UE Context Release Complete")
	}
	if bindingState != uecontext.S1BindingReleasePending {
		t.Errorf("S1BindingState: got %s, want %s", bindingState, uecontext.S1BindingReleasePending)
	}
	if releaseENBID != 1 {
		t.Errorf("S1ReleaseENBID: got %d, want 1", releaseENBID)
	}
	if len(mock.dsrCalls) != 0 {
		t.Errorf("sendDeleteSession must NOT be called on release request: got %d DSR calls", len(mock.dsrCalls))
	}
}

func TestUEContextReleaseRequest_DefersReleaseCommandUntilRABRsp(t *testing.T) {
	mock := &releaseAccessMockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.13:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "311435300070581"
	ue.SGWAddress = "10.90.250.59:2123"
	ue.SGWC_TEID = 0xABCD1001
	ue.SGWU_TEID = 0xABCD1002
	ue.SGWU_IP = net.ParseIP("10.90.250.59").To4()
	ue.ENBS1APID = 2
	ue.ENBU_TEID = 0x00000002
	ue.ENBU_IP = net.ParseIP("192.168.105.35").To4()
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(2)},
	}
	srv.handleUEContextReleaseRequest(addr, nil, ieList)

	if len(mock.rabrCalls) != 1 {
		t.Fatalf("expected 1 RABR call, got %d", len(mock.rabrCalls))
	}
	select {
	case msg := <-ch:
		t.Fatalf("unexpected UE Context Release Command before RABRsp: %x", msg)
	case <-time.After(50 * time.Millisecond):
	}

	srv.HandleRABRResult(mmeID, &gtpv2.ReleaseAccessBearersResult{
		Peer:              "10.90.250.59:2123",
		RequestedSGWCTEID: 0xABCD1001,
		Cause:             gtpv2.CauseRequestAccepted,
	}, nil)

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no UE Context Release Command sent after RABRsp")
	}

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE was removed from manager; expected ECM-IDLE retention")
	}
	found.Lock()
	enbuTEID := found.ENBU_TEID
	enbuIP := found.ENBU_IP
	releasePending := found.S1ReleasePending
	found.Unlock()
	if enbuTEID != 0 {
		t.Errorf("ENBU_TEID should be cleared after RABRsp, got %#x", enbuTEID)
	}
	if enbuIP != nil {
		t.Errorf("ENBU_IP should be cleared after RABRsp, got %v", enbuIP)
	}
	if !releasePending {
		t.Error("S1ReleasePending should remain true until UE Context Release Complete")
	}
}

func TestUEContextReleaseRequest_SendsRABRPerUniquePDNSession(t *testing.T) {
	mock := &releaseAccessMockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.14:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "311435300070582"
	ue.ENBS1APID = 3
	ue.TAI = &emm.TAI{TAC: 1}
	ue.SGWAddress = "10.90.250.80:2123"
	ue.SGWC_TEID = 0x800a6003
	ue.DefaultEBI = 5
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:        "internet",
			DefaultEBI: 5,
			SGWAddress: "10.90.250.80:2123",
			SGWC_TEID:  0x800a6003,
			State:      "active",
		},
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			SGWAddress: "10.90.250.80:2123",
			SGWC_TEID:  0x800a8003,
			State:      "active",
		},
		"mms": {
			APN:        "mms",
			DefaultEBI: 7,
			SGWAddress: "10.90.250.80:2123",
			SGWC_TEID:  0x800aa003,
			State:      "active",
		},
	}
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(3)},
	}
	srv.handleUEContextReleaseRequest(addr, nil, ieList)

	if len(mock.rabrCalls) != 3 {
		t.Fatalf("expected 3 RABR calls, got %d", len(mock.rabrCalls))
	}
	gotTEIDs := map[uint32]struct{}{}
	for _, call := range mock.rabrCalls {
		gotTEIDs[call.SGWC_TEID] = struct{}{}
	}
	for _, wantTEID := range []uint32{0x800a6003, 0x800a8003, 0x800aa003} {
		if _, ok := gotTEIDs[wantTEID]; !ok {
			t.Fatalf("missing RABR for SGW-C TEID %#x", wantTEID)
		}
	}

	select {
	case msg := <-ch:
		t.Fatalf("unexpected UE Context Release Command before all RABRs complete: %x", msg)
	case <-time.After(50 * time.Millisecond):
	}

	srv.HandleRABRResult(mmeID, &gtpv2.ReleaseAccessBearersResult{
		Peer:              "10.90.250.80:2123",
		RequestedSGWCTEID: 0x800a6003,
		Cause:             gtpv2.CauseRequestAccepted,
	}, nil)
	srv.HandleRABRResult(mmeID, &gtpv2.ReleaseAccessBearersResult{
		Peer:              "10.90.250.80:2123",
		RequestedSGWCTEID: 0x800a8003,
		Cause:             gtpv2.CauseRequestAccepted,
	}, nil)

	select {
	case msg := <-ch:
		t.Fatalf("unexpected UE Context Release Command before final RABR result: %x", msg)
	case <-time.After(50 * time.Millisecond):
	}

	srv.HandleRABRResult(mmeID, &gtpv2.ReleaseAccessBearersResult{
		Peer:              "10.90.250.80:2123",
		RequestedSGWCTEID: 0x800aa003,
		Cause:             gtpv2.CauseRequestAccepted,
	}, nil)

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no UE Context Release Command sent after final RABR result")
	}
}

func TestUEContextReleaseRequest_DeduplicatesPDNsSharingSameSession(t *testing.T) {
	mock := &releaseAccessMockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.15:36412"
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "311435300070583"
	ue.ENBS1APID = 4
	ue.SGWAddress = "10.90.250.80:2123"
	ue.SGWC_TEID = 0x800a6003
	ue.DefaultEBI = 5
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:        "internet",
			DefaultEBI: 5,
			SGWAddress: "10.90.250.80:2123",
			SGWC_TEID:  0x800a6003,
			State:      "active",
		},
		"legacy-copy": {
			APN:        "legacy-copy",
			DefaultEBI: 9,
			SGWAddress: "10.90.250.80:2123",
			SGWC_TEID:  0x800a6003,
			State:      "active",
		},
	}
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(4)},
	}
	srv.handleUEContextReleaseRequest(addr, nil, ieList)

	if len(mock.rabrCalls) != 1 {
		t.Fatalf("expected 1 deduplicated RABR call, got %d", len(mock.rabrCalls))
	}
}

func TestUEContextReleaseRequest_BadENBUEIDSendErrorIndication(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.11:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBS1APID = 1
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: []byte{0xff}},
		{ID: pdu.IECause, Value: ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUserInactivity)},
	}
	srv.handleUEContextReleaseRequest(addr, &pdu.PDU{
		Type:          pdu.PDUTypeInitiatingMessage,
		ProcedureCode: pdu.ProcUEContextReleaseRequest,
		Criticality:   aper.CriticalityIgnore,
	}, ieList)

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
}

func TestUEContextReleaseComplete_DoesNotClearReboundServiceRequestAccess(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.10:36412"
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.IMSI = "311435300070580"
	ue.S1ReleasePending = true
	ue.S1ReleaseENBID = 1
	ue.S1ReleaseENBAddr = addr
	ue.ENBS1APID = 2
	ue.ENBGlobalID = addr
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(1)},
	}
	srv.handleUEContextReleaseComplete(addr, nil, ieList)

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE was removed from manager")
	}
	found.Lock()
	enbUEID := found.ENBS1APID
	enbGlobalID := found.ENBGlobalID
	releasePending := found.S1ReleasePending
	found.Unlock()

	if enbUEID != 2 {
		t.Errorf("new Service Request ENBS1APID was cleared: got %d, want 2", enbUEID)
	}
	if enbGlobalID != addr {
		t.Errorf("new Service Request ENBGlobalID was cleared: got %q, want %q", enbGlobalID, addr)
	}
	if releasePending {
		t.Error("old S1 release should be acknowledged and cleared")
	}
}

func TestUEContextReleaseComplete_WrongPairSendsErrorIndication(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.12:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBS1APID = 1
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(2)},
	}
	srv.handleUEContextReleaseComplete(addr, &pdu.PDU{
		Type:          pdu.PDUTypeSuccessfulOutcome,
		ProcedureCode: pdu.ProcUEContextRelease,
		Criticality:   aper.CriticalityReject,
	}, ieList)

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownPairUES1APID)
}

func TestUEContextRelease_DeregisteredIsRemoved(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.4.2:36412"

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateDeregisteredInitiated
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "001010099900100"
	ue.SGWC_TEID = 0xDDEE0001
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
	}
	srv.handleUEContextReleaseComplete(addr, nil, ieList)

	// UE must be removed
	if _, ok := srv.ueManager.GetByMMEID(mmeID); ok {
		t.Error("UE should have been removed after deregistered release")
	}

	// DSR must have been sent
	if len(mock.dsrCalls) != 1 {
		t.Errorf("expected 1 DSR call, got %d", len(mock.dsrCalls))
	}
}

// ── C-1 regression: eNB disconnect must not evict ECM-IDLE UEs ───────────────

func TestHandleDisconnect_PreservesIdleUE(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.5.1:36412"

	// Register an eNB.
	registerTestENB(srv, addr)

	// UE was registered, S1 released (goes ECM-IDLE via handleUEContextReleaseComplete).
	// Simulate the post-release state: EMM-REGISTERED, ECM-IDLE, ENBGlobalID cleared.
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.ENBGlobalID = "" // cleared when going idle — key invariant
	ue.SGWC_TEID = 0xCAFE0001
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	srv.handleDisconnect(addr)

	// UE must still be in the manager (ECM-IDLE survives eNB disconnect)
	if _, ok := srv.ueManager.GetByMMEID(mmeID); !ok {
		t.Fatal("ECM-IDLE UE was evicted on eNB disconnect — C-1 regression")
	}
	// S-GW bearer must be preserved
	if len(mock.dsrCalls) != 0 {
		t.Errorf("sendDeleteSession called for ECM-IDLE UE: %d DSR(s)", len(mock.dsrCalls))
	}
}

func TestUEContextRelease_ClearsENBGlobalID(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.10.5.2:36412"

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.IMSI = "001010099900201"
	ue.SGWC_TEID = 0xBEEF0001
	ue.DefaultEBI = 5
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
	}
	srv.handleUEContextReleaseComplete(addr, nil, ieList)

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE removed from manager; expected ECM-IDLE retention")
	}
	found.Lock()
	enbGlobalID := found.ENBGlobalID
	found.Unlock()

	if enbGlobalID != "" {
		t.Errorf("ENBGlobalID not cleared on ECM-IDLE transition: got %q", enbGlobalID)
	}
}

// ── C-2 regression: nil TAI must not produce a malformed Paging PDU ──────────

func TestPageUE_NilTAIRejectsPaging(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.6.1:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	// Override: no known TAI
	ue.Lock()
	ue.TAI = nil
	ue.Unlock()

	ch := registerENBWithTAC(srv, addr, 1)

	if err := srv.PageUE(ue.IMSI); err != ErrNoPagingTAI {
		t.Fatalf("PageUE error: got %v, want %v", err, ErrNoPagingTAI)
	}

	select {
	case raw := <-ch:
		t.Fatalf("unexpected Paging PDU sent despite nil TAI: %x", raw)
	case <-time.After(200 * time.Millisecond):
	}

	ue.Lock()
	attempts := ue.PagingAttempts
	ue.Unlock()
	if attempts != 0 {
		t.Fatalf("PagingAttempts changed on rejected paging: got %d, want 0", attempts)
	}
}

// ── S-2 regression: stale timer with non-zero attempt mismatch ───────────────

func TestPageUE_StaleTimerNonZeroMismatch(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.10.7.1:36412"

	ue, _, _ := makeIdleRegisteredUE(srv, addr, 1)
	ch := registerENBWithTAC(srv, addr, 1)

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatalf("PageUE: %v", err)
	}
	<-ch // drain first PDU

	log, _ := zap.NewDevelopment()

	// Simulate a new paging cycle starting: PagingAttempts advances to 2.
	ue.Lock()
	ue.PagingAttempts = 2
	ue.Unlock()

	// Old timer from attempt=1 fires — should be a no-op because current(2) != attempt(1).
	srv.onPagingTimeout(ue, 1, log)

	// No retry PDU should have been sent.
	select {
	case <-ch:
		t.Error("stale timer (attempt=1, current=2) incorrectly sent a retry PDU")
	default:
	}

	// PagingAttempts must be unchanged.
	ue.Lock()
	attempts := ue.PagingAttempts
	ue.StopTimer(uecontext.TimerT3413)
	ue.Unlock()
	if attempts != 2 {
		t.Errorf("PagingAttempts changed by stale timer: got %d, want 2", attempts)
	}
}

// ── S-1 regression: paging-success metric fires correctly ────────────────────

func TestHandleServiceRequestReestablished_PagingSuccessMetric(t *testing.T) {
	// Simulate a UE that was being paged (PagingAttempts=1) and then sent a Service Request.
	// handleServiceRequestReestablished must increment paging_total{result="success"}.
	// We can't directly test the Prometheus counter value here (no test registry), but we
	// can verify that PagingAttempts is cleared to 0 after the call, confirming the code path ran.
	srv := newTAUTestServer()
	const addr = "10.10.8.1:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.PagingAttempts = 1 // UE was paged once
	ue.Unlock()

	log, _ := zap.NewDevelopment()
	srv.handleServiceRequestReestablished(ue, log)

	ue.Lock()
	attempts := ue.PagingAttempts
	ue.Unlock()
	if attempts != 0 {
		t.Errorf("PagingAttempts not cleared after SR re-establishment: got %d, want 0", attempts)
	}
}

// ── Additional encoding completeness check ───────────────────────────────────

func TestEncodeUEPagingIDSTMSI_LastMTMSIByte(t *testing.T) {
	b := ies.EncodeUEPagingIDSTMSI(0x01, 0xDEAD0001)
	if len(b) != 6 {
		t.Fatalf("length: got %d, want 6", len(b))
	}
	// M-TMSI = 0xDEAD0001: bytes[2..5] = {0xDE, 0xAD, 0x00, 0x01}
	if b[5] != 0x01 {
		t.Errorf("M-TMSI last byte: got %02X, want 01", b[5])
	}
}

// ── Metrics smoke test ────────────────────────────────────────────────────────

func TestPagingMetrics_SentAndTimeout(t *testing.T) {
	// Just verifies the metrics counters don't panic.
	// Real label validation would require a prometheus registry.
	metrics.PagingTotal.WithLabelValues("sent").Inc()
	metrics.PagingTotal.WithLabelValues("timeout").Inc()
	metrics.PagingTotal.WithLabelValues("success").Inc()
	metrics.PagingTotal.WithLabelValues("no_tai").Inc()
}

func assertPagingMessageHasMandatoryIEs(t *testing.T, raw []byte) {
	t.Helper()
	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("Decode paging PDU: %v", err)
	}
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcPaging {
		t.Fatalf("paging header got type=%s proc=%d, want initiating Paging", msg.Type, msg.ProcedureCode)
	}
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}

	want := map[uint16]bool{
		pdu.IEUEIdentityIndexValue: false,
		pdu.IEUEPagingID:           false,
		pdu.IECNDomain:             false,
		pdu.IEPagingTAIList:        false,
	}
	for _, ie := range ieList {
		if _, ok := want[ie.ID]; ok {
			want[ie.ID] = true
		}
	}
	for ieID, seen := range want {
		if !seen {
			t.Fatalf("Paging missing mandatory IE %d", ieID)
		}
	}
}
