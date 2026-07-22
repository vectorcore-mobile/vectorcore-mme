package s1ap

import (
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestHandleUpdateBearerRequestConnectedSendsERABModify(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.21:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070580"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 55
	ue.LocalS11TEID = 0x0f
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             1,
		ARP:             14,
		BearerQoS:       []byte{0x3c, 0x01, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111111,
		SGWS1UIP:        net.ParseIP("198.51.100.20").To4(),
		ENBS1UTEID:      0x22222222,
		ENBS1UIP:        net.ParseIP("192.0.2.20").To4(),
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x23d,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       2,
			ARP:       14,
			BearerQoS: []byte{0x38, 0x02, 0, 0, 0, 0, 0},
			TFT:       []byte{0x05, 0xa4, 0x20, 0x21},
		}},
	})

	first := readCapturedPDU(t, ch)
	if first.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("first procedure got %d, want DownlinkNASTransport", first.ProcedureCode)
	}
	second := readCapturedPDU(t, ch)
	if second.ProcedureCode != pdu.ProcERABModify {
		t.Fatalf("second procedure got %d, want E-RABModify", second.ProcedureCode)
	}
	ieList, err := decodeProcedureIEsCompat(second.Value)
	if err != nil {
		t.Fatalf("decode E-RAB Modify IE list: %v", err)
	}
	var sawModifyList bool
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABToBeModifiedListBearerModReq {
			sawModifyList = true
		}
	}
	if !sawModifyList {
		t.Fatal("E-RAB Modify Request missing E-RABToBeModifiedListBearerModReq")
	}
	if got := len(mock.updateResponses); got != 0 {
		t.Fatalf("Update Bearer Response sent before completion: %d", got)
	}
}

func TestUpdateBearerWaitsForNASAndERABModifyResponse(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.22:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070581"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 56
	ue.LocalS11TEID = 0x0f
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             1,
		ARP:             14,
		BearerQoS:       []byte{0x3c, 0x01, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111111,
		SGWS1UIP:        net.ParseIP("198.51.100.21").To4(),
		ENBS1UTEID:      0x22222223,
		ENBS1UIP:        net.ParseIP("192.0.2.21").To4(),
		ERABEstablished: true,
		State:           "active",
	}
	mmeID := ue.MMEUES1APID
	enbID := ue.ENBS1APID
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x23e,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       2,
			ARP:       14,
			BearerQoS: []byte{0x38, 0x02, 0, 0, 0, 0, 0},
			TFT:       []byte{0x05, 0xa4, 0x20, 0x21, 0x12, 0x13},
		}},
	})
	_ = readCapturedPDU(t, ch)
	_ = readCapturedPDU(t, ch)

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)

	select {
	case <-time.After(50 * time.Millisecond):
	case <-func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			waitForUpdateResponseCount(t, mock, 1)
			close(done)
		}()
		return done
	}():
		t.Fatal("Update Bearer Response sent before E-RAB Modify Response")
	}

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABModify, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbID)},
		{ID: pdu.IEERABModifyListBearerModRes, Criticality: aper.CriticalityIgnore, Value: encodeERABModifyResponseListForTest([]uint8{9})},
	})
	srv.handleMessage(addr, raw)

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("update response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestAccepted)
	}
	ue.Lock()
	defer ue.Unlock()
	if got := ue.DedicatedBearers[9].QCI; got != 2 {
		t.Fatalf("updated bearer QCI got %d, want 2", got)
	}
}

func TestTFTOnlyUpdateBearerUsesNASAndWaitsForAccept(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.26:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070583"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 58
	ue.LocalS11TEID = 0x0f
	ue.DedicatedBearers[10] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     10,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             1,
		BearerQoS:       []byte{0x44, 0x05, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111112,
		SGWS1UIP:        net.ParseIP("198.51.100.26").To4(),
		ENBS1UTEID:      0x22222226,
		ENBS1UIP:        net.ParseIP("192.0.2.26").To4(),
		NASAccepted:     true,
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x240,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       10,
			QCI:       5,
			ARP:       1,
			BearerQoS: []byte{},
			TFT:       []byte{0x05, 0xa4, 0x20, 0x99},
		}},
	})
	first := readCapturedPDU(t, ch)
	if first.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("procedure got %d, want DownlinkNASTransport", first.ProcedureCode)
	}
	assertNoCapturedPDU(t, ch)

	select {
	case <-time.After(50 * time.Millisecond):
	case <-func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			waitForUpdateResponseCount(t, mock, 1)
			close(done)
		}()
		return done
	}():
		t.Fatal("Update Bearer Response sent before NAS accept")
	}

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 10,
	}, srv.log)

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("update response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestAccepted)
	}
	ue.Lock()
	defer ue.Unlock()
	if got := ue.DedicatedBearers[10].TFT; len(got) != 4 || got[3] != 0x99 {
		t.Fatalf("updated bearer TFT got %x, want suffix 99", got)
	}
	if got := ue.DedicatedBearers[10].QCI; got != 5 {
		t.Fatalf("updated bearer QCI got %d, want 5", got)
	}
	if got := ue.DedicatedBearers[10].ARP; got != 1 {
		t.Fatalf("updated bearer ARP got %d, want 1", got)
	}
	if got := ue.DedicatedBearers[10].TransactionID; got == "" {
		t.Fatal("updated bearer transaction id not set")
	}
	if got := len(ue.PendingBearerTransactions); got != 0 {
		t.Fatalf("pending transactions after update got %d, want 0", got)
	}
	if got := len(ue.PendingERABProcedures); got != 0 {
		t.Fatalf("pending E-RAB procedures after update got %d, want 0", got)
	}
}

func TestAPNAMBROnlyUpdateBearerUsesNASWithoutERABModify(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.26b:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070588"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 63
	ue.LocalS11TEID = 0x14
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             1,
		BearerQoS:       []byte{0x44, 0x05},
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	req := &gtpv2.UpdateBearerRequest{
		TEID:   0x14,
		SeqNum: 0x247,
		AMBR:   []byte{0, 0, 0x0f, 0x0a, 0, 0, 0x05, 0xfa},
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI: 9,
		}},
	}
	srv.HandleUpdateBearerRequest("10.90.250.59:2123", req)
	first := readCapturedPDU(t, ch)
	if first.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("procedure got %d, want DownlinkNASTransport", first.ProcedureCode)
	}
	assertNoCapturedPDU(t, ch)

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)
	waitForUpdateResponseCount(t, mock, 1)
	if got := mock.updateResponseAt(0).Cause; got != gtpv2.CauseRequestAccepted {
		t.Fatalf("Update Bearer Response cause got %d, want %d", got, gtpv2.CauseRequestAccepted)
	}

	// Combining the same APN-AMBR update with a TFT-only change remains NAS-only.
	req.SeqNum = 0x248
	req.Bearers[0].TFT = []byte{0x05, 0xa4, 0x04, 0x05, 0x06, 0x07}
	srv.HandleUpdateBearerRequest("10.90.250.59:2123", req)
	first = readCapturedPDU(t, ch)
	if first.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("combined update procedure got %d, want DownlinkNASTransport", first.ProcedureCode)
	}
	assertNoCapturedPDU(t, ch)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)
	waitForUpdateResponseCount(t, mock, 2)
}

func TestHandleUpdateBearerRequestPreservesExistingQoSWhenRequestIsUnderspecified(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.27:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070584"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 59
	ue.LocalS11TEID = 0x10
	originalQoS := []byte{0x44, 0x05, 0, 0, 0, 0, 0}
	ue.DedicatedBearers[10] = &uecontext.DedicatedBearerContext{
		TransactionID:   "cbr-old",
		AssignedEBI:     10,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             1,
		BearerQoS:       append([]byte(nil), originalQoS...),
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111113,
		SGWS1UIP:        net.ParseIP("198.51.100.27").To4(),
		ENBS1UTEID:      0x22222227,
		ENBS1UIP:        net.ParseIP("192.0.2.27").To4(),
		NASAccepted:     true,
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x10,
		SeqNum: 0x241,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       10,
			QCI:       0,
			ARP:       0,
			BearerQoS: nil,
			TFT:       []byte{0x05, 0xa4, 0x20, 0xaa},
		}},
	})
	_ = readCapturedPDU(t, ch)

	ue.Lock()
	var tx *uecontext.DedicatedBearerTransaction
	for _, pending := range ue.PendingBearerTransactions {
		if pending.Kind == bearerTxUpdate {
			tx = pending
			break
		}
	}
	if tx == nil {
		ue.Unlock()
		t.Fatal("missing pending update bearer transaction")
	}
	proc := tx.Bearers[10]
	if proc == nil {
		ue.Unlock()
		t.Fatal("missing pending update bearer 10")
	}
	if got := proc.TransactionID; got != tx.ID {
		ue.Unlock()
		t.Fatalf("pending bearer transaction id got %q, want %q", got, tx.ID)
	}
	if got := proc.QCI; got != 5 {
		ue.Unlock()
		t.Fatalf("pending bearer QCI got %d, want 5", got)
	}
	if got := proc.ARP; got != 1 {
		ue.Unlock()
		t.Fatalf("pending bearer ARP got %d, want 1", got)
	}
	if got := proc.BearerQoS; len(got) != len(originalQoS) || got[1] != originalQoS[1] {
		ue.Unlock()
		t.Fatalf("pending bearer QoS got %x, want %x", got, originalQoS)
	}
	ue.Unlock()

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 10,
	}, srv.log)

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("update response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestAccepted)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := ue.DedicatedBearers[10].QCI; got != 5 {
		t.Fatalf("active bearer QCI got %d, want 5", got)
	}
	if got := ue.DedicatedBearers[10].ARP; got != 1 {
		t.Fatalf("active bearer ARP got %d, want 1", got)
	}
	if got := ue.DedicatedBearers[10].BearerQoS; len(got) != len(originalQoS) || got[1] != originalQoS[1] {
		t.Fatalf("active bearer QoS got %x, want %x", got, originalQoS)
	}
	if got := ue.DedicatedBearers[10].TFT; len(got) != 4 || got[3] != 0xaa {
		t.Fatalf("active bearer TFT got %x, want suffix aa", got)
	}
}

func TestHandleUpdateBearerRequestRejectsOverlappingUpdateForSameEBI(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.28:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070585"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 60
	ue.LocalS11TEID = 0x11
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             1,
		BearerQoS:       []byte{0x44, 0x05, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111114,
		SGWS1UIP:        net.ParseIP("198.51.100.28").To4(),
		ENBS1UTEID:      0x22222228,
		ENBS1UIP:        net.ParseIP("192.0.2.28").To4(),
		NASAccepted:     true,
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x11,
		SeqNum: 0x242,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       5,
			ARP:       1,
			BearerQoS: nil,
			TFT:       []byte{0x05, 0xa4, 0x20, 0x31},
		}},
	})
	_ = readCapturedPDU(t, ch)

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x11,
		SeqNum: 0x243,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       0,
			ARP:       0,
			BearerQoS: nil,
			TFT:       []byte{0x05, 0xa4, 0x20, 0x32},
		}},
	})

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Seq != 0x243 {
		t.Fatalf("overlap response seq got %d, want %d", resp.Seq, 0x243)
	}
	if resp.Cause != gtpv2.CauseRequestDenied {
		t.Fatalf("overlap response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestDenied)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 1 {
		t.Fatalf("pending transactions after overlap got %d, want 1", got)
	}
	var tx *uecontext.DedicatedBearerTransaction
	for _, pending := range ue.PendingBearerTransactions {
		tx = pending
	}
	if tx == nil {
		t.Fatal("missing pending update transaction after overlap")
	}
	if tx.SequenceNum != 0x242 {
		t.Fatalf("surviving update sequence got %d, want %d", tx.SequenceNum, 0x242)
	}
	if got := tx.Bearers[9].TFT; len(got) != 4 || got[3] != 0x31 {
		t.Fatalf("surviving update TFT got %x, want suffix 31", got)
	}
}

func TestHandleUpdateBearerRequestRejectsOverlapAfterERABModifyBeforeNASAccept(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.28b:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070586"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 61
	ue.LocalS11TEID = 0x12
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             1,
		BearerQoS:       []byte{0x44, 0x05, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111115,
		SGWS1UIP:        net.ParseIP("198.51.100.29").To4(),
		ENBS1UTEID:      0x22222229,
		ENBS1UIP:        net.ParseIP("192.0.2.29").To4(),
		NASAccepted:     true,
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x12,
		SeqNum: 0x244,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       5,
			ARP:       1,
			BearerQoS: nil,
			TFT:       []byte{0x05, 0xa4, 0x20, 0x41},
		}},
	})
	_ = readCapturedPDU(t, ch)

	ue.Lock()
	if got := len(ue.PendingBearerTransactions); got != 1 {
		ue.Unlock()
		t.Fatalf("pending transactions after E-RAB Modify got %d, want 1", got)
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x12,
		SeqNum: 0x245,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       0,
			ARP:       0,
			BearerQoS: nil,
			TFT:       []byte{0x05, 0xa4, 0x20, 0x42},
		}},
	})

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Seq != 0x245 {
		t.Fatalf("overlap response seq got %d, want %d", resp.Seq, 0x245)
	}
	if resp.Cause != gtpv2.CauseRequestDenied {
		t.Fatalf("overlap response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestDenied)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 1 {
		t.Fatalf("pending transactions after post-ERAB overlap got %d, want 1", got)
	}
	var tx *uecontext.DedicatedBearerTransaction
	for _, pending := range ue.PendingBearerTransactions {
		tx = pending
	}
	if tx == nil {
		t.Fatal("missing surviving update transaction after post-ERAB overlap")
	}
	if tx.SequenceNum != 0x244 {
		t.Fatalf("surviving update sequence got %d, want %d", tx.SequenceNum, 0x244)
	}
}

func TestERABModifyResponseWrongPairSendsErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.23:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 1
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	srv.handleERABModifyResponse(addr, &pdu.PDU{
		Type:          pdu.PDUTypeSuccessfulOutcome,
		ProcedureCode: pdu.ProcERABModify,
		Criticality:   aper.CriticalityIgnore,
	}, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
		{ID: pdu.IEERABModifyListBearerModRes, Criticality: aper.CriticalityIgnore, Value: encodeERABModifyResponseListForTest([]uint8{9})},
	})

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownPairUES1APID)
}

func TestUpdateBearerTimeoutClearsPendingStateAndIgnoresLateModifyResponse(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.24:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070582"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 57
	ue.LocalS11TEID = 0x0f
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             1,
		ARP:             14,
		BearerQoS:       []byte{0x3c, 0x01, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111111,
		SGWS1UIP:        net.ParseIP("198.51.100.22").To4(),
		ENBS1UTEID:      0x22222224,
		ENBS1UIP:        net.ParseIP("192.0.2.22").To4(),
		ERABEstablished: true,
		State:           "active",
	}
	mmeID := ue.MMEUES1APID
	enbID := ue.ENBS1APID
	ue.Unlock()

	req := &gtpv2.UpdateBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x23f,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       2,
			ARP:       14,
			BearerQoS: []byte{0x38, 0x02, 0, 0, 0, 0, 0},
			TFT:       []byte{0x05, 0xa4, 0x20, 0x31},
		}},
	}
	srv.HandleUpdateBearerRequest("10.90.250.59:2123", req)
	_ = readCapturedPDU(t, ch)
	_ = readCapturedPDU(t, ch)

	key := bearerTxKey("10.90.250.59:2123", gtpv2.MsgUpdateBearerRequest, req.TEID, req.SeqNum)
	srv.onUpdateBearerTimeout(ue, key)

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestDenied {
		t.Fatalf("timeout update response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestDenied)
	}

	ue.Lock()
	if got := len(ue.PendingBearerTransactions); got != 0 {
		ue.Unlock()
		t.Fatalf("pending transactions after timeout got %d, want 0", got)
	}
	if got := len(ue.PendingERABProcedures); got != 0 {
		ue.Unlock()
		t.Fatalf("pending E-RAB procedures after timeout got %d, want 0", got)
	}
	if got := ue.DedicatedBearers[9].QCI; got != 1 {
		ue.Unlock()
		t.Fatalf("active bearer QCI changed on timeout: got %d, want 1", got)
	}
	ue.Unlock()

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABModify, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbID)},
		{ID: pdu.IEERABModifyListBearerModRes, Criticality: aper.CriticalityIgnore, Value: encodeERABModifyResponseListForTest([]uint8{9})},
	})
	srv.handleMessage(addr, raw)

	time.Sleep(25 * time.Millisecond)
	if got := mock.createResponseCount(); got != 0 {
		t.Fatalf("unexpected create bearer responses after late modify response: %d", got)
	}
	if got := len(mock.updateResponses); got != 1 {
		t.Fatalf("late modify response changed update response count: got %d, want 1", got)
	}
}

func TestLateDuplicateModifyBearerAcceptIsIgnoredAfterUpdateCompletion(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	const addr = "10.0.0.24b:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070587"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 62
	ue.LocalS11TEID = 0x13
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             1,
		BearerQoS:       []byte{0x44, 0x05, 0, 0, 0, 0, 0},
		TFT:             []byte{0x01, 0x80},
		SGWS1UTEID:      0x11111116,
		SGWS1UIP:        net.ParseIP("198.51.100.30").To4(),
		ENBS1UTEID:      0x22222230,
		ENBS1UIP:        net.ParseIP("192.0.2.30").To4(),
		NASAccepted:     true,
		ERABEstablished: true,
		State:           "active",
	}
	ue.Unlock()

	srv.HandleUpdateBearerRequest("10.90.250.59:2123", &gtpv2.UpdateBearerRequest{
		TEID:   0x13,
		SeqNum: 0x246,
		Bearers: []gtpv2.UpdateBearerBearer{{
			EBI:       9,
			QCI:       5,
			ARP:       1,
			BearerQoS: nil,
			TFT:       []byte{0x05, 0xa4, 0x20, 0x51},
		}},
	})
	_ = readCapturedPDU(t, ch)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)

	waitForUpdateResponseCount(t, mock, 1)

	ue.Lock()
	if got := len(ue.PendingBearerTransactions); got != 0 {
		ue.Unlock()
		t.Fatalf("pending transactions after update completion got %d, want 0", got)
	}
	finalTxID := ue.DedicatedBearers[9].TransactionID
	finalTFT := append([]byte(nil), ue.DedicatedBearers[9].TFT...)
	ue.Unlock()

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 0 {
		t.Fatalf("pending transactions after stale duplicate got %d, want 0", got)
	}
	if got := ue.DedicatedBearers[9].TransactionID; got != finalTxID {
		t.Fatalf("transaction id changed after stale duplicate: got %q want %q", got, finalTxID)
	}
	if got := ue.DedicatedBearers[9].TFT; len(got) != len(finalTFT) || got[3] != finalTFT[3] {
		t.Fatalf("bearer TFT changed after stale duplicate: got %x want %x", got, finalTFT)
	}
}

func encodeERABModifyResponseListForTest(ebis []uint8) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(ebis)), 1, 256)
	w.AlignToByte()
	for _, ebi := range ebis {
		body := encodeERABModifyResponseItemForTest(ebi)
		w.WriteOctets(encodeSingleContainerIEForTest(pdu.IEERABModifyItemBearerModRes, aper.CriticalityIgnore, body))
	}
	return w.Bytes()
}

func encodeERABModifyResponseItemForTest(ebi uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(ebi), 0, 15)
	return w.Bytes()
}

func assertNoCapturedPDU(t *testing.T, ch <-chan []byte) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("unexpected additional S1AP PDU")
	case <-time.After(50 * time.Millisecond):
	}
}
