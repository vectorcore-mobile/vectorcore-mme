package s1ap

import (
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/uecontext"
)

type capturingMBRS11 struct {
	calls []gtpv2.ModifyBearerRequest
}

func (m *capturingMBRS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (m *capturingMBRS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }
func (m *capturingMBRS11) SendMBR(_ uint32, req *gtpv2.ModifyBearerRequest) error {
	m.calls = append(m.calls, *req)
	return nil
}

type capturingBearerAndMBRS11 struct {
	capturingMBRS11
	bearerResponderMock
	piggybackCalls []struct {
		Peer    string
		TEID    uint32
		Seq     uint32
		Cause   uint8
		Meta    *gtpv2.CreateBearerResponseMeta
		MMEUEID uint32
		MBRSeq  uint32
		MBR     gtpv2.ModifyBearerRequest
		Bearers []gtpv2.CreateBearerBearer
	}
}

func (m *capturingBearerAndMBRS11) SendCreateBearerResponseWithPiggybackMBR(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta, mmeUEID uint32, mbr *gtpv2.ModifyBearerRequest) (uint32, error) {
	call := struct {
		Peer    string
		TEID    uint32
		Seq     uint32
		Cause   uint8
		Meta    *gtpv2.CreateBearerResponseMeta
		MMEUEID uint32
		MBRSeq  uint32
		MBR     gtpv2.ModifyBearerRequest
		Bearers []gtpv2.CreateBearerBearer
	}{
		Peer:    peer,
		TEID:    teid,
		Seq:     seq,
		Cause:   cause,
		Meta:    meta,
		MMEUEID: mmeUEID,
		MBRSeq:  0x222,
		MBR:     *mbr,
		Bearers: append([]gtpv2.CreateBearerBearer(nil), bearers...),
	}
	m.piggybackCalls = append(m.piggybackCalls, call)
	return call.MBRSeq, nil
}

func TestIMSModifyBearerWaitsForDefaultBearerNASAccept(t *testing.T) {
	mock := &capturingMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.ECGIPLMN = [3]byte{0x13, 0x51, 0x34}
	ue.ECGIECI = 0x05300c81
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:          "ims",
			DefaultEBI:   6,
			SGWAddress:   "10.90.250.59:2123",
			SGWC_TEID:    0x06f718d5,
			LocalS11TEID: 0x00000002,
		},
	}
	ue.Unlock()

	srv.completeIMSDefaultERABSetupForBearer(ue, ERABSetupResult{
		EBI:        6,
		Success:    true,
		ENBS1UTEID: 0x312e2aef,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
	}, srv.log)
	if len(mock.calls) != 0 {
		t.Fatalf("MBR calls after E-RAB setup got %d, want 0", len(mock.calls))
	}

	if err := srv.handleStandaloneBearerAccept(ue, &esm.ActivateDefaultEPSBearerContextAccept{EPSBearerID: 6}, srv.log); err != nil {
		t.Fatalf("handleStandaloneBearerAccept: %v", err)
	}
	ue.Lock()
	pdn := ue.PDNs["ims"]
	mmeID := ue.MMEUES1APID
	ue.Unlock()
	if pdn == nil || !pdn.ModifyBearerDeferred {
		t.Fatalf("PDN after NAS accept got %+v, want deferred MBR", pdn)
	}
	if len(mock.calls) != 0 {
		t.Fatalf("MBR calls before settle got %d, want 0", len(mock.calls))
	}

	srv.onIMSModifyBearerSettleTimeout(mmeID, 6)
	if len(mock.calls) != 1 {
		t.Fatalf("MBR calls after settle got %d, want 1", len(mock.calls))
	}
	got := mock.calls[0]
	if got.SGWC_TEID != 0x06f718d5 || got.EBI != 6 || got.ENBU_TEID != 0x312e2aef {
		t.Fatalf("MBR got %+v", got)
	}
	if got.ENBU_IP.String() != "192.168.105.247" {
		t.Fatalf("MBR ENBU_IP got %s, want 192.168.105.247", got.ENBU_IP.String())
	}
}

func TestIMSModifyBearerDoesNotOverlapWhenRepeatedAcceptsArrive(t *testing.T) {
	mock := &capturingMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.ECGIPLMN = [3]byte{0x13, 0x51, 0x34}
	ue.ECGIECI = 0x05300c81
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:             "ims",
			DefaultEBI:      6,
			SGWAddress:      "10.90.250.59:2123",
			SGWC_TEID:       0x06f718d5,
			LocalS11TEID:    0x00000002,
			ERABEstablished: true,
			ENBU_TEID:       0x312e2aef,
			ENBU_IP:         net.ParseIP("192.168.105.247").To4(),
		},
	}
	ue.Unlock()

	accept := &esm.ActivateDefaultEPSBearerContextAccept{EPSBearerID: 6}
	if err := srv.handleStandaloneBearerAccept(ue, accept, srv.log); err != nil {
		t.Fatalf("first handleStandaloneBearerAccept: %v", err)
	}
	if err := srv.handleStandaloneBearerAccept(ue, accept, srv.log); err != nil {
		t.Fatalf("second handleStandaloneBearerAccept: %v", err)
	}
	ue.Lock()
	mmeID := ue.MMEUES1APID
	ue.Unlock()
	if len(mock.calls) != 0 {
		t.Fatalf("MBR calls before settle got %d, want 0", len(mock.calls))
	}
	srv.onIMSModifyBearerSettleTimeout(mmeID, 6)
	if len(mock.calls) != 1 {
		t.Fatalf("MBR calls got %d, want 1", len(mock.calls))
	}
}

func TestIMSDefaultBearerNotReadyBeforeModifyBearerAccepted(t *testing.T) {
	mock := &capturingBearerAndMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.ECGIPLMN = [3]byte{0x13, 0x51, 0x34}
	ue.ECGIECI = 0x05300c81
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:              "ims",
			DefaultEBI:       6,
			SGWAddress:       "10.90.250.59:2123",
			SGWC_TEID:        0x06f718d5,
			LocalS11TEID:     0x00000002,
			NASAccepted:      true,
			ERABEstablished:  true,
			ModifyBearerSent: true,
			State:            "modify-bearer-pending",
			ENBU_TEID:        0x312e2aef,
			ENBU_IP:          net.ParseIP("192.168.105.247").To4(),
		},
	}
	ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{
		"peer|95|00000002|0001df": {
			ID:          "cbr-1-00000002-0001df",
			Kind:        bearerTxCreate,
			PeerAddress: "10.90.250.59:2123",
			LocalTEID:   0x00000002,
			SequenceNum: 0x0001df,
			LinkedEBI:   6,
			CreateState: uecontext.CreateBearerWaitingResults,
			State:       string(uecontext.CreateBearerWaitingResults),
			CreatedAt:   time.Now(),
		},
	}
	ue.Unlock()

	srv.maybeAdvanceDefaultBearer(ue, 6, "test", srv.log)
	if len(mock.calls) != 0 {
		t.Fatalf("MBR calls while waiting for MBR acceptance got %d, want 0", len(mock.calls))
	}
	ue.Lock()
	tx := ue.PendingBearerTransactions["peer|95|00000002|0001df"]
	ue.Unlock()
	if tx == nil || tx.CreateState != uecontext.CreateBearerWaitingResults {
		t.Fatalf("pending tx state got %+v, want waiting_results", tx)
	}
}

func TestIMSDefaultBearerPreservesModifyBearerPendingStateWhileWaiting(t *testing.T) {
	mock := &capturingBearerAndMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: false,
			ModifyBearerFailed:   false,
			State:                "modify-bearer-pending",
		},
	}
	ue.Unlock()

	srv.maybeAdvanceDefaultBearer(ue, 6, "test", srv.log)

	ue.Lock()
	pdn := ue.PDNs["ims"]
	ue.Unlock()
	if pdn == nil {
		t.Fatal("ims PDN missing")
	}
	if pdn.State != "modify-bearer-pending" {
		t.Fatalf("PDN state got %q, want modify-bearer-pending", pdn.State)
	}
}

func TestIMSDefaultBearerReadyAfterNASERABAndMBR(t *testing.T) {
	mock := &capturingBearerAndMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.ECGIPLMN = [3]byte{0x13, 0x51, 0x34}
	ue.ECGIECI = 0x05300c81
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:              "ims",
			DefaultEBI:       6,
			SGWAddress:       "10.90.250.59:2123",
			SGWC_TEID:        0x06f718d5,
			LocalS11TEID:     0x00000002,
			NASAccepted:      true,
			ERABEstablished:  true,
			ModifyBearerSent: true,
			State:            "modify-bearer-pending",
			ENBU_TEID:        0x312e2aef,
			ENBU_IP:          net.ParseIP("192.168.105.247").To4(),
		},
	}
	ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{
		"peer|95|00000002|0001df": {
			ID:          "cbr-1-00000002-0001df",
			Kind:        bearerTxCreate,
			PeerAddress: "10.90.250.59:2123",
			LocalTEID:   0x00000002,
			SequenceNum: 0x0001df,
			LinkedEBI:   6,
			Bearers: map[uint8]*uecontext.DedicatedBearerContext{
				7: {AssignedEBI: 7},
			},
			CreateState: uecontext.CreateBearerWaitingForLink,
			State:       string(uecontext.CreateBearerWaitingForLink),
			CreatedAt:   time.Now(),
		},
	}
	ue.Unlock()

	srv.HandleMBRResult(ue.MMEUES1APID, nil)

	ue.Lock()
	pdn := ue.PDNs["ims"]
	ue.Unlock()
	if pdn == nil || !pdn.ModifyBearerAccepted {
		t.Fatalf("PDN modify bearer accepted got %+v", pdn)
	}
}

func TestIMSModifyBearerTimeoutTriggersStandaloneFallback(t *testing.T) {
	mock := &capturingMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:              "ims",
			DefaultEBI:       6,
			SGWAddress:       "10.90.250.59:2123",
			SGWC_TEID:        0x06f718d5,
			NASAccepted:      true,
			ERABEstablished:  true,
			ModifyBearerSent: true,
			State:            "modify-bearer-pending",
			ENBU_TEID:        0x312e2aef,
			ENBU_IP:          net.ParseIP("192.168.105.247").To4(),
		},
	}
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	srv.onIMSModifyBearerTimeout(mmeID, 6)

	if len(mock.calls) != 1 {
		t.Fatalf("fallback MBR calls got %d, want 1", len(mock.calls))
	}
	ue.Lock()
	pdn := ue.PDNs["ims"]
	ue.Unlock()
	if pdn == nil || !pdn.ModifyBearerFallbackSent || pdn.ModifyBearerFailed {
		t.Fatalf("PDN after fallback got %+v", pdn)
	}
}

func TestIMSModifyBearerTimeoutAfterFallbackMarksFailed(t *testing.T) {
	mock := &capturingMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                      "ims",
			DefaultEBI:               6,
			SGWAddress:               "10.90.250.59:2123",
			SGWC_TEID:                0x06f718d5,
			NASAccepted:              true,
			ERABEstablished:          true,
			ModifyBearerSent:         true,
			ModifyBearerFallbackSent: true,
			State:                    "modify-bearer-pending",
			ENBU_TEID:                0x312e2aef,
			ENBU_IP:                  net.ParseIP("192.168.105.247").To4(),
		},
	}
	ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{
		"peer|95|00000002|0001df": {
			ID:          "cbr-1-00000002-0001df",
			Kind:        bearerTxCreate,
			PeerAddress: "10.90.250.59:2123",
			LocalTEID:   0x00000002,
			SequenceNum: 0x0001df,
			LinkedEBI:   6,
			CreateState: uecontext.CreateBearerWaitingResults,
			State:       string(uecontext.CreateBearerWaitingResults),
			CreatedAt:   time.Now(),
		},
	}
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	srv.onIMSModifyBearerTimeout(mmeID, 6)

	ue.Lock()
	pdn := ue.PDNs["ims"]
	tx, ok := ue.PendingBearerTransactions["peer|95|00000002|0001df"]
	ue.Unlock()
	if pdn == nil || !pdn.ModifyBearerFailed || pdn.State != "modify-bearer-failed" {
		t.Fatalf("PDN after fallback timeout got %+v", pdn)
	}
	if ok && tx != nil {
		t.Fatalf("pending Create Bearer transaction still present after fallback timeout: %+v", tx)
	}
}

func TestCreateBearerResponseSendsStandaloneIMSModifyBearerWhenDeferred(t *testing.T) {
	mock := &capturingBearerAndMBRS11{}
	srv := newTestServer(mock)
	srv.nfCfg = config.NFConfig{MCC: "311", MNC: "435"}
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.ECGIPLMN = [3]byte{0x13, 0x41, 0x53}
	ue.ECGIECI = 0x05300c81
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:             "ims",
			DefaultEBI:      6,
			SGWAddress:      "10.90.250.59:2123",
			SGWC_TEID:       0x06f718d5,
			LocalS11TEID:    0x00000002,
			NASAccepted:     true,
			ERABEstablished: true,
			ENBU_TEID:       0x312e2aef,
			ENBU_IP:         net.ParseIP("192.168.105.247").To4(),
		},
	}
	ue.Unlock()

	tx := &uecontext.DedicatedBearerTransaction{
		ID:          "cbr-1-00000002-0001df",
		Kind:        bearerTxCreate,
		PeerAddress: "10.90.250.59:2123",
		LocalTEID:   0x00000002,
		SequenceNum: 0x0001df,
		LinkedEBI:   6,
		Bearers: map[uint8]*uecontext.DedicatedBearerContext{
			7: {AssignedEBI: 7},
		},
		CreateState: uecontext.CreateBearerCompleted,
		State:       string(uecontext.CreateBearerCompleted),
		CreatedAt:   time.Now(),
	}

	srv.sendFinalCreateBearerResponse(tx, gtpv2.CauseRequestAccepted, []gtpv2.CreateBearerBearer{{AssignedEBI: 7}}, 0, 1, 0)

	if got := mock.createResponseCount(); got != 1 {
		t.Fatalf("plain create bearer responses got %d, want 1", got)
	}
	resp := mock.createResponseAt(0)
	if resp.TEID != 0x06f718d5 {
		t.Fatalf("Create Bearer Response TEID got 0x%x, want 0x06f718d5", resp.TEID)
	}
	if resp.Meta == nil || !resp.Meta.IncludeULI {
		t.Fatalf("response meta got %+v, want ULI included", resp.Meta)
	}
	if resp.Meta.ULIPLMN != ([3]byte{0x13, 0x51, 0x34}) {
		t.Fatalf("response ULI PLMN got %x, want 135134", resp.Meta.ULIPLMN)
	}
	ue.Lock()
	pdn := ue.PDNs["ims"]
	mmeID := ue.MMEUES1APID
	ue.Unlock()
	if pdn == nil || !pdn.ModifyBearerDeferred {
		t.Fatalf("PDN after Create Bearer Response got %+v, want deferred MBR", pdn)
	}
	if len(mock.calls) != 0 {
		t.Fatalf("standalone MBR calls before settle got %d, want 0", len(mock.calls))
	}
	srv.onIMSModifyBearerSettleTimeout(mmeID, 6)
	if len(mock.calls) != 1 {
		t.Fatalf("standalone MBR calls after settle got %d, want 1", len(mock.calls))
	}
	call := mock.calls[0]
	if call.EBI != 6 || call.SGWC_TEID != 0x06f718d5 || call.ENBU_TEID != 0x312e2aef {
		t.Fatalf("standalone MBR got %+v", call)
	}
	if !call.IncludeIndicationCRSI || !call.OmitRATType {
		t.Fatalf("standalone MBR flags got %+v, want indication=true omit_rattype=true", call)
	}
}

func TestCompletedFailedCreateBearerResponseSendsStandaloneIMSModifyBearerAfterResponse(t *testing.T) {
	mock := &capturingBearerAndMBRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.ECGIPLMN = [3]byte{0x13, 0x51, 0x34}
	ue.ECGIECI = 0x05300c81
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:             "ims",
			DefaultEBI:      6,
			SGWAddress:      "10.90.250.59:2123",
			SGWC_TEID:       0x06f718d5,
			LocalS11TEID:    0x00000002,
			NASAccepted:     true,
			ERABEstablished: true,
			ENBU_TEID:       0x312e2aef,
			ENBU_IP:         net.ParseIP("192.168.105.247").To4(),
		},
	}
	ue.Unlock()

	tx := &uecontext.DedicatedBearerTransaction{
		ID:          "cbr-1-00000002-0001df",
		Kind:        bearerTxCreate,
		PeerAddress: "10.90.250.59:2123",
		LocalTEID:   0x00000002,
		SequenceNum: 0x0001df,
		LinkedEBI:   6,
		Bearers: map[uint8]*uecontext.DedicatedBearerContext{
			7: {AssignedEBI: 7},
		},
		CreateState: uecontext.CreateBearerCompleted,
		State:       string(uecontext.CreateBearerCompleted),
		CreatedAt:   time.Now(),
	}

	srv.sendFinalCreateBearerResponse(tx, gtpv2.CauseRequestAccepted, []gtpv2.CreateBearerBearer{{AssignedEBI: 7}}, 0, 0, 1)

	if got := mock.createResponseCount(); got != 1 {
		t.Fatalf("plain create bearer responses got %d, want 1", got)
	}
	resp := mock.createResponseAt(0)
	if resp.TEID != 0x06f718d5 {
		t.Fatalf("Create Bearer Response TEID got 0x%x, want 0x06f718d5", resp.TEID)
	}
	ue.Lock()
	pdn := ue.PDNs["ims"]
	mmeID := ue.MMEUES1APID
	ue.Unlock()
	if pdn == nil || !pdn.ModifyBearerDeferred {
		t.Fatalf("PDN after Create Bearer Response got %+v, want deferred MBR", pdn)
	}
	if len(mock.calls) != 0 {
		t.Fatalf("standalone MBR calls before settle got %d, want 0", len(mock.calls))
	}
	srv.onIMSModifyBearerSettleTimeout(mmeID, 6)
	if len(mock.calls) != 1 {
		t.Fatalf("standalone MBR calls after settle got %d, want 1", len(mock.calls))
	}
	call := mock.calls[0]
	if call.EBI != 6 || call.SGWC_TEID != 0x06f718d5 || call.ENBU_TEID != 0x312e2aef {
		t.Fatalf("standalone MBR got %+v", call)
	}
}
