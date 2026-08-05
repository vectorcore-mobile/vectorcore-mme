package vlr

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/sgsap"
)

type fakeTransport struct {
	mu   sync.Mutex
	sent [][]byte
	ok   bool
}

func (f *fakeTransport) setHandlers(func([]byte), func(), func(error)) {}
func (f *fakeTransport) available() bool                               { return f.ok }
func (f *fakeTransport) send(_ context.Context, b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, append([]byte(nil), b...))
	return nil
}
func (f *fakeTransport) start(context.Context) {}
func (f *fakeTransport) close() error          { return nil }

func (f *fakeTransport) last() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil
	}
	return f.sent[len(f.sent)-1]
}

type fakeHandler struct {
	mu            sync.Mutex
	resets        []string
	ups           []string
	luAccept      *sgsap.LocationUpdateAccept
	luReject      *sgsap.LocationUpdateReject
	paging        *sgsap.PagingRequest
	downlink      *sgsap.DownlinkUnitdata
	releaseIMSI   string
	releaseCause  *sgsap.Cause
	epsDetachAck  string
	imsiDetachAck string
	alertIMSI     string
	mmInfo        *sgsap.MMInformationRequest
	abortIMSI     string
	status        *sgsap.Status
}

func (h *fakeHandler) HandleLocationUpdateAccept(_ string, a *sgsap.LocationUpdateAccept) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.luAccept = a
}
func (h *fakeHandler) HandleLocationUpdateReject(_ string, r *sgsap.LocationUpdateReject) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.luReject = r
}
func (h *fakeHandler) HandlePagingRequest(_ string, r *sgsap.PagingRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paging = r
}
func (h *fakeHandler) HandleDownlinkUnitdata(_ string, d *sgsap.DownlinkUnitdata) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.downlink = d
}
func (h *fakeHandler) HandleReleaseRequest(_ string, imsi string, cause *sgsap.Cause) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.releaseIMSI, h.releaseCause = imsi, cause
}
func (h *fakeHandler) HandleEPSDetachAck(_ string, imsi string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.epsDetachAck = imsi
}
func (h *fakeHandler) HandleIMSIDetachAck(_ string, imsi string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.imsiDetachAck = imsi
}
func (h *fakeHandler) HandleAlertRequest(_ string, imsi string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alertIMSI = imsi
}
func (h *fakeHandler) HandleMMInformationRequest(_ string, r *sgsap.MMInformationRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mmInfo = r
}
func (h *fakeHandler) HandleServiceAbortRequest(_ string, imsi string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.abortIMSI = imsi
}
func (h *fakeHandler) HandleStatus(_ string, s *sgsap.Status) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status = s
}
func (h *fakeHandler) OnVLRReset(vlrName string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.resets = append(h.resets, vlrName)
}
func (h *fakeHandler) OnVLRAssociationUp(vlrName string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ups = append(h.ups, vlrName)
}

func testManager(t *testing.T) (*Manager, *fakeTransport, *fakeHandler) {
	t.Helper()
	cfg := config.SGsConfig{
		Enabled:           true,
		ReconnectInterval: time.Second,
		RequestTimeout:    time.Second,
		VLR:               []config.SGsVLRConfig{{Name: "vlr-1", Address: "192.0.2.50", Port: 29118}},
		TAILAIMap: []config.SGsTAILAIMapItem{{
			TAI: config.TAIItem{MCC: "001", MNC: "01", TAC: 1},
			LAI: config.SGsLAIItem{MCC: "001", MNC: "01", LAC: 1},
			VLR: "vlr-1",
		}},
	}
	h := &fakeHandler{}
	m := New(cfg, "mme.example.org", h, nil)
	ft := &fakeTransport{ok: true}
	m.associations["vlr-1"].transport = ft
	return m, ft, h
}

func TestOnConnectSendsResetIndication(t *testing.T) {
	m, ft, _ := testManager(t)
	m.onConnect("vlr-1")
	got, err := sgsap.DecodeResetIndication(ft.last())
	if err != nil {
		t.Fatal(err)
	}
	if got.MMEName != "mme.example.org" {
		t.Fatalf("reset indication MME name = %q", got.MMEName)
	}
	if m.Available("vlr-1") {
		t.Fatal("association must not be available before the Reset procedure completes")
	}
}

func TestHandleResetIndicationFromVLRAcksAndNotifies(t *testing.T) {
	m, ft, h := testManager(t)
	req := sgsap.BuildResetIndication(sgsap.Reset{VLRName: "vlr-1.example.org"})
	m.onMessage("vlr-1", req)

	ack, err := sgsap.DecodeResetAck(ft.last())
	if err != nil {
		t.Fatal(err)
	}
	if ack.MMEName != "mme.example.org" {
		t.Fatalf("reset ack MME name = %q", ack.MMEName)
	}
	if len(h.resets) != 1 || h.resets[0] != "vlr-1" {
		t.Fatalf("OnVLRReset calls = %v", h.resets)
	}
	if len(h.ups) != 1 || h.ups[0] != "vlr-1" {
		t.Fatalf("OnVLRAssociationUp calls = %v", h.ups)
	}
	if !m.Available("vlr-1") {
		t.Fatal("association must be available after acking a VLR Reset Indication")
	}
}

func TestHandleResetAckMarksAssociationUp(t *testing.T) {
	m, _, h := testManager(t)
	ack := sgsap.BuildResetAck(sgsap.Reset{VLRName: "vlr-1.example.org"})
	m.onMessage("vlr-1", ack)
	if len(h.ups) != 1 || h.ups[0] != "vlr-1" {
		t.Fatalf("OnVLRAssociationUp calls = %v", h.ups)
	}
	if !m.Available("vlr-1") {
		t.Fatal("association must be available after our Reset Indication is acked")
	}
}

func TestOnLossMarksAssociationDown(t *testing.T) {
	m, _, _ := testManager(t)
	m.onMessage("vlr-1", sgsap.BuildResetAck(sgsap.Reset{VLRName: "vlr-1.example.org"}))
	if !m.Available("vlr-1") {
		t.Fatal("expected available before loss")
	}
	m.onLoss("vlr-1", context.Canceled)
	if m.Available("vlr-1") {
		t.Fatal("expected unavailable after association loss")
	}
}

func TestDispatchLocationUpdateAcceptAndReject(t *testing.T) {
	m, _, h := testManager(t)
	plmn, err := sgsap.EncodePLMN("001", "01")
	if err != nil {
		t.Fatal(err)
	}
	lai := sgsap.LAI{PLMN: plmn, LAC: 1}
	accept, err := sgsap.BuildLocationUpdateAccept(sgsap.LocationUpdateAccept{IMSI: "001010123456789", LAI: lai})
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", accept)
	if h.luAccept == nil || h.luAccept.IMSI != "001010123456789" {
		t.Fatalf("location update accept dispatch = %+v", h.luAccept)
	}

	reject, err := sgsap.BuildLocationUpdateReject(sgsap.LocationUpdateReject{IMSI: "001010123456789", Cause: 13})
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", reject)
	if h.luReject == nil || h.luReject.Cause != 13 {
		t.Fatalf("location update reject dispatch = %+v", h.luReject)
	}
}

func TestDispatchPagingDownlinkReleaseAlertMMInfoAbortStatus(t *testing.T) {
	m, _, h := testManager(t)

	paging, err := sgsap.BuildPagingRequest(sgsap.PagingRequest{IMSI: "001010123456789", VLRName: "vlr-1.example.org", ServiceIndicator: sgsap.ServiceIndicatorSMS})
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", paging)
	if h.paging == nil || h.paging.IMSI != "001010123456789" {
		t.Fatalf("paging request dispatch = %+v", h.paging)
	}

	downlink, err := sgsap.BuildDownlinkUnitdata(sgsap.DownlinkUnitdata{IMSI: "001010123456789", NASMessageContainer: []byte{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", downlink)
	if h.downlink == nil || h.downlink.IMSI != "001010123456789" {
		t.Fatalf("downlink unitdata dispatch = %+v", h.downlink)
	}

	release, err := sgsap.BuildReleaseRequest("001010123456789", nil)
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", release)
	if h.releaseIMSI != "001010123456789" || h.releaseCause != nil {
		t.Fatalf("release request dispatch = %q %v", h.releaseIMSI, h.releaseCause)
	}

	alert, err := sgsap.BuildAlertRequest("001010123456789")
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", alert)
	if h.alertIMSI != "001010123456789" {
		t.Fatalf("alert request dispatch = %q", h.alertIMSI)
	}

	mmInfo, err := sgsap.BuildMMInformationRequest(sgsap.MMInformationRequest{IMSI: "001010123456789", MMInformation: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", mmInfo)
	if h.mmInfo == nil || h.mmInfo.IMSI != "001010123456789" {
		t.Fatalf("MM information request dispatch = %+v", h.mmInfo)
	}

	abort, err := sgsap.BuildServiceAbortRequest("001010123456789")
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", abort)
	if h.abortIMSI != "001010123456789" {
		t.Fatalf("service abort request dispatch = %q", h.abortIMSI)
	}

	status, err := sgsap.BuildStatus(sgsap.Status{Cause: sgsap.CauseMessageUnknown, ErroneousMessage: []byte{sgsap.MsgPagingRequest}})
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", status)
	if h.status == nil || h.status.Cause != sgsap.CauseMessageUnknown {
		t.Fatalf("status dispatch = %+v", h.status)
	}
}

func TestDispatchEPSAndIMSIDetachAck(t *testing.T) {
	m, _, h := testManager(t)

	epsAck, err := sgsap.BuildEPSDetachAck("001010123456789")
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", epsAck)
	if h.epsDetachAck != "001010123456789" {
		t.Fatalf("EPS detach ack dispatch = %q", h.epsDetachAck)
	}

	imsiAck, err := sgsap.BuildIMSIDetachAck("001010123456789")
	if err != nil {
		t.Fatal(err)
	}
	m.onMessage("vlr-1", imsiAck)
	if h.imsiDetachAck != "001010123456789" {
		t.Fatalf("IMSI detach ack dispatch = %q", h.imsiDetachAck)
	}
}

func TestSendWrappersRoundTripThroughTransport(t *testing.T) {
	m, ft, _ := testManager(t)
	plmn, err := sgsap.EncodePLMN("001", "01")
	if err != nil {
		t.Fatal(err)
	}
	lai := sgsap.LAI{PLMN: plmn, LAC: 1}
	if err := m.SendLocationUpdateRequest("vlr-1", sgsap.LocationUpdateRequest{
		IMSI: "001010123456789", MMEName: "mme.example.org", UpdateType: sgsap.EPSLocationUpdateTypeNormal, NewLAI: lai,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := sgsap.DecodeLocationUpdateRequest(ft.last())
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" {
		t.Fatalf("sent location update request = %+v", got)
	}

	if err := m.SendTMSIReallocationComplete("vlr-1", "001010123456789"); err != nil {
		t.Fatal(err)
	}
	if imsi, err := sgsap.DecodeTMSIReallocationComplete(ft.last()); err != nil || imsi != "001010123456789" {
		t.Fatalf("sent TMSI reallocation complete = %q %v", imsi, err)
	}

	if err := m.SendPagingReject("vlr-1", "001010123456789", sgsap.CauseUEUnreachable); err != nil {
		t.Fatal(err)
	}
	if imsi, cause, err := sgsap.DecodePagingReject(ft.last()); err != nil || imsi != "001010123456789" || cause != sgsap.CauseUEUnreachable {
		t.Fatalf("sent paging reject = %q %v %v", imsi, cause, err)
	}
}

func TestSendToUnknownVLRReturnsError(t *testing.T) {
	m, _, _ := testManager(t)
	if err := m.SendAlertAck("does-not-exist", "001010123456789"); err == nil {
		t.Fatal("expected error sending to an unconfigured VLR")
	}
}

func TestLookupVLR(t *testing.T) {
	m, _, _ := testManager(t)
	item, ok := m.LookupVLR("001", "01", 1)
	if !ok || item.VLR != "vlr-1" || item.LAI.LAC != 1 {
		t.Fatalf("LookupVLR = %+v, %v", item, ok)
	}
	if _, ok := m.LookupVLR("001", "01", 99); ok {
		t.Fatal("expected no mapping for an unconfigured TAC")
	}
}
