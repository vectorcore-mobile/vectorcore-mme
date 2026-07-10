package api_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/api"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/uecontext"
)

// stubDiamStatus satisfies api.DiamStatus for tests.
type stubDiamStatus struct{}

func (stubDiamStatus) Connected() bool { return false }

func newTestAPIServer(mgr *uecontext.Manager) http.Handler {
	log, _ := zap.NewDevelopment()
	srv := api.New(
		config.APIConfig{BindAddress: "127.0.0.1", BindPort: 8080},
		config.NFConfig{},
		config.OperatorConfig{},
		nil, // store — not needed for UE list/get tests
		nil, // enbTracker
		mgr,
		stubDiamStatus{},
		log,
	)
	return srv.Handler()
}

func newTestAPIServerWithENBTracker(tracker *peertracker.Tracker) http.Handler {
	log, _ := zap.NewDevelopment()
	srv := api.New(
		config.APIConfig{BindAddress: "127.0.0.1", BindPort: 8080},
		config.NFConfig{},
		config.OperatorConfig{},
		nil,
		tracker,
		uecontext.NewManager(),
		stubDiamStatus{},
		log,
	)
	return srv.Handler()
}

func TestListENBsReturnsStructuredSupportedTAs(t *testing.T) {
	tracker := peertracker.New()
	tracker.Add(peertracker.Peer{
		Name:         "srsenb01",
		GlobalENBID:  "311435-0-407",
		RemoteAddr:   "192.168.105.34:36412",
		Transport:    "sctp",
		SupportedTAs: `[{"TAC":1,"BroadcastPLMNs":[{"MCC":"311","MNC":"435"}]}]`,
	})

	h := newTestAPIServerWithENBTracker(tracker)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enodeb", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET enodeb expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ENBs []struct {
			SupportedTAs []struct {
				TAC            uint16 `json:"TAC"`
				BroadcastPLMNs []struct {
					MCC string `json:"MCC"`
					MNC string `json:"MNC"`
				} `json:"BroadcastPLMNs"`
			} `json:"supported_tas"`
		} `json:"enbs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal enodeb: %v", err)
	}
	if len(resp.ENBs) != 1 || len(resp.ENBs[0].SupportedTAs) != 1 {
		t.Fatalf("supported_tas = %+v, want one TA", resp.ENBs)
	}
	ta := resp.ENBs[0].SupportedTAs[0]
	if ta.TAC != 1 || len(ta.BroadcastPLMNs) != 1 || ta.BroadcastPLMNs[0].MCC != "311" || ta.BroadcastPLMNs[0].MNC != "435" {
		t.Fatalf("supported_tas[0] = %+v, want TAC 1 PLMN 311/435", ta)
	}
}

func TestListENBsNormalizesNullSupportedTAs(t *testing.T) {
	tracker := peertracker.New()
	tracker.Add(peertracker.Peer{
		Name:         "srsenb01",
		RemoteAddr:   "192.168.105.34:36412",
		Transport:    "sctp",
		SupportedTAs: "null",
	})

	h := newTestAPIServerWithENBTracker(tracker)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enodeb", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET enodeb expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ENBs []struct {
			SupportedTAs []interface{} `json:"supported_tas"`
		} `json:"enbs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal enodeb: %v", err)
	}
	if len(resp.ENBs) != 1 || resp.ENBs[0].SupportedTAs == nil || len(resp.ENBs[0].SupportedTAs) != 0 {
		t.Fatalf("supported_tas = %#v, want empty array", resp.ENBs)
	}
}

func TestListUEs_IncludesTunnelFields(t *testing.T) {
	mgr := uecontext.NewManager()
	ue := mgr.Allocate()
	ue.Lock()
	ue.IMSI = "204950000000001"
	ue.ENBS1APID = 7
	ue.ENBGlobalID = "311435-0-407"
	ue.APN = "internet"
	ue.DefaultEBI = 5
	ue.UEIPv4 = net.ParseIP("10.45.0.2").To4()
	ue.SGWU_TEID = 0x00000042
	ue.SGWU_IP = net.ParseIP("127.0.0.3").To4()
	ue.SGWC_TEID = 0x00000043
	ue.SGWC_IP = net.ParseIP("127.0.0.3").To4()
	ue.ENBU_TEID = 0x00000001
	ue.ENBU_IP = net.ParseIP("127.0.0.1").To4()
	ue.Unlock()
	mgr.Register(ue)

	h := newTestAPIServer(mgr)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ue", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		UEs   []map[string]interface{} `json:"ues"`
		Count int                      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("expected 1 UE, got %d", resp.Count)
	}

	entry := resp.UEs[0]
	checks := map[string]interface{}{
		"imsi":           "204950000000001",
		"enb_ue_s1ap_id": float64(7),
		"enb_global_id":  "311435-0-407",
		"ue_ipv4":        "10.45.0.2",
		"sgw_u_teid":     float64(0x42),
		"sgw_u_ip":       "127.0.0.3",
		"sgw_c_teid":     float64(0x43),
		"sgw_c_ip":       "127.0.0.3",
		"enb_u_teid":     float64(1),
		"enb_u_ip":       "127.0.0.1",
		"default_ebi":    float64(5),
	}
	for field, want := range checks {
		got, ok := entry[field]
		if !ok {
			t.Errorf("field %q missing from response", field)
			continue
		}
		if got != want {
			t.Errorf("field %q: got %v (%T), want %v (%T)", field, got, got, want, want)
		}
	}
}

func TestGetUEByIMSI_IncludesTunnelFields(t *testing.T) {
	mgr := uecontext.NewManager()
	ue := mgr.Allocate()
	ue.Lock()
	ue.IMSI = "204950000000002"
	ue.DefaultEBI = 5
	ue.UEIPv4 = net.ParseIP("10.45.0.3").To4()
	ue.SGWU_TEID = 0x000000FF
	ue.Unlock()
	mgr.Register(ue)

	h := newTestAPIServer(mgr)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ue/204950000000002", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := entry["ue_ipv4"]; got != "10.45.0.3" {
		t.Errorf("ue_ipv4: got %v, want 10.45.0.3", got)
	}
	if got := entry["sgw_u_teid"]; got != float64(0xFF) {
		t.Errorf("sgw_u_teid: got %v, want 255", got)
	}
	if got := entry["default_ebi"]; got != float64(5) {
		t.Errorf("default_ebi: got %v, want 5", got)
	}
}

func TestGetUEByIMSI_NotFound(t *testing.T) {
	mgr := uecontext.NewManager()
	h := newTestAPIServer(mgr)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ue/999999999999999", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestOAMDNSCacheEndpointsWithoutSelector(t *testing.T) {
	h := newTestAPIServer(uecontext.NewManager())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oam/dns-cache", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET dns cache expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var getResp struct {
		Entries []map[string]interface{} `json:"entries"`
		Count   int                      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("unmarshal GET dns cache: %v", err)
	}
	if getResp.Count != 0 || len(getResp.Entries) != 0 {
		t.Fatalf("GET dns cache = count %d entries %d, want empty", getResp.Count, len(getResp.Entries))
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/oam/dns-cache/flush", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST dns cache flush expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var flushResp struct {
		Flushed int `json:"flushed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &flushResp); err != nil {
		t.Fatalf("unmarshal POST dns cache flush: %v", err)
	}
	if flushResp.Flushed != 0 {
		t.Fatalf("flushed = %d, want 0", flushResp.Flushed)
	}
}

func TestOperatorPLMNComesFromNFConfig(t *testing.T) {
	log, _ := zap.NewDevelopment()
	srv := api.New(
		config.APIConfig{BindAddress: "127.0.0.1", BindPort: 8080},
		config.NFConfig{MCC: "311", MNC: "435"},
		config.OperatorConfig{},
		nil,
		nil,
		uecontext.NewManager(),
		stubDiamStatus{},
		log,
	)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/operator", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET operator expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		PLMN struct {
			MCC string `json:"mcc"`
			MNC string `json:"mnc"`
		} `json:"plmn"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal operator: %v", err)
	}
	if resp.PLMN.MCC != "311" || resp.PLMN.MNC != "435" {
		t.Fatalf("operator PLMN = %s/%s, want 311/435", resp.PLMN.MCC, resp.PLMN.MNC)
	}
}

func TestHumaDocsAndOpenAPIPaths(t *testing.T) {
	h := newTestAPIServer(uecontext.NewManager())

	for _, tc := range []struct {
		path        string
		contentType string
	}{
		{path: "/docs", contentType: "text/html"},
		{path: "/openapi.json", contentType: "application/openapi+json"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s expected 200, got %d: %s", tc.path, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, tc.contentType) {
			t.Fatalf("GET %s content-type = %q, want prefix %q", tc.path, got, tc.contentType)
		}
	}
}
