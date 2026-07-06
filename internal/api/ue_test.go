package api_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/api"
	"github.com/vectorcore/mme/internal/config"
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

func TestListUEs_IncludesTunnelFields(t *testing.T) {
	mgr := uecontext.NewManager()
	ue := mgr.Allocate()
	ue.Lock()
	ue.IMSI = "204950000000001"
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
		"imsi":        "204950000000001",
		"ue_ipv4":     "10.45.0.2",
		"sgw_u_teid":  float64(0x42),
		"sgw_u_ip":    "127.0.0.3",
		"sgw_c_teid":  float64(0x43),
		"sgw_c_ip":    "127.0.0.3",
		"enb_u_teid":  float64(1),
		"enb_u_ip":    "127.0.0.1",
		"default_ebi": float64(5),
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
