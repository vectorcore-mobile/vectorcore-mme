package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/api"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/diameter/peer"
	"github.com/vectorcore/mme/internal/sbcap"
	"github.com/vectorcore/mme/internal/uecontext"
	"github.com/vectorcore/mme/internal/vlr"
)

type fakeDiamStatus struct{ peers []peer.PeerStatus }

func (f fakeDiamStatus) Connected() bool                  { return len(f.peers) > 0 }
func (f fakeDiamStatus) DiameterPeers() []peer.PeerStatus { return f.peers }

type fakeVLRStatus struct{ snap []vlr.VLRStatus }

func (f fakeVLRStatus) Snapshot() []vlr.VLRStatus { return f.snap }

type fakeSBcAPStatus struct{ snap []sbcap.PeerStatus }

func (f fakeSBcAPStatus) Snapshot() []sbcap.PeerStatus { return f.snap }

type fakeSLsStatus struct{ available bool }

func (f fakeSLsStatus) Available() bool { return f.available }

type interfacesResponse struct {
	Interfaces []struct {
		Interface string `json:"interface"`
		Peers     []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
			Healthy bool   `json:"healthy"`
			Detail  string `json:"detail"`
		} `json:"peers"`
	} `json:"interfaces"`
}

func TestGetInterfaces_OnlyWiredProvidersAppear(t *testing.T) {
	log, _ := zap.NewDevelopment()
	srv := api.New(
		config.APIConfig{BindAddress: "127.0.0.1", BindPort: 8080},
		config.NFConfig{},
		config.OperatorConfig{},
		nil,
		nil,
		uecontext.NewManager(),
		stubDiamStatus{}, // DiameterPeers() returns nil -> empty Diameter block
		log,
	)
	// vlrStatus/sbcapStatus/slsStatus intentionally left unset (disabled interfaces).

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oam/interfaces", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp interfacesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Interfaces) != 1 || resp.Interfaces[0].Interface != "Diameter" || len(resp.Interfaces[0].Peers) != 0 {
		t.Fatalf("interfaces = %+v, want only an empty Diameter block", resp.Interfaces)
	}
}

func TestGetInterfaces_ReportsWiredPeersAcrossInterfaces(t *testing.T) {
	log, _ := zap.NewDevelopment()
	srv := api.New(
		config.APIConfig{BindAddress: "127.0.0.1", BindPort: 8080},
		config.NFConfig{},
		config.OperatorConfig{},
		nil,
		nil,
		uecontext.NewManager(),
		fakeDiamStatus{peers: []peer.PeerStatus{
			{Name: "dra-1", Address: "10.0.0.1:3868", State: peer.Ready},
			{Name: "dra-2", Address: "10.0.0.2:3868", State: peer.Down},
		}},
		log,
	)
	srv.SetVLRStatus(fakeVLRStatus{snap: []vlr.VLRStatus{
		{Name: "vlr-1", Address: "10.90.250.42", Port: 29118, Available: true},
	}})
	srv.SetSBcAPStatus(fakeSBcAPStatus{snap: []sbcap.PeerStatus{
		{Name: "osmo-cbc-local", Addresses: []string{"127.0.0.1"}, Connected: false},
	}})
	srv.SetSLsStatus(fakeSLsStatus{available: true}, config.SLsConfig{RemoteAddress: "10.0.0.9", RemotePort: 9999})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oam/interfaces", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp interfacesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Interfaces) != 4 {
		t.Fatalf("expected 4 interface blocks, got %d: %+v", len(resp.Interfaces), resp.Interfaces)
	}

	byName := map[string][]struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Healthy bool   `json:"healthy"`
		Detail  string `json:"detail"`
	}{}
	for _, iface := range resp.Interfaces {
		byName[iface.Interface] = iface.Peers
	}

	diam := byName["Diameter"]
	if len(diam) != 2 || diam[0].Healthy != true || diam[0].Detail != "Ready" || diam[1].Healthy != false || diam[1].Detail != "Down" {
		t.Fatalf("Diameter peers = %+v", diam)
	}
	sgs := byName["SGs"]
	if len(sgs) != 1 || sgs[0].Name != "vlr-1" || sgs[0].Address != "10.90.250.42:29118" || !sgs[0].Healthy || sgs[0].Detail != "Associated" {
		t.Fatalf("SGs peers = %+v", sgs)
	}
	sbcapPeers := byName["SBc-AP"]
	if len(sbcapPeers) != 1 || sbcapPeers[0].Name != "osmo-cbc-local" || sbcapPeers[0].Healthy || sbcapPeers[0].Detail != "Down" {
		t.Fatalf("SBc-AP peers = %+v", sbcapPeers)
	}
	sls := byName["SLs"]
	if len(sls) != 1 || sls[0].Address != "10.0.0.9:9999" || !sls[0].Healthy || sls[0].Detail != "Connected" {
		t.Fatalf("SLs peers = %+v", sls)
	}
}
