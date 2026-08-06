package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/vectorcore/mme/internal/diameter/peer"
	"github.com/vectorcore/mme/internal/gateway"
)

type versionOutput struct {
	Body struct {
		AppName     string `json:"app_name"`
		AppVersion  string `json:"app_version"`
		OriginHost  string `json:"origin_host"`
		OriginRealm string `json:"origin_realm"`
		MCC         string `json:"mcc"`
		MNC         string `json:"mnc"`
		MMEGI       uint16 `json:"mmegi"`
		MMEC        uint8  `json:"mmec"`
	}
}

type healthOutput struct {
	Body struct {
		Status        string  `json:"status"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		AttachedUEs   int     `json:"attached_ues"`
		ConnectedENBs int     `json:"connected_enbs"`
		S6aConnected  bool    `json:"s6a_connected"`
	}
}

type peerStatusItem struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Healthy bool   `json:"healthy"`
	Detail  string `json:"detail"`
}

type interfaceStatusItem struct {
	Interface string           `json:"interface"`
	Peers     []peerStatusItem `json:"peers"`
}

type interfacesOutput struct {
	Body struct {
		Interfaces []interfaceStatusItem `json:"interfaces"`
	}
}

type dnsCacheOutput struct {
	Body struct {
		Entries []gateway.DNSCacheEntry `json:"entries"`
		Count   int                     `json:"count"`
	}
}

type flushDNSCacheOutput struct {
	Body struct {
		Flushed int `json:"flushed"`
	}
}

func registerOAMHandlers(api huma.API, s *Server) {
	huma.Register(api, huma.Operation{
		OperationID: "get-version",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/oam/version",
		Summary:     "Get MME version and identity",
		Tags:        []string{"OAM"},
	}, s.getVersion)

	huma.Register(api, huma.Operation{
		OperationID: "get-health",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/oam/health",
		Summary:     "Get MME health",
		Tags:        []string{"OAM"},
	}, s.getHealth)

	huma.Register(api, huma.Operation{
		OperationID: "get-interfaces",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/oam/interfaces",
		Summary:     "Get status of enabled interfaces and their peers",
		Tags:        []string{"OAM"},
	}, s.getInterfaces)

	huma.Register(api, huma.Operation{
		OperationID: "get-dns-cache",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/oam/dns-cache",
		Summary:     "Get in-memory gateway DNS cache entries",
		Tags:        []string{"OAM"},
	}, s.getDNSCache)

	huma.Register(api, huma.Operation{
		OperationID: "flush-dns-cache",
		Method:      http.MethodPost,
		Path:        apiPrefix + "/oam/dns-cache/flush",
		Summary:     "Flush in-memory gateway DNS cache entries",
		Tags:        []string{"OAM"},
	}, s.flushDNSCache)
}

func (s *Server) getVersion(_ context.Context, _ *struct{}) (*versionOutput, error) {
	out := &versionOutput{}
	out.Body.AppName = "VectorCore MME"
	out.Body.AppVersion = appVersion
	out.Body.OriginHost = s.nfCfg.OriginHost
	out.Body.OriginRealm = s.nfCfg.OriginRealm
	out.Body.MCC = s.nfCfg.MCC
	out.Body.MNC = s.nfCfg.MNC
	out.Body.MMEGI = s.nfCfg.MMEGI
	out.Body.MMEC = s.nfCfg.MMEC
	return out, nil
}

func (s *Server) getHealth(_ context.Context, _ *struct{}) (*healthOutput, error) {
	out := &healthOutput{}
	out.Body.Status = "ok"
	out.Body.UptimeSeconds = time.Since(startTime).Seconds()
	out.Body.AttachedUEs = s.ueManager.Count()
	out.Body.ConnectedENBs = s.enbTracker.Count()
	if s.s6a != nil {
		out.Body.S6aConnected = s.s6a.Connected()
	}
	return out, nil
}

// getInterfaces reports every enabled, connection-oriented interface and its
// configured peers. Disabled interfaces (nil provider) are simply omitted -
// there is nothing to report for them. S1AP/eNBs are intentionally excluded
// (already covered by GET /enodeb); S10/S11 are excluded too (stateless
// GTP-C request/response, no persistent connection to report).
func (s *Server) getInterfaces(_ context.Context, _ *struct{}) (*interfacesOutput, error) {
	out := &interfacesOutput{}

	if s.s6a != nil {
		peers := s.s6a.DiameterPeers()
		items := make([]peerStatusItem, 0, len(peers))
		for _, p := range peers {
			items = append(items, peerStatusItem{
				Name:    p.Name,
				Address: p.Address,
				Healthy: p.State == peer.Ready,
				Detail:  string(p.State),
			})
		}
		out.Body.Interfaces = append(out.Body.Interfaces, interfaceStatusItem{Interface: "Diameter", Peers: items})
	}

	if s.vlrStatus != nil {
		vlrs := s.vlrStatus.Snapshot()
		items := make([]peerStatusItem, 0, len(vlrs))
		for _, v := range vlrs {
			detail := "Down"
			if v.Available {
				detail = "Associated"
			}
			items = append(items, peerStatusItem{
				Name:    v.Name,
				Address: fmt.Sprintf("%s:%d", v.Address, v.Port),
				Healthy: v.Available,
				Detail:  detail,
			})
		}
		out.Body.Interfaces = append(out.Body.Interfaces, interfaceStatusItem{Interface: "SGs", Peers: items})
	}

	if s.sbcapStatus != nil {
		peers := s.sbcapStatus.Snapshot()
		items := make([]peerStatusItem, 0, len(peers))
		for _, p := range peers {
			detail := "Down"
			if p.Connected {
				detail = "Connected"
			}
			items = append(items, peerStatusItem{
				Name:    p.Name,
				Address: strings.Join(p.Addresses, ", "),
				Healthy: p.Connected,
				Detail:  detail,
			})
		}
		out.Body.Interfaces = append(out.Body.Interfaces, interfaceStatusItem{Interface: "SBc-AP", Peers: items})
	}

	if s.slsStatus != nil {
		available := s.slsStatus.Available()
		detail := "Down"
		if available {
			detail = "Connected"
		}
		out.Body.Interfaces = append(out.Body.Interfaces, interfaceStatusItem{
			Interface: "SLs",
			Peers: []peerStatusItem{{
				Name:    "e-smlc",
				Address: fmt.Sprintf("%s:%d", s.slsCfg.RemoteAddress, s.slsCfg.RemotePort),
				Healthy: available,
				Detail:  detail,
			}},
		})
	}

	return out, nil
}

func (s *Server) getDNSCache(_ context.Context, _ *struct{}) (*dnsCacheOutput, error) {
	out := &dnsCacheOutput{}
	if s.gatewaySel != nil {
		out.Body.Entries = s.gatewaySel.DNSCacheSnapshot()
	}
	out.Body.Count = len(out.Body.Entries)
	return out, nil
}

func (s *Server) flushDNSCache(_ context.Context, _ *struct{}) (*flushDNSCacheOutput, error) {
	out := &flushDNSCacheOutput{}
	if s.gatewaySel != nil {
		out.Body.Flushed = s.gatewaySel.FlushDNSCache()
	}
	return out, nil
}
