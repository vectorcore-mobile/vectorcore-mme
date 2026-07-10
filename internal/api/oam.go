package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

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
