package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

type ENBEntry struct {
	GlobalENBID  string          `json:"global_enb_id,omitempty"`
	Name         string          `json:"enb_name,omitempty"`
	RemoteAddr   string          `json:"remote_addr"`
	Transport    string          `json:"transport"`
	SupportedTAs json.RawMessage `json:"supported_tas"`
	ConnectedAt  string          `json:"connected_at"`
	LastSeen     string          `json:"last_seen,omitempty"`
}

type listENBsOutput struct {
	Body struct {
		ENBs  []ENBEntry `json:"enbs"`
		Count int        `json:"count"`
	}
}

func registerENBHandlers(api huma.API, s *Server) {
	huma.Register(api, huma.Operation{
		OperationID: "list-enodebs",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/enodeb",
		Summary:     "List connected eNodeBs",
		Tags:        []string{"eNodeB"},
	}, s.listENBs)
}

func (s *Server) listENBs(_ context.Context, _ *struct{}) (*listENBsOutput, error) {
	peers := s.enbTracker.List()
	out := &listENBsOutput{}
	for _, p := range peers {
		lastSeen := ""
		if !p.LastSeen.IsZero() {
			lastSeen = p.LastSeen.UTC().Format(time.RFC3339)
		}
		out.Body.ENBs = append(out.Body.ENBs, ENBEntry{
			GlobalENBID:  p.GlobalENBID,
			Name:         p.Name,
			RemoteAddr:   p.RemoteAddr,
			Transport:    p.Transport,
			SupportedTAs: supportedTAsJSON(p.SupportedTAs),
			ConnectedAt:  p.ConnectedAt.UTC().Format(time.RFC3339),
			LastSeen:     lastSeen,
		})
	}
	out.Body.Count = len(out.Body.ENBs)
	return out, nil
}

func supportedTAsJSON(raw string) json.RawMessage {
	if raw == "" || !json.Valid([]byte(raw)) || string(raw) == "null" {
		return json.RawMessage("[]")
	}
	return json.RawMessage(raw)
}
