package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

type ENBEntry struct {
	GlobalENBID string `json:"global_enb_id,omitempty"`
	Name        string `json:"enb_name,omitempty"`
	RemoteAddr  string `json:"remote_addr"`
	Transport   string `json:"transport"`
	ConnectedAt string `json:"connected_at"`
	LastSeen    string `json:"last_seen,omitempty"`
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
		Path:        "/enodeb",
		Summary:     "List connected eNodeBs",
		Tags:        []string{"eNodeB"},
	}, s.listENBs)
}

func (s *Server) listENBs(_ context.Context, _ *struct{}) (*listENBsOutput, error) {
	peers := s.enbTracker.List()
	out := &listENBsOutput{}
	for _, p := range peers {
		out.Body.ENBs = append(out.Body.ENBs, ENBEntry{
			Name:        p.Name,
			RemoteAddr:  p.RemoteAddr,
			Transport:   p.Transport,
			ConnectedAt: p.ConnectedAt.UTC().Format(time.RFC3339),
		})
	}
	out.Body.Count = len(out.Body.ENBs)
	return out, nil
}
