package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/vectorcore/mme/internal/uecontext"
)

type UEEntry struct {
	MMEUES1APID        uint32   `json:"mme_ue_s1ap_id"`
	ENBUES1APID        uint32   `json:"enb_ue_s1ap_id,omitempty"`
	IMSI               string   `json:"imsi,omitempty"`
	GUTI               string   `json:"guti,omitempty"`
	TAI                string   `json:"tai,omitempty"`
	EMMState           string   `json:"emm_state"`
	ECMState           string   `json:"ecm_state"`
	RegistrationStatus string   `json:"registration_status"`
	ConnectionStatus   string   `json:"connection_status"`
	S1Connected        bool     `json:"s1_connected"`
	LastReleaseCause   string   `json:"last_release_cause,omitempty"`
	ENBGlobalID        string   `json:"enb_global_id,omitempty"`
	IntAlg             uint8    `json:"int_alg"`
	EncAlg             uint8    `json:"enc_alg"`
	MSISDN             *string  `json:"msisdn,omitempty"`
	APN                *string  `json:"apn,omitempty"`
	APNs               []string `json:"apns,omitempty"`
	DefaultEBI         uint8    `json:"default_ebi,omitempty"`
	UEIPv4             string   `json:"ue_ipv4,omitempty"`
	SGWU_TEID          uint32   `json:"sgw_u_teid,omitempty"`
	SGWU_IP            string   `json:"sgw_u_ip,omitempty"`
	SGWC_TEID          uint32   `json:"sgw_c_teid,omitempty"`
	SGWC_IP            string   `json:"sgw_c_ip,omitempty"`
	ENBU_TEID          uint32   `json:"enb_u_teid,omitempty"`
	ENBU_IP            string   `json:"enb_u_ip,omitempty"`
	LastSeen           string   `json:"last_seen,omitempty"`
	LastModified       string   `json:"last_modified,omitempty"`
}

type listUEsOutput struct {
	Body struct {
		UEs   []UEEntry `json:"ues"`
		Count int       `json:"count"`
	}
}

type getUEInput struct {
	IMSI string `path:"imsi"`
}

type getUEOutput struct {
	Body UEEntry
}

type pageUEInput struct {
	IMSI string `path:"imsi"`
}

type pageUEOutput struct {
	Body struct {
		Status string `json:"status"`
	}
}

func registerUEHandlers(api huma.API, s *Server) {
	huma.Register(api, huma.Operation{
		OperationID: "list-ues",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/ue",
		Summary:     "List attached UEs",
		Tags:        []string{"UE"},
	}, s.listUEs)

	huma.Register(api, huma.Operation{
		OperationID: "get-ue-by-imsi",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/ue/{imsi}",
		Summary:     "Get UE by IMSI",
		Tags:        []string{"UE"},
	}, s.getUEByIMSI)

	huma.Register(api, huma.Operation{
		OperationID: "page-ue",
		Method:      http.MethodPost,
		Path:        apiPrefix + "/ue/{imsi}/page",
		Summary:     "Trigger S1AP Paging (OAM/debug)",
		Tags:        []string{"UE"},
	}, s.pageUE)
}

func (s *Server) listUEs(_ context.Context, _ *struct{}) (*listUEsOutput, error) {
	ues := s.ueManager.List()
	out := &listUEsOutput{}
	for _, ue := range ues {
		ue.Lock()
		entry := s.ueEntryLocked(ue)
		ue.Unlock()
		out.Body.UEs = append(out.Body.UEs, entry)
	}
	out.Body.Count = len(out.Body.UEs)
	return out, nil
}

func (s *Server) pageUE(_ context.Context, input *pageUEInput) (*pageUEOutput, error) {
	if s.pager == nil {
		return nil, huma.Error503ServiceUnavailable("S1AP pager not available")
	}
	if err := s.pager.PageUE(input.IMSI); err != nil {
		if err.Error() == "IMSI not found" {
			return nil, huma.Error404NotFound(err.Error())
		}
		return nil, huma.Error400BadRequest(err.Error())
	}
	out := &pageUEOutput{}
	out.Body.Status = "paging"
	return out, nil
}

func (s *Server) getUEByIMSI(_ context.Context, input *getUEInput) (*getUEOutput, error) {
	ue, ok := s.ueManager.GetByIMSI(input.IMSI)
	if !ok {
		return nil, huma.Error404NotFound("UE not found")
	}
	ue.Lock()
	defer ue.Unlock()
	return &getUEOutput{Body: s.ueEntryLocked(ue)}, nil
}

func (s *Server) ueEntryLocked(ue *uecontext.Context) UEEntry {
	entry := UEEntry{
		MMEUES1APID:        ue.MMEUES1APID,
		ENBUES1APID:        ue.ENBS1APID,
		IMSI:               ue.IMSI,
		EMMState:           ue.EMMState.String(),
		ECMState:           ue.ECMState.String(),
		RegistrationStatus: registrationStatus(ue.EMMState.String()),
		ConnectionStatus:   connectionStatus(ue.ECMState.String(), ue.ENBGlobalID),
		S1Connected:        ue.ECMState.String() == "ECM-CONNECTED" && ue.ENBGlobalID != "",
		LastReleaseCause:   ue.LastReleaseCause,
		ENBGlobalID:        s.displayENBGlobalID(ue.ENBGlobalID),
		IntAlg:             ue.IntAlg,
		EncAlg:             ue.EncAlg,
		APNs:               append([]string(nil), ue.SubscriberAPNs...),
		DefaultEBI:         ue.DefaultEBI,
		SGWU_TEID:          ue.SGWU_TEID,
		SGWC_TEID:          ue.SGWC_TEID,
		ENBU_TEID:          ue.ENBU_TEID,
	}
	if ue.GUTI != nil {
		entry.GUTI = ue.GUTI.String()
	}
	if ue.TAI != nil {
		entry.TAI = fmt.Sprintf("%02X%02X%02X-%d", ue.TAI.PLMN[0], ue.TAI.PLMN[1], ue.TAI.PLMN[2], ue.TAI.TAC)
	}
	if ue.MSISDN != "" {
		ms := ue.MSISDN
		entry.MSISDN = &ms
	}
	if ue.APN != "" {
		a := ue.APN
		entry.APN = &a
	}
	if ue.UEIPv4 != nil {
		entry.UEIPv4 = ue.UEIPv4.String()
	}
	if ue.SGWU_IP != nil {
		entry.SGWU_IP = ue.SGWU_IP.String()
	}
	if ue.SGWC_IP != nil {
		entry.SGWC_IP = ue.SGWC_IP.String()
	}
	if ue.ENBU_IP != nil {
		entry.ENBU_IP = ue.ENBU_IP.String()
	}
	if !ue.UpdatedAt.IsZero() {
		ts := ue.UpdatedAt.UTC().Format(time.RFC3339)
		entry.LastSeen = ts
		entry.LastModified = ts
	}
	return entry
}

func registrationStatus(emmState string) string {
	switch emmState {
	case "EMM-REGISTERED":
		return "registered"
	case "EMM-DEREGISTERED":
		return "deregistered"
	default:
		return emmState
	}
}

func connectionStatus(ecmState, enb string) string {
	if ecmState == "ECM-CONNECTED" && enb != "" {
		return "connected"
	}
	return "idle"
}

func (s *Server) displayENBGlobalID(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if s.enbTracker != nil {
		if p, ok := s.enbTracker.Get(remoteAddr); ok && p.GlobalENBID != "" {
			return p.GlobalENBID
		}
	}
	return remoteAddr
}
