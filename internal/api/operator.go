package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type operatorOutput struct {
	Body struct {
		PLMN struct {
			MCC string `json:"mcc"`
			MNC string `json:"mnc"`
		} `json:"plmn"`
		FullName           string `json:"full_name,omitempty"`
		ShortName          string `json:"short_name,omitempty"`
		NameEncoding       string `json:"name_encoding"`
		AddCountryInitials bool   `json:"add_country_initials"`
		ShowFull           bool   `json:"show_full"`
		ShowShort          bool   `json:"show_short"`
		NITZEnabled        bool   `json:"nitz_enabled"`
		TimezoneOffset     int    `json:"timezone_offset_minutes,omitempty"`
		DaylightSaving     uint8  `json:"daylight_saving,omitempty"`
		EMMInfoEnabled     bool   `json:"emm_information_enabled"`
		SendAfterAttach    bool   `json:"send_after_attach"`
		SendAfterTAU       bool   `json:"send_after_tau"`
	}
}

func registerOperatorHandlers(api huma.API, s *Server) {
	huma.Register(api, huma.Operation{
		OperationID: "get-operator",
		Method:      http.MethodGet,
		Path:        apiPrefix + "/operator",
		Summary:     "Get operator identity and NITZ configuration",
		Tags:        []string{"Operator"},
	}, s.getOperator)
}

func (s *Server) getOperator(_ context.Context, _ *struct{}) (*operatorOutput, error) {
	cfg := s.operCfg
	out := &operatorOutput{}
	out.Body.PLMN.MCC = s.nfCfg.MCC
	out.Body.PLMN.MNC = s.nfCfg.MNC
	out.Body.FullName = cfg.Name.Full
	out.Body.ShortName = cfg.Name.Short
	out.Body.NameEncoding = cfg.Name.Encoding
	out.Body.AddCountryInitials = cfg.Name.AddCountryInitials
	out.Body.ShowFull = cfg.Name.ShowFull
	out.Body.ShowShort = cfg.Name.ShowShort
	out.Body.NITZEnabled = cfg.NITZ.Enabled
	out.Body.TimezoneOffset = cfg.NITZ.TimezoneOffsetMinutes
	out.Body.DaylightSaving = cfg.NITZ.DaylightSaving
	out.Body.EMMInfoEnabled = cfg.EMMInformation.Enabled
	out.Body.SendAfterAttach = cfg.EMMInformation.SendAfterAttach
	out.Body.SendAfterTAU = cfg.EMMInformation.SendAfterTAU
	return out, nil
}
