package pdu

import "github.com/vectorcore/mme/internal/asn1/aper"

type IEPresence string

const (
	IEPresenceMandatory   IEPresence = "mandatory"
	IEPresenceOptional    IEPresence = "optional"
	IEPresenceConditional IEPresence = "conditional"
)

type ProcedureDirection string

const (
	DirectionENBToMME ProcedureDirection = "eNB->MME"
	DirectionMMEToENB ProcedureDirection = "MME->eNB"
)

type ProcedureInfo struct {
	Name      string
	PDUType   PDUType
	Code      uint8
	Direction ProcedureDirection
}

type IEInfo struct {
	Name        string
	ID          uint16
	Criticality aper.Criticality
	Presence    IEPresence
	ValueType   string
}

type ProcedureIEKey struct {
	ProcedureCode uint8
	PDUType       PDUType
	IEID          uint16
}

var Phase1Procedures = []ProcedureInfo{
	{Name: "S1SetupRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcS1Setup, Direction: DirectionENBToMME},
	{Name: "S1SetupResponse", PDUType: PDUTypeSuccessfulOutcome, Code: ProcS1Setup, Direction: DirectionMMEToENB},
	{Name: "S1SetupFailure", PDUType: PDUTypeUnsuccessfulOutcome, Code: ProcS1Setup, Direction: DirectionMMEToENB},
	{Name: "InitialUEMessage", PDUType: PDUTypeInitiatingMessage, Code: ProcInitialUEMessage, Direction: DirectionENBToMME},
	{Name: "DownlinkNASTransport", PDUType: PDUTypeInitiatingMessage, Code: ProcDownlinkNASTransport, Direction: DirectionMMEToENB},
	{Name: "UplinkNASTransport", PDUType: PDUTypeInitiatingMessage, Code: ProcUplinkNASTransport, Direction: DirectionENBToMME},
	{Name: "InitialContextSetupRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcInitialContextSetup, Direction: DirectionMMEToENB},
	{Name: "InitialContextSetupResponse", PDUType: PDUTypeSuccessfulOutcome, Code: ProcInitialContextSetup, Direction: DirectionENBToMME},
	{Name: "InitialContextSetupFailure", PDUType: PDUTypeUnsuccessfulOutcome, Code: ProcInitialContextSetup, Direction: DirectionENBToMME},
	{Name: "E-RABSetupRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcERABSetup, Direction: DirectionMMEToENB},
	{Name: "E-RABSetupResponse", PDUType: PDUTypeSuccessfulOutcome, Code: ProcERABSetup, Direction: DirectionENBToMME},
	{Name: "UEContextReleaseRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcUEContextReleaseRequest, Direction: DirectionENBToMME},
	{Name: "UEContextReleaseCommand", PDUType: PDUTypeInitiatingMessage, Code: ProcUEContextRelease, Direction: DirectionMMEToENB},
	{Name: "UEContextReleaseComplete", PDUType: PDUTypeSuccessfulOutcome, Code: ProcUEContextRelease, Direction: DirectionENBToMME},
	{Name: "ErrorIndication", PDUType: PDUTypeInitiatingMessage, Code: ProcErrorIndication, Direction: DirectionENBToMME},
	{Name: "UECapabilityInfoIndication", PDUType: PDUTypeInitiatingMessage, Code: ProcUECapabilityInfoIndication, Direction: DirectionENBToMME},
}

var Phase1ProcedureIEs = map[ProcedureIEKey]IEInfo{
	{ProcS1Setup, PDUTypeInitiatingMessage, IEGlobal_ENB_ID}:       {"Global-ENB-ID", IEGlobal_ENB_ID, aper.CriticalityReject, IEPresenceMandatory, "Global-ENB-ID"},
	{ProcS1Setup, PDUTypeInitiatingMessage, IEeNBname}:             {"eNBname", IEeNBname, aper.CriticalityIgnore, IEPresenceOptional, "ENBname"},
	{ProcS1Setup, PDUTypeInitiatingMessage, IESupportedTAs}:        {"SupportedTAs", IESupportedTAs, aper.CriticalityReject, IEPresenceMandatory, "SupportedTAs"},
	{ProcS1Setup, PDUTypeInitiatingMessage, IEDefaultPagingDRX}:    {"DefaultPagingDRX", IEDefaultPagingDRX, aper.CriticalityIgnore, IEPresenceMandatory, "PagingDRX"},
	{ProcS1Setup, PDUTypeSuccessfulOutcome, IEServedGUMMEIs}:       {"ServedGUMMEIs", IEServedGUMMEIs, aper.CriticalityReject, IEPresenceMandatory, "ServedGUMMEIs"},
	{ProcS1Setup, PDUTypeSuccessfulOutcome, IERelativeMMECapacity}: {"RelativeMMECapacity", IERelativeMMECapacity, aper.CriticalityIgnore, IEPresenceMandatory, "RelativeMMECapacity"},
	{ProcS1Setup, PDUTypeUnsuccessfulOutcome, IECause}:             {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},

	{ProcInitialUEMessage, PDUTypeInitiatingMessage, IEENBS1APID}:                     {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcInitialUEMessage, PDUTypeInitiatingMessage, IENAS_PDU}:                       {"NAS-PDU", IENAS_PDU, aper.CriticalityReject, IEPresenceMandatory, "NAS-PDU"},
	{ProcInitialUEMessage, PDUTypeInitiatingMessage, IETAI}:                           {"TAI", IETAI, aper.CriticalityReject, IEPresenceMandatory, "TAI"},
	{ProcInitialUEMessage, PDUTypeInitiatingMessage, IECGI}:                           {"EUTRAN-CGI", IECGI, aper.CriticalityIgnore, IEPresenceMandatory, "EUTRAN-CGI"},
	{ProcInitialUEMessage, PDUTypeInitiatingMessage, IERRCEstablishmentCause}:         {"RRC-Establishment-Cause", IERRCEstablishmentCause, aper.CriticalityIgnore, IEPresenceMandatory, "RRC-Establishment-Cause"},
	{ProcInitialUEMessage, PDUTypeInitiatingMessage, IESTMSI}:                         {"S-TMSI", IESTMSI, aper.CriticalityReject, IEPresenceOptional, "S-TMSI"},
	{ProcDownlinkNASTransport, PDUTypeInitiatingMessage, IEMMEUES1APID}:               {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcDownlinkNASTransport, PDUTypeInitiatingMessage, IEENBS1APID}:                 {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcDownlinkNASTransport, PDUTypeInitiatingMessage, IENAS_PDU}:                   {"NAS-PDU", IENAS_PDU, aper.CriticalityReject, IEPresenceMandatory, "NAS-PDU"},
	{ProcUplinkNASTransport, PDUTypeInitiatingMessage, IEMMEUES1APID}:                 {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUplinkNASTransport, PDUTypeInitiatingMessage, IEENBS1APID}:                   {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUplinkNASTransport, PDUTypeInitiatingMessage, IENAS_PDU}:                     {"NAS-PDU", IENAS_PDU, aper.CriticalityReject, IEPresenceMandatory, "NAS-PDU"},
	{ProcUplinkNASTransport, PDUTypeInitiatingMessage, IECGI}:                         {"EUTRAN-CGI", IECGI, aper.CriticalityIgnore, IEPresenceMandatory, "EUTRAN-CGI"},
	{ProcUplinkNASTransport, PDUTypeInitiatingMessage, IETAI}:                         {"TAI", IETAI, aper.CriticalityIgnore, IEPresenceMandatory, "TAI"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IEMMEUES1APID}:                {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IEENBS1APID}:                  {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IEUEAggregateMaxBitrate}:      {"UEAggregateMaximumBitrate", IEUEAggregateMaxBitrate, aper.CriticalityReject, IEPresenceMandatory, "UEAggregateMaximumBitrate"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IEERABToBeSetupListCtxtSUReq}: {"E-RABToBeSetupListCtxtSUReq", IEERABToBeSetupListCtxtSUReq, aper.CriticalityReject, IEPresenceMandatory, "E-RABToBeSetupListCtxtSUReq"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IEUESecurityCapabilities}:     {"UESecurityCapabilities", IEUESecurityCapabilities, aper.CriticalityReject, IEPresenceMandatory, "UESecurityCapabilities"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IESecurityKey}:                {"SecurityKey", IESecurityKey, aper.CriticalityReject, IEPresenceMandatory, "SecurityKey"},
	{ProcInitialContextSetup, PDUTypeInitiatingMessage, IENAS_PDU}:                    {"NAS-PDU", IENAS_PDU, aper.CriticalityIgnore, IEPresenceOptional, "NAS-PDU"},
	{ProcInitialContextSetup, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcInitialContextSetup, PDUTypeSuccessfulOutcome, IEENBS1APID}:                  {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcInitialContextSetup, PDUTypeSuccessfulOutcome, IEERABSetupListCtxtSURes}:     {"E-RABSetupListCtxtSURes", IEERABSetupListCtxtSURes, aper.CriticalityIgnore, IEPresenceMandatory, "E-RABSetupListCtxtSURes"},
	{ProcInitialContextSetup, PDUTypeUnsuccessfulOutcome, IEMMEUES1APID}:              {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcInitialContextSetup, PDUTypeUnsuccessfulOutcome, IEENBS1APID}:                {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcInitialContextSetup, PDUTypeUnsuccessfulOutcome, IECause}:                    {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},

	{ProcERABSetup, PDUTypeInitiatingMessage, IEMMEUES1APID}:                        {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeInitiatingMessage, IEENBS1APID}:                          {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeInitiatingMessage, IEUEAggregateMaxBitrate}:              {"UEAggregateMaximumBitrate", IEUEAggregateMaxBitrate, aper.CriticalityReject, IEPresenceOptional, "UEAggregateMaximumBitrate"},
	{ProcERABSetup, PDUTypeInitiatingMessage, IEERABToBeSetupListBearerSUReq}:       {"E-RABToBeSetupListBearerSUReq", IEERABToBeSetupListBearerSUReq, aper.CriticalityReject, IEPresenceMandatory, "E-RABToBeSetupListBearerSUReq"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                        {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEENBS1APID}:                          {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEERABSetupListBearerSURes}:           {"E-RABSetupListBearerSURes", IEERABSetupListBearerSURes, aper.CriticalityIgnore, IEPresenceOptional, "E-RABSetupListBearerSURes"},
	{ProcUEContextReleaseRequest, PDUTypeInitiatingMessage, IEMMEUES1APID}:          {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextReleaseRequest, PDUTypeInitiatingMessage, IEENBS1APID}:            {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUEContextReleaseRequest, PDUTypeInitiatingMessage, IECause}:                {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcUEContextRelease, PDUTypeInitiatingMessage, IEUES1APIDs}:                   {"UE-S1AP-IDs", IEUES1APIDs, aper.CriticalityReject, IEPresenceMandatory, "UE-S1AP-IDs"},
	{ProcUEContextRelease, PDUTypeInitiatingMessage, IECause}:                       {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcUEContextRelease, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                 {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextRelease, PDUTypeSuccessfulOutcome, IEENBS1APID}:                   {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IEMMEUES1APID}:                  {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceOptional, "MME-UE-S1AP-ID"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IEENBS1APID}:                    {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceOptional, "ENB-UE-S1AP-ID"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IECause}:                        {"Cause", IECause, aper.CriticalityIgnore, IEPresenceOptional, "Cause"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IECriticalityDiagnostics}:       {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcUECapabilityInfoIndication, PDUTypeInitiatingMessage, IEMMEUES1APID}:       {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUECapabilityInfoIndication, PDUTypeInitiatingMessage, IEENBS1APID}:         {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUECapabilityInfoIndication, PDUTypeInitiatingMessage, IEUERadioCapability}: {"UE-RadioCapability", IEUERadioCapability, aper.CriticalityIgnore, IEPresenceMandatory, "UERadioCapability"},
}
