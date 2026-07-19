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
	{Name: "E-RABModifyRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcERABModify, Direction: DirectionMMEToENB},
	{Name: "E-RABModifyResponse", PDUType: PDUTypeSuccessfulOutcome, Code: ProcERABModify, Direction: DirectionENBToMME},
	{Name: "E-RABModifyFailure", PDUType: PDUTypeUnsuccessfulOutcome, Code: ProcERABModify, Direction: DirectionENBToMME},
	{Name: "E-RABModificationIndication", PDUType: PDUTypeInitiatingMessage, Code: ProcERABModificationIndication, Direction: DirectionENBToMME},
	{Name: "E-RABModificationConfirm", PDUType: PDUTypeSuccessfulOutcome, Code: ProcERABModificationIndication, Direction: DirectionMMEToENB},
	{Name: "E-RABReleaseRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcERABRelease, Direction: DirectionMMEToENB},
	{Name: "E-RABReleaseResponse", PDUType: PDUTypeSuccessfulOutcome, Code: ProcERABRelease, Direction: DirectionENBToMME},
	{Name: "UEContextReleaseRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcUEContextReleaseRequest, Direction: DirectionENBToMME},
	{Name: "UEContextReleaseCommand", PDUType: PDUTypeInitiatingMessage, Code: ProcUEContextRelease, Direction: DirectionMMEToENB},
	{Name: "UEContextReleaseComplete", PDUType: PDUTypeSuccessfulOutcome, Code: ProcUEContextRelease, Direction: DirectionENBToMME},
	{Name: "ErrorIndication", PDUType: PDUTypeInitiatingMessage, Code: ProcErrorIndication, Direction: DirectionENBToMME},
	{Name: "UECapabilityInfoIndication", PDUType: PDUTypeInitiatingMessage, Code: ProcUECapabilityInfoIndication, Direction: DirectionENBToMME},
	{Name: "Reset", PDUType: PDUTypeInitiatingMessage, Code: ProcReset, Direction: DirectionENBToMME},
	{Name: "ResetAcknowledge", PDUType: PDUTypeSuccessfulOutcome, Code: ProcReset, Direction: DirectionMMEToENB},
	{Name: "UEContextModificationRequest", PDUType: PDUTypeInitiatingMessage, Code: ProcUEContextModification, Direction: DirectionMMEToENB},
	{Name: "UEContextModificationResponse", PDUType: PDUTypeSuccessfulOutcome, Code: ProcUEContextModification, Direction: DirectionENBToMME},
	{Name: "UEContextModificationFailure", PDUType: PDUTypeUnsuccessfulOutcome, Code: ProcUEContextModification, Direction: DirectionENBToMME},
	{Name: "ENBConfigurationUpdate", PDUType: PDUTypeInitiatingMessage, Code: ProcENBConfigurationUpdate, Direction: DirectionENBToMME},
	{Name: "ENBConfigurationUpdateAcknowledge", PDUType: PDUTypeSuccessfulOutcome, Code: ProcENBConfigurationUpdate, Direction: DirectionMMEToENB},
	{Name: "ENBConfigurationUpdateFailure", PDUType: PDUTypeUnsuccessfulOutcome, Code: ProcENBConfigurationUpdate, Direction: DirectionMMEToENB},
}

var Phase1ProcedureIEs = map[ProcedureIEKey]IEInfo{
	{ProcS1Setup, PDUTypeInitiatingMessage, IEGlobal_ENB_ID}:       {"Global-ENB-ID", IEGlobal_ENB_ID, aper.CriticalityReject, IEPresenceMandatory, "Global-ENB-ID"},
	{ProcS1Setup, PDUTypeInitiatingMessage, IEeNBname}:             {"eNBname", IEeNBname, aper.CriticalityIgnore, IEPresenceOptional, "ENBname"},
	{ProcS1Setup, PDUTypeInitiatingMessage, IESupportedTAs}:        {"SupportedTAs", IESupportedTAs, aper.CriticalityReject, IEPresenceMandatory, "SupportedTAs"},
	{ProcS1Setup, PDUTypeInitiatingMessage, IEDefaultPagingDRX}:    {"DefaultPagingDRX", IEDefaultPagingDRX, aper.CriticalityIgnore, IEPresenceMandatory, "PagingDRX"},
	{ProcS1Setup, PDUTypeSuccessfulOutcome, IEMMEname}:             {"MMEname", IEMMEname, aper.CriticalityIgnore, IEPresenceOptional, "MMEname"},
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

	{ProcERABSetup, PDUTypeInitiatingMessage, IEMMEUES1APID}:                                          {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeInitiatingMessage, IEENBS1APID}:                                            {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeInitiatingMessage, IEUEAggregateMaxBitrate}:                                {"UEAggregateMaximumBitrate", IEUEAggregateMaxBitrate, aper.CriticalityReject, IEPresenceOptional, "UEAggregateMaximumBitrate"},
	{ProcERABSetup, PDUTypeInitiatingMessage, IEERABToBeSetupListBearerSUReq}:                         {"E-RABToBeSetupListBearerSUReq", IEERABToBeSetupListBearerSUReq, aper.CriticalityReject, IEPresenceMandatory, "E-RABToBeSetupListBearerSUReq"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                                          {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEENBS1APID}:                                            {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEERABSetupListBearerSURes}:                             {"E-RABSetupListBearerSURes", IEERABSetupListBearerSURes, aper.CriticalityIgnore, IEPresenceOptional, "E-RABSetupListBearerSURes"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IEERABFailedToSetupListBearerSURes}:                     {"E-RABFailedToSetupListBearerSURes", IEERABFailedToSetupListBearerSURes, aper.CriticalityIgnore, IEPresenceOptional, "E-RABFailedToSetupListBearerSURes"},
	{ProcERABSetup, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:                               {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcERABModify, PDUTypeInitiatingMessage, IEMMEUES1APID}:                                         {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABModify, PDUTypeInitiatingMessage, IEENBS1APID}:                                           {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABModify, PDUTypeInitiatingMessage, IEUEAggregateMaxBitrate}:                               {"UEAggregateMaximumBitrate", IEUEAggregateMaxBitrate, aper.CriticalityReject, IEPresenceOptional, "UEAggregateMaximumBitrate"},
	{ProcERABModify, PDUTypeInitiatingMessage, IEERABToBeModifiedListBearerModReq}:                    {"E-RABToBeModifiedListBearerModReq", IEERABToBeModifiedListBearerModReq, aper.CriticalityReject, IEPresenceMandatory, "E-RABToBeModifiedListBearerModReq"},
	{ProcERABModify, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                                         {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABModify, PDUTypeSuccessfulOutcome, IEENBS1APID}:                                           {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABModify, PDUTypeSuccessfulOutcome, IEERABModifyListBearerModRes}:                          {"E-RABModifyListBearerModRes", IEERABModifyListBearerModRes, aper.CriticalityIgnore, IEPresenceOptional, "E-RABModifyListBearerModRes"},
	{ProcERABModify, PDUTypeSuccessfulOutcome, IEERABFailedToModifyList}:                              {"E-RABFailedToModifyList", IEERABFailedToModifyList, aper.CriticalityIgnore, IEPresenceOptional, "E-RABList"},
	{ProcERABModify, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:                              {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcERABModify, PDUTypeUnsuccessfulOutcome, IEMMEUES1APID}:                                       {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABModify, PDUTypeUnsuccessfulOutcome, IEENBS1APID}:                                         {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABModify, PDUTypeUnsuccessfulOutcome, IECause}:                                             {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcERABModify, PDUTypeUnsuccessfulOutcome, IECriticalityDiagnostics}:                            {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcERABModificationIndication, PDUTypeInitiatingMessage, IEMMEUES1APID}:                         {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABModificationIndication, PDUTypeInitiatingMessage, IEENBS1APID}:                           {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABModificationIndication, PDUTypeInitiatingMessage, IEERABToBeModifiedListBearerModInd}:    {"E-RABToBeModifiedListBearerModInd", IEERABToBeModifiedListBearerModInd, aper.CriticalityReject, IEPresenceMandatory, "E-RABToBeModifiedListBearerModInd"},
	{ProcERABModificationIndication, PDUTypeInitiatingMessage, IEERABNotToBeModifiedListBearerModInd}: {"E-RABNotToBeModifiedListBearerModInd", IEERABNotToBeModifiedListBearerModInd, aper.CriticalityReject, IEPresenceOptional, "E-RABNotToBeModifiedListBearerModInd"},
	{ProcERABModificationIndication, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                         {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABModificationIndication, PDUTypeSuccessfulOutcome, IEENBS1APID}:                           {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABModificationIndication, PDUTypeSuccessfulOutcome, IEERABModifyListBearerModConf}:         {"E-RABModifyListBearerModConf", IEERABModifyListBearerModConf, aper.CriticalityIgnore, IEPresenceOptional, "E-RABModifyListBearerModConf"},
	{ProcERABModificationIndication, PDUTypeSuccessfulOutcome, IEERABFailedToModifyListBearerModConf}: {"E-RABFailedToModifyListBearerModConf", IEERABFailedToModifyListBearerModConf, aper.CriticalityIgnore, IEPresenceOptional, "E-RABList"},
	{ProcERABModificationIndication, PDUTypeSuccessfulOutcome, IEERABToBeReleasedListBearerModConf}:   {"E-RABToBeReleasedListBearerModConf", IEERABToBeReleasedListBearerModConf, aper.CriticalityIgnore, IEPresenceOptional, "E-RABList"},
	{ProcERABModificationIndication, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:              {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcERABRelease, PDUTypeInitiatingMessage, IEMMEUES1APID}:                                        {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABRelease, PDUTypeInitiatingMessage, IEENBS1APID}:                                          {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABRelease, PDUTypeInitiatingMessage, IEERABToBeReleasedList}:                               {"E-RABToBeReleasedList", IEERABToBeReleasedList, aper.CriticalityIgnore, IEPresenceMandatory, "E-RABList"},
	{ProcERABRelease, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                                        {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcERABRelease, PDUTypeSuccessfulOutcome, IEENBS1APID}:                                          {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcERABRelease, PDUTypeSuccessfulOutcome, IEERABReleaseListERABRelComp}:                         {"E-RABReleaseListBearerRelComp", IEERABReleaseListERABRelComp, aper.CriticalityIgnore, IEPresenceOptional, "E-RABReleaseListBearerRelComp"},
	{ProcERABRelease, PDUTypeSuccessfulOutcome, IEERABFailedToReleaseList}:                            {"E-RABFailedToReleaseList", IEERABFailedToReleaseList, aper.CriticalityIgnore, IEPresenceOptional, "E-RABList"},
	{ProcERABRelease, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:                             {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcUEContextReleaseRequest, PDUTypeInitiatingMessage, IEMMEUES1APID}:                            {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextReleaseRequest, PDUTypeInitiatingMessage, IEENBS1APID}:                              {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUEContextReleaseRequest, PDUTypeInitiatingMessage, IECause}:                                  {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcUEContextRelease, PDUTypeInitiatingMessage, IEUES1APIDs}:                                     {"UE-S1AP-IDs", IEUES1APIDs, aper.CriticalityReject, IEPresenceMandatory, "UE-S1AP-IDs"},
	{ProcUEContextRelease, PDUTypeInitiatingMessage, IECause}:                                         {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcUEContextRelease, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                                   {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextRelease, PDUTypeSuccessfulOutcome, IEENBS1APID}:                                     {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IEMMEUES1APID}:                                    {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceOptional, "MME-UE-S1AP-ID"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IEENBS1APID}:                                      {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceOptional, "ENB-UE-S1AP-ID"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IECause}:                                          {"Cause", IECause, aper.CriticalityIgnore, IEPresenceOptional, "Cause"},
	{ProcErrorIndication, PDUTypeInitiatingMessage, IECriticalityDiagnostics}:                         {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcUECapabilityInfoIndication, PDUTypeInitiatingMessage, IEMMEUES1APID}:                         {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUECapabilityInfoIndication, PDUTypeInitiatingMessage, IEENBS1APID}:                           {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUECapabilityInfoIndication, PDUTypeInitiatingMessage, IEUERadioCapability}:                   {"UE-RadioCapability", IEUERadioCapability, aper.CriticalityIgnore, IEPresenceMandatory, "UERadioCapability"},
	{ProcReset, PDUTypeInitiatingMessage, IECause}:                                                    {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcReset, PDUTypeInitiatingMessage, IEResetType}:                                                {"ResetType", IEResetType, aper.CriticalityReject, IEPresenceMandatory, "ResetType"},
	{ProcReset, PDUTypeSuccessfulOutcome, IEUEAssociatedLogicalS1ConnectionListResAck}:                {"UE-associatedLogicalS1-ConnectionListResAck", IEUEAssociatedLogicalS1ConnectionListResAck, aper.CriticalityIgnore, IEPresenceOptional, "UE-associatedLogicalS1-ConnectionListResAck"},
	{ProcReset, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:                                   {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcUEContextModification, PDUTypeInitiatingMessage, IEMMEUES1APID}:                              {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityReject, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextModification, PDUTypeInitiatingMessage, IEENBS1APID}:                                {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityReject, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUEContextModification, PDUTypeInitiatingMessage, IESecurityKey}:                              {"SecurityKey", IESecurityKey, aper.CriticalityReject, IEPresenceOptional, "SecurityKey"},
	{ProcUEContextModification, PDUTypeInitiatingMessage, IEUEAggregateMaxBitrate}:                    {"UEAggregateMaximumBitrate", IEUEAggregateMaxBitrate, aper.CriticalityIgnore, IEPresenceOptional, "UEAggregateMaximumBitrate"},
	{ProcUEContextModification, PDUTypeInitiatingMessage, IEUESecurityCapabilities}:                   {"UESecurityCapabilities", IEUESecurityCapabilities, aper.CriticalityReject, IEPresenceOptional, "UESecurityCapabilities"},
	{ProcUEContextModification, PDUTypeSuccessfulOutcome, IEMMEUES1APID}:                              {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextModification, PDUTypeSuccessfulOutcome, IEENBS1APID}:                                {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUEContextModification, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:                   {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcUEContextModification, PDUTypeUnsuccessfulOutcome, IEMMEUES1APID}:                            {"MME-UE-S1AP-ID", IEMMEUES1APID, aper.CriticalityIgnore, IEPresenceMandatory, "MME-UE-S1AP-ID"},
	{ProcUEContextModification, PDUTypeUnsuccessfulOutcome, IEENBS1APID}:                              {"eNB-UE-S1AP-ID", IEENBS1APID, aper.CriticalityIgnore, IEPresenceMandatory, "ENB-UE-S1AP-ID"},
	{ProcUEContextModification, PDUTypeUnsuccessfulOutcome, IECause}:                                  {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcUEContextModification, PDUTypeUnsuccessfulOutcome, IECriticalityDiagnostics}:                 {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcENBConfigurationUpdate, PDUTypeInitiatingMessage, IEeNBname}:                                 {"eNBname", IEeNBname, aper.CriticalityIgnore, IEPresenceOptional, "ENBname"},
	{ProcENBConfigurationUpdate, PDUTypeInitiatingMessage, IESupportedTAs}:                            {"SupportedTAs", IESupportedTAs, aper.CriticalityReject, IEPresenceOptional, "SupportedTAs"},
	{ProcENBConfigurationUpdate, PDUTypeInitiatingMessage, IEDefaultPagingDRX}:                        {"DefaultPagingDRX", IEDefaultPagingDRX, aper.CriticalityIgnore, IEPresenceOptional, "PagingDRX"},
	{ProcENBConfigurationUpdate, PDUTypeSuccessfulOutcome, IECriticalityDiagnostics}:                  {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
	{ProcENBConfigurationUpdate, PDUTypeUnsuccessfulOutcome, IECause}:                                 {"Cause", IECause, aper.CriticalityIgnore, IEPresenceMandatory, "Cause"},
	{ProcENBConfigurationUpdate, PDUTypeUnsuccessfulOutcome, IECriticalityDiagnostics}:                {"CriticalityDiagnostics", IECriticalityDiagnostics, aper.CriticalityIgnore, IEPresenceOptional, "CriticalityDiagnostics"},
}

var Phase1ProcedureIEOrder = map[ProcedureIEKey][]uint16{
	{ProcedureCode: ProcS1Setup, PDUType: PDUTypeInitiatingMessage}:                    {IEGlobal_ENB_ID, IEeNBname, IESupportedTAs, IEDefaultPagingDRX},
	{ProcedureCode: ProcS1Setup, PDUType: PDUTypeSuccessfulOutcome}:                    {IEMMEname, IEServedGUMMEIs, IERelativeMMECapacity},
	{ProcedureCode: ProcS1Setup, PDUType: PDUTypeUnsuccessfulOutcome}:                  {IECause},
	{ProcedureCode: ProcInitialUEMessage, PDUType: PDUTypeInitiatingMessage}:           {IEENBS1APID, IENAS_PDU, IETAI, IECGI, IERRCEstablishmentCause, IESTMSI},
	{ProcedureCode: ProcDownlinkNASTransport, PDUType: PDUTypeInitiatingMessage}:       {IEMMEUES1APID, IEENBS1APID, IENAS_PDU},
	{ProcedureCode: ProcUplinkNASTransport, PDUType: PDUTypeInitiatingMessage}:         {IEMMEUES1APID, IEENBS1APID, IENAS_PDU, IECGI, IETAI},
	{ProcedureCode: ProcInitialContextSetup, PDUType: PDUTypeInitiatingMessage}:        {IEMMEUES1APID, IEENBS1APID, IEUEAggregateMaxBitrate, IEERABToBeSetupListCtxtSUReq, IEUESecurityCapabilities, IESecurityKey, IENAS_PDU},
	{ProcedureCode: ProcInitialContextSetup, PDUType: PDUTypeSuccessfulOutcome}:        {IEMMEUES1APID, IEENBS1APID, IEERABSetupListCtxtSURes},
	{ProcedureCode: ProcInitialContextSetup, PDUType: PDUTypeUnsuccessfulOutcome}:      {IEMMEUES1APID, IEENBS1APID, IECause},
	{ProcedureCode: ProcERABSetup, PDUType: PDUTypeInitiatingMessage}:                  {IEMMEUES1APID, IEENBS1APID, IEUEAggregateMaxBitrate, IEERABToBeSetupListBearerSUReq},
	{ProcedureCode: ProcERABSetup, PDUType: PDUTypeSuccessfulOutcome}:                  {IEMMEUES1APID, IEENBS1APID, IEERABSetupListBearerSURes, IEERABFailedToSetupListBearerSURes, IECriticalityDiagnostics},
	{ProcedureCode: ProcERABModify, PDUType: PDUTypeInitiatingMessage}:                 {IEMMEUES1APID, IEENBS1APID, IEUEAggregateMaxBitrate, IEERABToBeModifiedListBearerModReq},
	{ProcedureCode: ProcERABModify, PDUType: PDUTypeSuccessfulOutcome}:                 {IEMMEUES1APID, IEENBS1APID, IEERABModifyListBearerModRes, IEERABFailedToModifyList, IECriticalityDiagnostics},
	{ProcedureCode: ProcERABModify, PDUType: PDUTypeUnsuccessfulOutcome}:               {IEMMEUES1APID, IEENBS1APID, IECause, IECriticalityDiagnostics},
	{ProcedureCode: ProcERABModificationIndication, PDUType: PDUTypeInitiatingMessage}: {IEMMEUES1APID, IEENBS1APID, IEERABToBeModifiedListBearerModInd, IEERABNotToBeModifiedListBearerModInd},
	{ProcedureCode: ProcERABModificationIndication, PDUType: PDUTypeSuccessfulOutcome}: {IEMMEUES1APID, IEENBS1APID, IEERABModifyListBearerModConf, IEERABFailedToModifyListBearerModConf, IEERABToBeReleasedListBearerModConf, IECriticalityDiagnostics},
	{ProcedureCode: ProcERABRelease, PDUType: PDUTypeInitiatingMessage}:                {IEMMEUES1APID, IEENBS1APID, IEERABToBeReleasedList},
	{ProcedureCode: ProcERABRelease, PDUType: PDUTypeSuccessfulOutcome}:                {IEMMEUES1APID, IEENBS1APID, IEERABReleaseListERABRelComp, IEERABFailedToReleaseList, IECriticalityDiagnostics},
	{ProcedureCode: ProcUEContextReleaseRequest, PDUType: PDUTypeInitiatingMessage}:    {IEMMEUES1APID, IEENBS1APID, IECause},
	{ProcedureCode: ProcUEContextRelease, PDUType: PDUTypeInitiatingMessage}:           {IEUES1APIDs, IECause},
	{ProcedureCode: ProcUEContextRelease, PDUType: PDUTypeSuccessfulOutcome}:           {IEMMEUES1APID, IEENBS1APID},
	{ProcedureCode: ProcErrorIndication, PDUType: PDUTypeInitiatingMessage}:            {IEMMEUES1APID, IEENBS1APID, IECause, IECriticalityDiagnostics},
	{ProcedureCode: ProcUECapabilityInfoIndication, PDUType: PDUTypeInitiatingMessage}: {IEMMEUES1APID, IEENBS1APID, IEUERadioCapability},
	{ProcedureCode: ProcReset, PDUType: PDUTypeInitiatingMessage}:                      {IECause, IEResetType},
	{ProcedureCode: ProcReset, PDUType: PDUTypeSuccessfulOutcome}:                      {IEUEAssociatedLogicalS1ConnectionListResAck, IECriticalityDiagnostics},
	{ProcedureCode: ProcUEContextModification, PDUType: PDUTypeInitiatingMessage}:      {IEMMEUES1APID, IEENBS1APID, IESecurityKey, IEUEAggregateMaxBitrate, IEUESecurityCapabilities},
	{ProcedureCode: ProcUEContextModification, PDUType: PDUTypeSuccessfulOutcome}:      {IEMMEUES1APID, IEENBS1APID, IECriticalityDiagnostics},
	{ProcedureCode: ProcUEContextModification, PDUType: PDUTypeUnsuccessfulOutcome}:    {IEMMEUES1APID, IEENBS1APID, IECause, IECriticalityDiagnostics},
	{ProcedureCode: ProcENBConfigurationUpdate, PDUType: PDUTypeInitiatingMessage}:     {IEeNBname, IESupportedTAs, IEDefaultPagingDRX},
	{ProcedureCode: ProcENBConfigurationUpdate, PDUType: PDUTypeSuccessfulOutcome}:     {IECriticalityDiagnostics},
	{ProcedureCode: ProcENBConfigurationUpdate, PDUType: PDUTypeUnsuccessfulOutcome}:   {IECause, IECriticalityDiagnostics},
}
