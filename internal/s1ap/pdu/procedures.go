package pdu

import "github.com/vectorcore/mme/internal/asn1/aper"

// S1AP Procedure codes (3GPP TS 36.413 Annex A).
const (
	ProcHandoverPreparation                  uint8 = 0
	ProcHandoverResourceAllocation           uint8 = 1
	ProcHandoverNotification                 uint8 = 2
	ProcPathSwitchRequest                    uint8 = 3
	ProcHandoverCancel                       uint8 = 4
	ProcERABSetup                            uint8 = 5
	ProcERABModify                           uint8 = 6
	ProcERABRelease                          uint8 = 7
	ProcERABReleaseIndication                uint8 = 8
	ProcInitialContextSetup                  uint8 = 9
	ProcPaging                               uint8 = 10
	ProcDownlinkNASTransport                 uint8 = 11
	ProcInitialUEMessage                     uint8 = 12
	ProcUplinkNASTransport                   uint8 = 13
	ProcReset                                uint8 = 14
	ProcErrorIndication                      uint8 = 15
	ProcNASNonDeliveryIndication             uint8 = 16
	ProcS1Setup                              uint8 = 17
	ProcUEContextReleaseRequest              uint8 = 18
	ProcDownlinkS1CDMA                       uint8 = 19
	ProcUplinkS1CDMA                         uint8 = 20
	ProcUEContextModification                uint8 = 21
	ProcUECapabilityInfoIndication           uint8 = 22
	ProcUEContextRelease                     uint8 = 23
	ProcENBStatusTransfer                    uint8 = 24
	ProcMMEStatusTransfer                    uint8 = 25
	ProcDeactivateTrace                      uint8 = 26
	ProcTraceStart                           uint8 = 27
	ProcTraceFailureIndication               uint8 = 28
	ProcENBConfigurationUpdate               uint8 = 29
	ProcMMEConfigurationUpdate               uint8 = 30
	ProcLocationReportingControl             uint8 = 31
	ProcLocationReportFailure                uint8 = 32
	ProcLocationReport                       uint8 = 33
	ProcOverloadStart                        uint8 = 34
	ProcOverloadStop                         uint8 = 35
	ProcWriteReplaceWarning                  uint8 = 36
	ProcENBDirectInformationTransfer         uint8 = 37
	ProcMMEDirectInformationTransfer         uint8 = 38
	ProcPrivateMessage                       uint8 = 39
	ProcENBConfigurationTransfer             uint8 = 40
	ProcMMEConfigurationTransfer             uint8 = 41
	ProcKill                                 uint8 = 43
	ProcCellTrafficTrace                     uint8 = 42
	ProcDownlinkUEAssociatedLPPaTransport    uint8 = 44
	ProcUplinkUEAssociatedLPPaTransport      uint8 = 45
	ProcDownlinkNonUEAssociatedLPPaTransport uint8 = 46
	ProcUplinkNonUEAssociatedLPPaTransport   uint8 = 47
	ProcPWSRestartIndication                 uint8 = 49
	ProcERABModificationIndication           uint8 = 50
	ProcPWSFailureIndication                 uint8 = 51
)

// S1AP IE identifiers (3GPP TS 36.413 Annex A).
const (
	IEMMEUES1APID                               uint16 = 0
	IEHandoverType                              uint16 = 1
	IECause                                     uint16 = 2
	IESourceID                                  uint16 = 3
	IETargetID                                  uint16 = 4
	IEENBS1APID                                 uint16 = 8
	IEERABToBeSetupListBearerSUReq              uint16 = 16
	IEERABToBeSetupItemBearerSUReq              uint16 = 17
	IEERABSetupListBearerSURes                  uint16 = 28
	IEERABFailedToSetupListBearerSURes          uint16 = 29
	IEERABSetupItemBearerSURes                  uint16 = 39
	IEERABItem                                  uint16 = 35
	IEERABToBeModifiedListBearerModReq          uint16 = 30
	IEERABModifyListBearerModRes                uint16 = 31
	IEERABFailedToModifyList                    uint16 = 32
	IEERABToBeReleasedList                      uint16 = 33
	IEERABFailedToReleaseList                   uint16 = 34
	IEERABToBeModifiedItemBearerModReq          uint16 = 36
	IEERABModifyItemBearerModRes                uint16 = 37
	IEERABReleaseItemBearerRelComp              uint16 = 15
	IEERABReleaseListERABRelComp                uint16 = 69
	IEERABToBeSetupListCtxtSUReq                uint16 = 24 // outer list (ICS Request)
	IETraceActivation                           uint16 = 25
	IENAS_PDU                                   uint16 = 26
	IEERABSetupListCtxtSURes                    uint16 = 51 // outer list (ICS Response)
	IEERABFailedToSetupListCtxtSURes            uint16 = 48
	IEERABToBeSetupItemCtxtSUReq                uint16 = 52 // inner item inside ICS Request E-RAB list
	IEERABSetupItemCtxtSURes                    uint16 = 50 // inner item inside ICS Response E-RAB list
	IEERABToBeReleasedListBearerRelInd          uint16 = 38
	IECDMACode                                  uint16 = 40
	IECriticalityDiagnostics                    uint16 = 58
	IEGlobal_ENB_ID                             uint16 = 59
	IEeNBname                                   uint16 = 60
	IEMMEname                                   uint16 = 61
	IESupportedTAs                              uint16 = 64
	IETimeToWait                                uint16 = 65
	IEUEAggregateMaxBitrate                     uint16 = 66
	IETAI                                       uint16 = 67
	IESecurityKey                               uint16 = 73
	IEUERadioCapability                         uint16 = 74
	IEGUMMEIList                                uint16 = 154
	IERelativeMMECapacity                       uint16 = 87
	IEServedGUMMEIs                             uint16 = 105
	IESubscriberProfileIDforRFP                 uint16 = 106 // Subscriber Profile ID for RAT/Frequency priority (TS 36.413 §9.2.1.39)
	IEUESecurityCapabilities                    uint16 = 107
	IESecurityContext                           uint16 = 119
	IERRCEstablishmentCause                     uint16 = 134
	IEDefaultPagingDRX                          uint16 = 137
	IECSG_ID                                    uint16 = 145
	IECSGMembershipStatus                       uint16 = 146
	IECGI                                       uint16 = 100
	IEGUMMEI                                    uint16 = 75
	IEERABList                                  uint16 = 92
	IEUEAssociatedLogicalS1ConnectionItem       uint16 = 91
	IEResetType                                 uint16 = 92
	IEUEAssociatedLogicalS1ConnectionListResAck uint16 = 93
	IEUES1APIDs                                 uint16 = 99  // UE-S1AP-IDs CHOICE (for UE Context Release Command)
	IESTMSI                                     uint16 = 96  // S-TMSI (optional in Initial UE Message)
	IEUEPagingID                                uint16 = 43  // UE-PagingID CHOICE (s-TMSI or IMSI)
	IEPagingDRX                                 uint16 = 44  // Per-UE Paging DRX
	IEPagingTAIList                             uint16 = 46  // TAI List for Paging message
	IEUEIdentityIndexValue                      uint16 = 80  // UE Identity Index Value (10-bit BIT STRING)
	IECNDomain                                  uint16 = 109 // CN Domain (mandatory in Paging; ps or cs)
	IECSFallbackIndicator                       uint16 = 108 // CS Fallback Indicator (Initial Context Setup / UE Context Modification)
	IEERABToBeSwitchedInUplinkList              uint16 = 22  // Path Switch Request: uplink E-RAB list
	IEERABToBeModifiedListBearerModInd          uint16 = 199
	IEERABToBeModifiedItemBearerModInd          uint16 = 200
	IEERABNotToBeModifiedListBearerModInd       uint16 = 201
	IEERABNotToBeModifiedItemBearerModInd       uint16 = 202
	IEERABModifyListBearerModConf               uint16 = 203
	IEERABModifyItemBearerModConf               uint16 = 204
	IEERABFailedToModifyListBearerModConf       uint16 = 205
	IEERABToBeReleasedListBearerModConf         uint16 = 210
	IELPPaPDU                                   uint16 = 147
	IERoutingID                                 uint16 = 148
	IEHandoverRestrictionList                   uint16 = 41  // Handover Restriction List (TS 36.413 §9.2.1.22; Initial Context Setup Request, optional)
	IEENBStatusTransferTransparentContainer     uint16 = 90  // eNB Status Transfer Transparent Container (eNB/MME Status Transfer, PDCP SN/HFN relay)
	IELTEMIndication                            uint16 = 272 // LTE-M Indication (TS 36.413 §9.2.1.135; UE Capability Info Indication, optional)

	// S1 Handover IEs (TS 36.413 Annex A)
	IEERABToBeSetupListHOReq             uint16 = 53  // HandoverRequest: E-RAB list outer
	IEERABToBeSetupItemHOReq             uint16 = 27  // HandoverRequest: E-RAB item
	IEERABAdmittedList                   uint16 = 18  // HandoverRequestAck: admitted list
	IEERABAdmittedItem                   uint16 = 20  // HandoverRequestAck: admitted item
	IETargetToSourceTransparentContainer uint16 = 127 // HandoverRequestAck/Command: RRC container
	IESourceToTargetTransparentContainer uint16 = 96  // HandoverRequired/Request: RRC container (same value as IESTMSI)
)

// PDUType represents the S1AP PDU choice.
type PDUType uint8

const (
	PDUTypeInitiatingMessage   PDUType = 0
	PDUTypeSuccessfulOutcome   PDUType = 1
	PDUTypeUnsuccessfulOutcome PDUType = 2
)

func (t PDUType) String() string {
	switch t {
	case PDUTypeInitiatingMessage:
		return "initiatingMessage"
	case PDUTypeSuccessfulOutcome:
		return "successfulOutcome"
	case PDUTypeUnsuccessfulOutcome:
		return "unsuccessfulOutcome"
	default:
		return "unknown"
	}
}

// ProtocolIE represents a single Protocol IE field.
type ProtocolIE struct {
	ID          uint16
	Criticality aper.Criticality
	Value       []byte
}
