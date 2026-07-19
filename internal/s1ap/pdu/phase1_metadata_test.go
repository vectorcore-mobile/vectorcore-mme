package pdu

import (
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

func TestRel16Phase1IEConstants(t *testing.T) {
	tests := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"MME-UE-S1AP-ID", IEMMEUES1APID, 0},
		{"Cause", IECause, 2},
		{"eNB-UE-S1AP-ID", IEENBS1APID, 8},
		{"E-RABToBeSetupListBearerSUReq", IEERABToBeSetupListBearerSUReq, 16},
		{"E-RABSetupListBearerSURes", IEERABSetupListBearerSURes, 28},
		{"E-RABFailedToSetupListBearerSURes", IEERABFailedToSetupListBearerSURes, 29},
		{"E-RABFailedToSetupListCtxtSURes", IEERABFailedToSetupListCtxtSURes, 48},
		{"E-RABSetupListCtxtSURes", IEERABSetupListCtxtSURes, 51},
		{"Global-ENB-ID", IEGlobal_ENB_ID, 59},
		{"MMEname", IEMMEname, 61},
		{"SupportedTAs", IESupportedTAs, 64},
		{"TAI", IETAI, 67},
		{"RelativeMMECapacity", IERelativeMMECapacity, 87},
		{"UE-S1AP-IDs", IEUES1APIDs, 99},
		{"EUTRAN-CGI", IECGI, 100},
		{"ServedGUMMEIs", IEServedGUMMEIs, 105},
		{"RRC-Establishment-Cause", IERRCEstablishmentCause, 134},
		{"DefaultPagingDRX", IEDefaultPagingDRX, 137},
		{"GUMMEIList", IEGUMMEIList, 154},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s IE ID: got %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestPhase1MetadataMandatoryIEs(t *testing.T) {
	tests := []struct {
		name string
		key  ProcedureIEKey
		info IEInfo
	}{
		{
			name: "S1SetupResponse MMEname",
			key:  ProcedureIEKey{ProcedureCode: ProcS1Setup, PDUType: PDUTypeSuccessfulOutcome, IEID: IEMMEname},
			info: IEInfo{"MMEname", IEMMEname, aper.CriticalityIgnore, IEPresenceOptional, "MMEname"},
		},
		{
			name: "S1SetupResponse ServedGUMMEIs",
			key:  ProcedureIEKey{ProcedureCode: ProcS1Setup, PDUType: PDUTypeSuccessfulOutcome, IEID: IEServedGUMMEIs},
			info: IEInfo{"ServedGUMMEIs", IEServedGUMMEIs, aper.CriticalityReject, IEPresenceMandatory, "ServedGUMMEIs"},
		},
		{
			name: "DownlinkNASTransport NAS-PDU",
			key:  ProcedureIEKey{ProcedureCode: ProcDownlinkNASTransport, PDUType: PDUTypeInitiatingMessage, IEID: IENAS_PDU},
			info: IEInfo{"NAS-PDU", IENAS_PDU, aper.CriticalityReject, IEPresenceMandatory, "NAS-PDU"},
		},
		{
			name: "InitialContextSetupRequest SecurityKey",
			key:  ProcedureIEKey{ProcedureCode: ProcInitialContextSetup, PDUType: PDUTypeInitiatingMessage, IEID: IESecurityKey},
			info: IEInfo{"SecurityKey", IESecurityKey, aper.CriticalityReject, IEPresenceMandatory, "SecurityKey"},
		},
		{
			name: "UEContextReleaseCommand UE-S1AP-IDs",
			key:  ProcedureIEKey{ProcedureCode: ProcUEContextRelease, PDUType: PDUTypeInitiatingMessage, IEID: IEUES1APIDs},
			info: IEInfo{"UE-S1AP-IDs", IEUES1APIDs, aper.CriticalityReject, IEPresenceMandatory, "UE-S1AP-IDs"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Phase1ProcedureIEs[tt.key]
			if !ok {
				t.Fatalf("metadata missing %+v", tt.key)
			}
			if got != tt.info {
				t.Fatalf("metadata: got %+v, want %+v", got, tt.info)
			}
		})
	}
}

func TestBuildMessagesEncodeProcedureBodyWrapper(t *testing.T) {
	ieList := []ProtocolIE{
		{ID: IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 1}},
		{ID: IEENBS1APID, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 1}},
	}
	for _, c := range []struct {
		name string
		raw  []byte
		typ  PDUType
	}{
		{name: "initiating", raw: BuildInitiatingMessage(ProcDownlinkNASTransport, aper.CriticalityIgnore, ieList), typ: PDUTypeInitiatingMessage},
		{name: "successful", raw: BuildSuccessfulOutcome(ProcInitialContextSetup, aper.CriticalityReject, ieList), typ: PDUTypeSuccessfulOutcome},
		{name: "unsuccessful", raw: BuildUnsuccessfulOutcome(ProcInitialContextSetup, aper.CriticalityReject, ieList), typ: PDUTypeUnsuccessfulOutcome},
	} {
		t.Run(c.name, func(t *testing.T) {
			msg, err := Decode(c.raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if msg.Type != c.typ {
				t.Fatalf("Type: got %d, want %d", msg.Type, c.typ)
			}
			ies, err := DecodeProcedureIEContainer(msg.Value)
			if err != nil {
				t.Fatalf("DecodeProcedureIEContainer: %v", err)
			}
			if len(ies) != len(ieList) {
				t.Fatalf("IE count: got %d, want %d", len(ies), len(ieList))
			}
		})
	}
}
