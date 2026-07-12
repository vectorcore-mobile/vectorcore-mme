package emm_test

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
)

// buildTAURequestBody constructs a minimal TAU Request body with a GUTI.
func buildTAURequestBody(updateType uint8, guti *emm.GUTI) []byte {
	b := make([]byte, 0, 32)

	// Byte 0: (eKSI=7)<<4 | (active=0)<<3 | updateType
	b = append(b, (0x07<<4)|updateType)

	// LV: mobile identity (GUTI)
	// GUTI wire format: [0xF6][PLMN(3)][MMEGI(2)][MMEC(1)][MTMSI(4)] = 11 bytes
	gutiBytes := guti.Encode() // returns LV: [0x0B, ...11 value bytes]
	b = append(b, gutiBytes...)

	// LV: UE network capability (length=2, EEA=0xE0, EIA=0xE0)
	b = append(b, 0x02, 0xE0, 0xE0)

	return b
}

// ── DecodeTAURequest ──────────────────────────────────────────────────────────

func TestDecodeTAURequest_PeriodicGUTI(t *testing.T) {
	guti := &emm.GUTI{
		PLMN:  [3]byte{0x00, 0xF1, 0x10},
		MMEGI: 1,
		MMEC:  1,
		MTMSI: 0xDEADBEEF,
	}
	body := buildTAURequestBody(emm.EPSUpdateTypePeriodic, guti)

	req, err := emm.DecodeTAURequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if req.EPSUpdateType != emm.EPSUpdateTypePeriodic {
		t.Errorf("EPSUpdateType: got %d, want %d (periodic)", req.EPSUpdateType, emm.EPSUpdateTypePeriodic)
	}
	if req.OldGUTI == nil {
		t.Fatal("OldGUTI should not be nil")
	}
	if req.OldGUTI.MTMSI != guti.MTMSI {
		t.Errorf("GUTI MTMSI: got %#x, want %#x", req.OldGUTI.MTMSI, guti.MTMSI)
	}
	if req.OldGUTI.MMEC != guti.MMEC {
		t.Errorf("GUTI MMEC: got %d, want %d", req.OldGUTI.MMEC, guti.MMEC)
	}
	if len(req.UENetworkCapability) != 2 {
		t.Errorf("UENetworkCapability length: got %d, want 2", len(req.UENetworkCapability))
	}
}

func TestDecodeTAURequest_NormalGUTI(t *testing.T) {
	guti := &emm.GUTI{
		PLMN:  [3]byte{0x02, 0xF8, 0x39},
		MMEGI: 42,
		MMEC:  7,
		MTMSI: 0x12345678,
	}
	body := buildTAURequestBody(emm.EPSUpdateTypeTA, guti)

	req, err := emm.DecodeTAURequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if req.EPSUpdateType != emm.EPSUpdateTypeTA {
		t.Errorf("EPSUpdateType: got %d, want %d (TA)", req.EPSUpdateType, emm.EPSUpdateTypeTA)
	}
	if req.OldGUTI == nil {
		t.Fatal("OldGUTI should not be nil")
	}
	if req.OldGUTI.MTMSI != 0x12345678 {
		t.Errorf("MTMSI: got %#x, want 0x12345678", req.OldGUTI.MTMSI)
	}
}

func TestDecodeTAURequest_TooShort(t *testing.T) {
	_, err := emm.DecodeTAURequest([]byte{0x03})
	if err == nil {
		t.Error("expected error for 1-byte body, got nil")
	}
}

// ── EncodeTAUAccept ───────────────────────────────────────────────────────────

func TestEncodeTAUAccept_NoGUTI(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0001}
	b := emm.EncodeTAUAccept(0x00, 0x21, []emm.TAI{tai}, nil)

	if len(b) < 3 {
		t.Fatalf("output too short: %d bytes", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgTrackingAreaUpdateAccept {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgTrackingAreaUpdateAccept)
	}
	if b[2] != 0x00 {
		t.Errorf("byte[2] EPS update result: got %#x, want 0x00", b[2])
	}
	// T3412 IEI should be present
	found := false
	for i := 3; i < len(b)-1; i++ {
		if b[i] == 0x5A {
			found = true
			if b[i+1] != 0x01 {
				t.Errorf("T3412 length: got %d, want 1", b[i+1])
			}
			if i+2 < len(b) && b[i+2] != 0x21 {
				t.Errorf("T3412 value: got %#x, want 0x21", b[i+2])
			}
			break
		}
	}
	if !found {
		t.Error("T3412 IEI 0x5A not found in TAU Accept")
	}
	// TAI list IEI should be present
	found = false
	for _, bb := range b[3:] {
		if bb == 0x54 {
			found = true
			break
		}
	}
	if !found {
		t.Error("TAI list IEI 0x54 not found in TAU Accept")
	}
	// GUTI IEI must NOT be present
	for _, bb := range b {
		if bb == 0x50 {
			t.Error("GUTI IEI 0x50 unexpectedly present in no-GUTI TAU Accept")
			break
		}
	}

	decoded, err := emm.DecodeTAUAccept(b)
	if err != nil {
		t.Fatalf("DecodeTAUAccept error: %v", err)
	}
	if decoded.UpdateResult != 0x00 {
		t.Fatalf("decoded update result got %#x, want 0", decoded.UpdateResult)
	}
	if decoded.T3412 == nil || *decoded.T3412 != 0x21 {
		t.Fatalf("decoded T3412 got %v, want 0x21", decoded.T3412)
	}
	if len(decoded.TAIList) != 1 || decoded.TAIList[0].TAC != tai.TAC || decoded.TAIList[0].PLMN != tai.PLMN {
		t.Fatalf("decoded TAI list got %+v, want %+v", decoded.TAIList, tai)
	}
	if decoded.GUTI != nil {
		t.Fatalf("decoded unexpected GUTI: %+v", decoded.GUTI)
	}
}

func TestEncodeTAUAccept_WithGUTI(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0007}
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0xABCD1234}

	b := emm.EncodeTAUAccept(0x00, 0x21, []emm.TAI{tai}, guti)
	if len(b) < 20 {
		t.Fatalf("output too short with GUTI: %d bytes", len(b))
	}
	found := false
	for i, bb := range b {
		if bb == 0x50 {
			found = true
			// Next byte should be the GUTI LV length (0x0B = 11)
			if i+1 < len(b) && b[i+1] != 0x0B {
				t.Errorf("GUTI LV length: got %d, want 11", b[i+1])
			}
			break
		}
	}
	if !found {
		t.Error("GUTI IEI 0x50 not found in TAU Accept")
	}

	decoded, err := emm.DecodeTAUAccept(b)
	if err != nil {
		t.Fatalf("DecodeTAUAccept error: %v", err)
	}
	if decoded.GUTI == nil {
		t.Fatal("decoded GUTI is nil")
	}
	if decoded.GUTI.PLMN != guti.PLMN || decoded.GUTI.MMEGI != guti.MMEGI ||
		decoded.GUTI.MMEC != guti.MMEC || decoded.GUTI.MTMSI != guti.MTMSI {
		t.Fatalf("decoded GUTI got %+v, want %+v", decoded.GUTI, guti)
	}
}

func TestEncodeTAUAcceptWithParams_RoundTrip(t *testing.T) {
	taiList := []emm.TAI{
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0102},
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0304},
	}
	guti := &emm.GUTI{PLMN: [3]byte{0x13, 0x51, 0x34}, MMEGI: 1, MMEC: 1, MTMSI: 0x9F719526}
	b := emm.EncodeTAUAcceptWithParams(emm.TAUAcceptParams{
		UpdateResult: 0,
		T3412:        0x21,
		TAIList:      taiList,
		IncludeGUTI:  true,
		GUTI:         guti,
		EPSNetworkFeatureSupport: &emm.EPSNetworkFeatureSupport{
			IMSVoiceOverPSSessionInS1Mode: true,
		},
	})
	decoded, err := emm.DecodeTAUAccept(b)
	if err != nil {
		t.Fatalf("DecodeTAUAccept error: %v bytes=%x", err, b)
	}
	if len(decoded.TAIList) != len(taiList) {
		t.Fatalf("TAI count got %d want %d", len(decoded.TAIList), len(taiList))
	}
	for i := range taiList {
		if decoded.TAIList[i] != taiList[i] {
			t.Fatalf("TAI[%d] got %+v want %+v", i, decoded.TAIList[i], taiList[i])
		}
	}
	if decoded.GUTI == nil || decoded.GUTI.MTMSI != guti.MTMSI {
		t.Fatalf("decoded GUTI got %+v want %+v", decoded.GUTI, guti)
	}
	if decoded.EPSNetworkFeatureSupport == nil ||
		!decoded.EPSNetworkFeatureSupport.IMSVoiceOverPSSessionInS1Mode {
		t.Fatalf("decoded EPS Network Feature Support got %+v, want IMS VoPS", decoded.EPSNetworkFeatureSupport)
	}
}

// ── EncodeTAUReject ───────────────────────────────────────────────────────────

func TestEncodeTAUReject(t *testing.T) {
	const cause = emm.CauseImplicitlyDetached
	b := emm.EncodeTAUReject(cause)

	if len(b) != 3 {
		t.Fatalf("length: got %d, want 3", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgTrackingAreaUpdateReject {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgTrackingAreaUpdateReject)
	}
	if b[2] != cause {
		t.Errorf("byte[2] cause: got %#x, want %#x", b[2], cause)
	}
}
