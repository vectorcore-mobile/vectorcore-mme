package s1ap

import (
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/sgsap"
	"github.com/vectorcore/mme/internal/uecontext"
)

// attachAcceptIEs is the parsed plain Attach Accept: attach result and the
// optional IEs this MME can send after the ESM container.
type attachAcceptIEs struct {
	result   uint8
	lai      []byte
	msID     []byte
	emmCause *uint8
}

func parseAttachAccept(t *testing.T, plain []byte) attachAcceptIEs {
	t.Helper()
	if len(plain) < 5 || plain[1] != emm.MsgAttachAccept {
		t.Fatalf("not an Attach Accept: %x", plain)
	}
	out := attachAcceptIEs{result: plain[2] & 0x07}
	i := 4
	i += 1 + int(plain[i])                        // TAI list (LV)
	i += 2 + (int(plain[i])<<8 | int(plain[i+1])) // ESM message container (LV-E)
	for i < len(plain) {
		iei := plain[i]
		switch {
		case iei&0xf0 == 0xf0: // type 1, half octet
			i++
		case iei == 0x13: // LAI, TV 6
			out.lai = plain[i+1 : i+6]
			i += 6
		case iei == 0x53: // EMM cause, TV 2
			c := plain[i+1]
			out.emmCause = &c
			i += 2
		case iei == 0x17 || iei == 0x59: // T3402, T3423, TV 2
			i += 2
		default: // TLV (GUTI 0x50, MS identity 0x23, EPS NFS 0x64, ...)
			l := int(plain[i+1])
			if iei == 0x23 {
				out.msID = plain[i+2 : i+2+l]
			}
			i += 2 + l
		}
	}
	return out
}

// newCombinedAttachUE prepares a UE that sent a combined EPS/IMSI Attach and
// is waiting for its Create Session Response.
func newCombinedAttachUE(t *testing.T, srv *Server, remoteAddr string) *uecontext.Context {
	t.Helper()
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.Lock()
	ue.ENBS1APID = 1
	ue.IMSI = "001010123456789"
	ue.TAI = tai
	ue.KASME = make([]byte, 32)
	ue.KNASint = fakeKeys()
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = security.AlgIDEIA2
	ue.DLNASCount = 1
	ue.PDNRequestPTI = 1
	ue.APN = "internet"
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	ue.AttachType = emm.AttachTypeCombinedEPSAndIMSI
	ue.Unlock()
	srv.ueManager.Register(ue)
	return ue
}

func combinedAttachCSRsp() *gtpv2.CreateSessionResponse {
	return &gtpv2.CreateSessionResponse{
		Cause:     gtpv2.CauseRequestAccepted,
		SGWC_TEID: 0x3e9,
		SGWC_IP:   net.ParseIP("10.0.2.3"),
		SGWU_TEID: 0x6173,
		SGWU_IP:   net.ParseIP("10.0.2.6"),
		UEIPv4:    net.ParseIP("10.45.0.12"),
		EBI:       5,
	}
}

func expectNoPDU(t *testing.T, ch <-chan []byte, what string) {
	t.Helper()
	select {
	case raw := <-ch:
		t.Fatalf("%s: unexpected S1AP PDU %x", what, raw)
	case <-time.After(100 * time.Millisecond):
	}
}

func readAttachAcceptFromICS(t *testing.T, ch <-chan []byte) attachAcceptIEs {
	t.Helper()
	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("procedure got %d, want InitialContextSetup", msg.ProcedureCode)
	}
	return parseAttachAccept(t, decodeNASPDUFromInitialContextSetup(t, msg)[6:])
}

// User field log: the combined attach was answered "EPS only" with no EMM
// cause because the SGs Location Update went out after the Attach Accept.
// TS 29.118 §5.2.2.3: the MME waits for the VLR before answering the UE.
func TestCombinedAttachWaitsForSGsLocationUpdateAccept(t *testing.T) {
	srv, fake := sgsTestServer()
	const remoteAddr = "192.0.2.30:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := newCombinedAttachUE(t, srv, remoteAddr)

	srv.HandleCSRResult(ue.MMEUES1APID, combinedAttachCSRsp(), nil)

	expectNoPDU(t, ch, "Attach Accept before SGs Location Update outcome")
	fake.mu.Lock()
	lu := fake.lastLURequest
	fake.mu.Unlock()
	if lu == nil || lu.UpdateType != sgsap.EPSLocationUpdateTypeIMSIAttach {
		t.Fatalf("Location Update Request got %+v, want IMSI attach", lu)
	}

	lai := sgsap.LAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, LAC: 7}
	srv.HandleLocationUpdateAccept("vlr-1", &sgsap.LocationUpdateAccept{
		IMSI:        ue.IMSI,
		LAI:         lai,
		NewIdentity: &sgsap.MobileIdentity{Kind: sgsap.MobileIdentityTMSI, TMSI: 0x04b00304},
	})

	acc := readAttachAcceptFromICS(t, ch)
	if acc.result != emm.AttachTypeCombinedEPSAndIMSI {
		t.Fatalf("attach result got %d, want combined EPS/IMSI", acc.result)
	}
	if acc.lai == nil || acc.msID == nil {
		t.Fatalf("Attach Accept LAI %x / MS identity %x, want both present", acc.lai, acc.msID)
	}
	if acc.emmCause != nil {
		t.Fatalf("combined success carries EMM cause #%d", *acc.emmCause)
	}
	// The TMSI is confirmed to the VLR only on Attach Complete.
	fake.mu.Lock()
	early := fake.lastTMSIReallocCompleteIMSI
	fake.mu.Unlock()
	if early != "" {
		t.Fatal("TMSI-REALLOCATION-COMPLETE sent before Attach Complete")
	}
}

func TestCombinedAttachSGsLocationUpdateFailureGivesEPSOnlyWithCause(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fail      func(srv *Server, ue *uecontext.Context)
		wantCause uint8
	}{
		{
			name: "Ts6-1 expiry",
			fail: func(srv *Server, ue *uecontext.Context) {
				srv.expireSGsLocationUpdate(ue.MMEUES1APID, "vlr-1")
			},
			wantCause: emm.CauseMSCNotReachable,
		},
		{
			name: "VLR reject network failure",
			fail: func(srv *Server, ue *uecontext.Context) {
				srv.HandleLocationUpdateReject("vlr-1", &sgsap.LocationUpdateReject{IMSI: ue.IMSI, Cause: 17})
			},
			wantCause: emm.CauseNetworkFailure,
		},
		{
			name: "VLR reject without EPS-only meaning",
			fail: func(srv *Server, ue *uecontext.Context) {
				srv.HandleLocationUpdateReject("vlr-1", &sgsap.LocationUpdateReject{IMSI: ue.IMSI, Cause: 13})
			},
			wantCause: emm.CauseNetworkFailure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := sgsTestServer()
			const remoteAddr = "192.0.2.31:36412"
			ch := setupSendCapture(srv, remoteAddr)
			ue := newCombinedAttachUE(t, srv, remoteAddr)

			srv.HandleCSRResult(ue.MMEUES1APID, combinedAttachCSRsp(), nil)
			expectNoPDU(t, ch, "Attach Accept before SGs Location Update outcome")
			tc.fail(srv, ue)

			acc := readAttachAcceptFromICS(t, ch)
			if acc.result != emm.AttachTypeEPSOnly {
				t.Fatalf("attach result got %d, want EPS only", acc.result)
			}
			if acc.emmCause == nil || *acc.emmCause != tc.wantCause {
				t.Fatalf("EMM cause got %v, want #%d", acc.emmCause, tc.wantCause)
			}
			if acc.lai != nil || acc.msID != nil {
				t.Fatal("EPS-only Attach Accept carries LAI or MS identity")
			}
		})
	}
}

func TestEPSOnlyAttachIsNotDeferredForSGs(t *testing.T) {
	srv, fake := sgsTestServer()
	const remoteAddr = "192.0.2.32:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := newCombinedAttachUE(t, srv, remoteAddr)
	ue.Lock()
	ue.AttachType = emm.AttachTypeEPSOnly
	ue.Unlock()

	srv.HandleCSRResult(ue.MMEUES1APID, combinedAttachCSRsp(), nil)

	acc := readAttachAcceptFromICS(t, ch)
	if acc.result != emm.AttachTypeEPSOnly || acc.emmCause != nil {
		t.Fatalf("EPS-only attach got result %d cause %v", acc.result, acc.emmCause)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.lastLURequest != nil {
		t.Fatal("Location Update sent for an EPS-only attach")
	}
}

func TestEMMCauseForSGsLUReject(t *testing.T) {
	for in, want := range map[uint8]uint8{2: 2, 16: 16, 17: 17, 18: 18, 22: 22, 11: 17, 13: 17, 3: 17} {
		if got := emmCauseForSGsLUReject(in); got != want {
			t.Fatalf("VLR cause #%d mapped to #%d, want #%d", in, got, want)
		}
	}
}

// User field log: the TAU Accept carried a new VLR TMSI without a GUTI and
// the MME sent SGsAP-TMSI-REALLOCATION-COMPLETE straight away. TS 24.301
// §5.5.3.3.4.2: the UE confirms the TMSI with TAU Complete and the MME runs
// T3450; TS 29.118 §5.2.2.3: the VLR is told only on TAU Complete.
func TestTAUAcceptWithTMSIWaitsForTAUComplete(t *testing.T) {
	srv, fake := sgsTestServer()
	const remoteAddr = "192.0.2.33:36412"
	_ = setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	tmsi := uint32(0x04b00304)
	lai := sgsap.LAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, LAC: 7}
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.SGsState = uecontext.SGsUEAssociated
	ue.SGsVLRName = "vlr-1"
	ue.SGsLAI = &lai
	ue.SGsPendingNewTMSI = &tmsi
	ue.Unlock()

	if err := srv.sendTAUAcceptWithOptions(ue, srv.log, tauAcceptOptions{
		UpdateResult: emm.EPSUpdateResultCombinedTALAUpdated,
		LAI:          &lai,
		NewTMSI:      &tmsi,
	}); err != nil {
		t.Fatalf("sendTAUAcceptWithOptions: %v", err)
	}

	fake.mu.Lock()
	early := fake.lastTMSIReallocCompleteIMSI
	fake.mu.Unlock()
	if early != "" {
		t.Fatal("TMSI-REALLOCATION-COMPLETE sent before TAU Complete")
	}
	ue.Lock()
	step := ue.AttachStep
	pending := len(ue.PendingTAUAcceptNAS)
	ue.Unlock()
	if step != uecontext.AttachStepWaitingTAUComplete || pending == 0 {
		t.Fatalf("after TAU Accept with TMSI: step %d, pending accept %d bytes; want waiting for TAU Complete", step, pending)
	}

	if err := srv.processTAUComplete(ue, srv.log); err != nil {
		t.Fatalf("processTAUComplete: %v", err)
	}
	fake.mu.Lock()
	got := fake.lastTMSIReallocCompleteIMSI
	fake.mu.Unlock()
	if got != ue.IMSI {
		t.Fatalf("TMSI-REALLOCATION-COMPLETE after TAU Complete got IMSI %q, want %q", got, ue.IMSI)
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.AttachStep != uecontext.AttachStepNone || len(ue.PendingTAUAcceptNAS) != 0 {
		t.Fatalf("after TAU Complete: step %d, pending accept %d bytes", ue.AttachStep, len(ue.PendingTAUAcceptNAS))
	}
}
