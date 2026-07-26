package s1ap

import (
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func assertS1SetupCause(t *testing.T, p *pdu.PDU, wantGroup ies.CauseGroup, wantValue uint8) {
	t.Helper()
	container, err := pdu.DecodeProcedureIEContainer(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, ie := range container {
		if ie.ID == pdu.IECause {
			group, value, err := ies.DecodeCause(ie.Value)
			if err != nil || group != wantGroup || value != wantValue {
				t.Fatalf("cause=%s/%d err=%v, want %s/%d", ies.CauseGroupName(group), value, err, ies.CauseGroupName(wantGroup), wantValue)
			}
			return
		}
	}
	t.Fatal("S1 Setup Failure missing Cause")
}

func TestS1SetupAdmissionUsesCompletePLMNAndTAC(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MCC, srv.nfCfg.MNC = "311", "435"
	srv.nfCfg.TAIList = []config.TAIItem{{MCC: "311", MNC: "435", TAC: 1}}
	const remote = "192.168.105.247:36412"
	ch := setupSendCapture(srv, remote)
	// setupSendCapture installs a placeholder association for its send channel;
	// S1 Setup must replace it only after admission succeeds.
	srv.enbs.Delete(remote)

	// A Global eNB ID may be different in a network-sharing deployment; the
	// accepted intersection is derived from Broadcast PLMN + TAC instead.
	srv.handleMessage(remote, buildS1SetupRequestForTest(t, "001", "01", 1, 1))
	resp := readCapturedPDU(t, ch)
	if resp.Type != pdu.PDUTypeUnsuccessfulOutcome {
		t.Fatalf("unserved Broadcast PLMN response=%s", resp.Type)
	}
	assertS1SetupCause(t, resp, ies.CauseGroupMisc, ies.CauseMiscUnknownPLMN)
	if _, ok := srv.enbs.Load(remote); ok {
		t.Fatal("rejected setup registered topology")
	}

	// Matching PLMN but an unsupported TAC is also rejected with the defined
	// unknown-PLMN cause; TS 36.413 has no invented "unknown TAI" cause.
	srv.handleMessage(remote, buildS1SetupRequestForTest(t, "311", "435", 1, 2))
	resp = readCapturedPDU(t, ch)
	assertS1SetupCause(t, resp, ies.CauseGroupMisc, ies.CauseMiscUnknownPLMN)
	if _, ok := srv.enbs.Load(remote); ok {
		t.Fatal("unsupported TAC registered topology")
	}

	srv.handleMessage(remote, buildS1SetupRequestForTest(t, "311", "435", 1, 1))
	select {
	case raw := <-ch:
		p, err := pdu.Decode(raw)
		if err != nil || p.Type != pdu.PDUTypeSuccessfulOutcome {
			t.Fatalf("valid setup response=%+v err=%v", p, err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no response to valid setup")
	}
	value, ok := srv.enbs.Load(remote)
	if !ok {
		t.Fatal("accepted setup was not registered")
	}
	enb := value.(*ENBContext)
	if len(enb.SupportedTAs) != 1 || len(enb.AcceptedTAs) != 1 || !supportsTAI(enb.AcceptedTAs, "311", "435", 1) {
		t.Fatalf("stored topology advertised=%+v accepted=%+v", enb.SupportedTAs, enb.AcceptedTAs)
	}
}
