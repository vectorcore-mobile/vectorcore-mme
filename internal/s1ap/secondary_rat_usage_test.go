package s1ap

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func findLogEntry(t *testing.T, logs *observer.ObservedLogs, message string) map[string]interface{} {
	t.Helper()
	for _, entry := range logs.All() {
		if entry.Message == message {
			return entry.ContextMap()
		}
	}
	t.Fatalf("log message %q not found", message)
	return nil
}

func TestHandleSecondaryRATDataUsageReport_DecodesIdentityAndLogsOtherIEs(t *testing.T) {
	srv := newTestServer(NoopS11Client{})
	core, logs := observer.New(zap.DebugLevel)
	srv.log = zap.New(core)

	ue := allocateTestUE(srv, "10.0.0.1:36412", 1, true)
	ue.IMSI = "001010000000001"

	const usageListIEID uint16 = 252 // exact TS 36.413 IE-ID is not asserted here; decode-only feature
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(ue.MMEUES1APID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(42)},
		{ID: usageListIEID, Value: []byte{0x01, 0x02, 0x03, 0x04}},
	}

	srv.handleSecondaryRATDataUsageReport("10.0.0.1:36412", ieList)

	ctx := findLogEntry(t, logs, "s1ap: Secondary RAT Data Usage Report received (decode-only; not yet relayed to P-GW for charging)")

	if got := fmt.Sprintf("%v", ctx["mme_ue_id"]); got != fmt.Sprintf("%v", ue.MMEUES1APID) {
		t.Errorf("mme_ue_id = %v, want %d", ctx["mme_ue_id"], ue.MMEUES1APID)
	}
	if got := fmt.Sprintf("%v", ctx["enb_ue_id"]); got != "42" {
		t.Errorf("enb_ue_id = %v, want 42", ctx["enb_ue_id"])
	}
	if got := fmt.Sprintf("%v", ctx["imsi"]); got != ue.IMSI {
		t.Errorf("imsi = %v, want %s", ctx["imsi"], ue.IMSI)
	}
	if got := fmt.Sprintf("%v", ctx["report_ie_ids"]); got != fmt.Sprintf("[%d]", usageListIEID) {
		t.Errorf("report_ie_ids = %v, want [%d]", ctx["report_ie_ids"], usageListIEID)
	}
	if got := fmt.Sprintf("%v", ctx["report_ie_lengths"]); got != "[4]" {
		t.Errorf("report_ie_lengths = %v, want [4]", ctx["report_ie_lengths"])
	}
}

func TestHandleSecondaryRATDataUsageReport_UnknownUEOmitsIMSI(t *testing.T) {
	srv := newTestServer(NoopS11Client{})
	core, logs := observer.New(zap.DebugLevel)
	srv.log = zap.New(core)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(999)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(1)},
	}

	srv.handleSecondaryRATDataUsageReport("10.0.0.1:36412", ieList)

	ctx := findLogEntry(t, logs, "s1ap: Secondary RAT Data Usage Report received (decode-only; not yet relayed to P-GW for charging)")
	if _, present := ctx["imsi"]; present {
		t.Errorf("imsi should be absent for an unknown UE, got %v", ctx["imsi"])
	}
}
