package s1ap

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// operCfgWithName returns an OperatorConfig with a full name configured and EMM Information enabled.
func operCfgWithName(full, short string) config.OperatorConfig {
	var cfg config.OperatorConfig
	cfg.Name.Full = full
	cfg.Name.Short = short
	cfg.Name.ShowFull = full != ""
	cfg.Name.ShowShort = short != ""
	cfg.Name.Encoding = "gsm7"
	cfg.Name.AddCountryInitials = false
	cfg.EMMInformation.Enabled = true
	cfg.EMMInformation.SendAfterAttach = true
	cfg.EMMInformation.SendAfterTAU = true
	return cfg
}

// fakeKeys returns a 16-byte slice for use as a fake NAS key in tests.
func fakeKeys() []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// TestSendEMMInformation_NoSecurity verifies that when the UE has no KNASint,
// the function increments the no_security counter and does not attempt a send.
func TestSendEMMInformation_NoSecurity(t *testing.T) {
	srv := newTestServer(&mockS11{})
	srv.operCfg = operCfgWithName("Test Net", "TN")

	const addr = "10.0.0.1:36412"
	registerTestENB(srv, addr)

	ue := allocateTestUE(srv, addr, 0, true)
	// Leave KNASint/KNASenc empty (no security context yet)

	before := counterVecValue(metrics.EMMInformationTotal, "attach", "no_security")
	srv.sendEMMInformation(ue.MMEUES1APID, "attach", srv.log)
	after := counterVecValue(metrics.EMMInformationTotal, "attach", "no_security")

	if after-before != 1 {
		t.Errorf("no_security counter: delta=%.0f, want 1", after-before)
	}
}

// TestSendEMMInformation_Sent verifies that a UE with security keys receives an
// integrity-protected EMM Information PDU and the sent counter is incremented.
func TestSendEMMInformation_Sent(t *testing.T) {
	srv := newTestServer(&mockS11{})
	srv.operCfg = operCfgWithName("Test Net", "TN")

	const addr = "10.0.0.1:36412"
	ch := registerTestENBWithChan(srv, addr)

	ue := allocateTestUE(srv, addr, 0, true)
	ue.Lock()
	ue.IntAlg = security.AlgIDEIA0 // null integrity — computes zero MAC, always succeeds
	ue.EncAlg = security.AlgIDEEA0 // null ciphering
	ue.KNASint = fakeKeys()
	ue.KNASenc = fakeKeys()
	mmeUEID := ue.MMEUES1APID
	startDLCount := uint32(ue.DLNASCount)
	ue.Unlock()

	before := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")
	srv.sendEMMInformation(mmeUEID, "attach", srv.log)
	after := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")

	if after-before != 1 {
		t.Errorf("sent counter: delta=%.0f, want 1", after-before)
	}

	// The PDU should have arrived in the sends channel.
	if len(ch) == 0 {
		t.Fatal("expected a PDU in the sends channel, channel is empty")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, <-ch)
	if len(gotNAS) < 6 {
		t.Fatalf("protected NAS too short: %x", gotNAS)
	}
	if got, want := gotNAS[0], byte(emm.PDEPSMobilityMgmt|(emm.SecurityHeaderIntegrityProtected<<4)); got != want {
		t.Fatalf("security header byte got 0x%02x, want 0x%02x", got, want)
	}
	if got, want := gotNAS[5], byte(startDLCount); got != want {
		t.Fatalf("NAS sequence got %d, want %d", got, want)
	}
	ue.Lock()
	if got, want := uint32(ue.DLNASCount), startDLCount+1; got != want {
		ue.Unlock()
		t.Fatalf("DL NAS count after send got %d, want %d", got, want)
	}
	if got, want := ue.LastDownlinkNASMessage, "EMM Information"; got != want {
		ue.Unlock()
		t.Fatalf("last downlink got %q, want %q", got, want)
	}
	ue.Unlock()
	plain := gotNAS[6:]
	if len(plain) < 2 || plain[0] != 0x07 || plain[1] != emm.MsgEMMInformation {
		t.Fatalf("plain NAS is not EMM Information: %x", plain)
	}
	wantPlain := emm.EncodeEMMInformation("Test Net", true, "TN", true, "gsm7", false, false, 0, 0)
	if !bytes.Equal(plain, wantPlain) {
		t.Fatalf("plain EMM Information got %x, want %x", plain, wantPlain)
	}
}

// TestSendEMMInformation_UEGone verifies that sendEMMInformation returns without panic
// when the UE has already been removed from the manager.
func TestSendEMMInformation_UEGone(t *testing.T) {
	srv := newTestServer(&mockS11{})
	srv.operCfg = operCfgWithName("Test Net", "TN")

	// Use a MMEUES1APID that was never registered
	srv.sendEMMInformation(0xDEADBEEF, "attach", srv.log) // must not panic
}

// TestSendEMMInformation_NothingToSend verifies that when EncodeEMMInformation returns nil
// (all flags off, empty names) the function returns early without incrementing any counter.
func TestSendEMMInformation_NothingToSend(t *testing.T) {
	srv := newTestServer(&mockS11{})
	// operCfg with enabled=true but no names and nitz=false → EncodeEMMInformation returns nil

	const addr = "10.0.0.1:36412"
	registerTestENB(srv, addr)

	ue := allocateTestUE(srv, addr, 0, true)
	ue.Lock()
	ue.IntAlg = security.AlgIDEIA0
	ue.EncAlg = security.AlgIDEEA0
	ue.KNASint = fakeKeys()
	ue.KNASenc = fakeKeys()
	mmeUEID := ue.MMEUES1APID
	startDLCount := uint32(ue.DLNASCount)
	ue.Unlock()

	before := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")
	srv.sendEMMInformation(mmeUEID, "attach", srv.log)
	after := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")

	if after != before {
		t.Errorf("sent counter should not change when nothing to send: before=%.0f after=%.0f", before, after)
	}
	ue.Lock()
	defer ue.Unlock()
	if uint32(ue.DLNASCount) != startDLCount {
		t.Errorf("DL NAS count changed when nothing was sent: got %d, want %d", ue.DLNASCount, startDLCount)
	}
}

func TestShouldDeferAttachEMMInformationForSecondaryIMS(t *testing.T) {
	ue := &uecontext.Context{
		APN:            "internet",
		SubscriberAPNs: []string{"internet", "IMS"},
	}
	if !shouldDeferAttachEMMInformation(ue) {
		t.Fatal("shouldDeferAttachEMMInformation=false, want true")
	}
}

func TestShouldDeferAttachEMMInformationForIMSDefault(t *testing.T) {
	ue := &uecontext.Context{
		APN:            "ims",
		SubscriberAPNs: []string{"internet", "ims"},
	}
	if shouldDeferAttachEMMInformation(ue) {
		t.Fatal("shouldDeferAttachEMMInformation=true, want false")
	}
}

func decodeDownlinkNASFromRawPDU(t *testing.T, raw []byte) []byte {
	t.Helper()
	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("Decode S1AP PDU: %v", err)
	}
	if msg.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("procedureCode got %d, want DownlinkNASTransport", msg.ProcedureCode)
	}
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range container {
		if ie.ID != pdu.IENAS_PDU {
			continue
		}
		nasPDU, err := ies.DecodeNASPDU(ie.Value)
		if err != nil {
			t.Fatalf("DecodeNASPDU: %v", err)
		}
		return nasPDU
	}
	t.Fatal("missing NAS-PDU IE")
	return nil
}
