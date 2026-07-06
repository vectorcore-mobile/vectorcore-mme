package s1ap

import (
	"testing"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/security"
)

// operCfgWithName returns an OperatorConfig with a full name configured and EMM Information enabled.
func operCfgWithName(full, short string) config.OperatorConfig {
	var cfg config.OperatorConfig
	cfg.Name.Full = full
	cfg.Name.Short = short
	cfg.Name.ShowFull = full != ""
	cfg.Name.ShowShort = short != ""
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
	ue.Unlock()

	before := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")
	srv.sendEMMInformation(mmeUEID, "attach", srv.log)
	after := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")

	if after-before != 1 {
		t.Errorf("sent counter: delta=%.0f, want 1", after-before)
	}

	// The PDU should have arrived in the sends channel.
	if len(ch) == 0 {
		t.Error("expected a PDU in the sends channel, channel is empty")
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
	ue.Unlock()

	before := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")
	srv.sendEMMInformation(mmeUEID, "attach", srv.log)
	after := counterVecValue(metrics.EMMInformationTotal, "attach", "sent")

	if after != before {
		t.Errorf("sent counter should not change when nothing to send: before=%.0f after=%.0f", before, after)
	}
}
