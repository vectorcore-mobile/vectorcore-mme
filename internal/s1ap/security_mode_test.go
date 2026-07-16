package s1ap

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func TestProcessAuthResponseSecurityModeCommandUsesDLCountZero(t *testing.T) {
	srv := newTAUTestServer()
	srv.secCfg = config.SecurityConfig{
		IntegrityAlgorithms: []string{"EIA0"},
		CipheringAlgorithms: []string{"EEA0"},
	}
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.ENBS1APID = 1

	xres := []byte{0x4b, 0x92, 0x4f, 0x5c, 0xaf, 0xf8, 0x78, 0xa9}
	ue.Lock()
	ue.XRES = append([]byte(nil), xres...)
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0x70}
	ue.Unlock()

	body := append([]byte{byte(len(xres))}, xres...)
	if err := srv.processAuthResponse(ue, body, srv.log.With(zap.String("test", "smc-count"))); err != nil {
		t.Fatalf("processAuthResponse: %v", err)
	}

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("procedure: got %d, want DownlinkNASTransport", msg.ProcedureCode)
	}
	nasPDU := decodeNASPDUFromPDU(t, msg)
	if got, want := nasPDU[0]>>4, emm.SecurityHeaderNewEPSSecurityCtx; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if got, want := nasPDU[5], byte(0); got != want {
		t.Fatalf("NAS sequence number: got %d, want %d", got, want)
	}
	if len(nasPDU) < 8 || nasPDU[7] != emm.MsgSecurityModeCommand {
		t.Fatalf("inner NAS message type: got %x, want SecurityModeCommand", nasPDU)
	}
	ue.Lock()
	dlCount := uint32(ue.DLNASCount)
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	ue.Unlock()
	if dlCount != 1 {
		t.Fatalf("stored DL NAS COUNT after SMC: got %d, want 1", dlCount)
	}
	if intAlg != security.AlgIDEIA0 || encAlg != security.AlgIDEEA0 {
		t.Fatalf("selected algorithms: got int=%d enc=%d, want 0/0", intAlg, encAlg)
	}

	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra PDU: %x", extra)
	case <-time.After(10 * time.Millisecond):
	}
}

func TestProcessAuthResponseSecurityModeCommandOmitsHashMMEOnAttach(t *testing.T) {
	srv := newTAUTestServer()
	srv.secCfg = config.SecurityConfig{
		IntegrityAlgorithms: []string{"EIA2"},
		CipheringAlgorithms: []string{"EEA2"},
	}
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.ENBS1APID = 1

	xres := []byte{0x70, 0xba, 0x3c, 0xde, 0x5a, 0xce, 0xaa, 0xdc}
	kasme := mustHexForS1AP(t, "ed5ad878b984563b23b013fc9ba344f827a2ac0b27398ff8ee4030f297a1f4b6")
	initialAttach := mustHexForS1AP(t, "21170876eb9d010741010bf613513400140ac000000502f07000050201d011d191e0")
	ue.Lock()
	ue.XRES = append([]byte(nil), xres...)
	ue.KASME = append([]byte(nil), kasme...)
	ue.UENetworkCapability = []byte{0xf0, 0x70}
	ue.InitialAttachRequestNAS = append([]byte(nil), initialAttach...)
	ue.Unlock()

	body := append([]byte{byte(len(xres))}, xres...)
	if err := srv.processAuthResponse(ue, body, srv.log.With(zap.String("test", "smc-hashmme"))); err != nil {
		t.Fatalf("processAuthResponse: %v", err)
	}

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromPDU(t, msg)
	if got, want := nasPDU[0]>>4, emm.SecurityHeaderNewEPSSecurityCtx; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if got, want := nasPDU[5], byte(0); got != want {
		t.Fatalf("NAS sequence number: got %d, want %d", got, want)
	}
	wantPlain := []byte{0x07, emm.MsgSecurityModeCommand, 0x22, 0x00, 0x02, 0xf0, 0x70}
	if !bytes.Equal(nasPDU[6:], wantPlain) {
		t.Fatalf("plain SMC: got %x, want %x", nasPDU[6:], wantPlain)
	}

	knasInt, _, err := security.DeriveNASKeys(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatalf("DeriveNASKeys: %v", err)
	}
	macInput := append([]byte{0x00}, wantPlain...)
	wantMAC, err := security.ComputeNASMAC(security.AlgIDEIA2, knasInt, 0, 0, 1, macInput)
	if err != nil {
		t.Fatalf("ComputeNASMAC: %v", err)
	}
	if !bytes.Equal(nasPDU[1:5], wantMAC) {
		t.Fatalf("SMC MAC: got %x, want %x", nasPDU[1:5], wantMAC)
	}
}

func TestProcessAuthResponseSecurityModeCommandNormalizesRealUECapability(t *testing.T) {
	srv := newTAUTestServer()
	srv.secCfg = config.SecurityConfig{
		IntegrityAlgorithms: []string{"EIA2"},
		CipheringAlgorithms: []string{"EEA2"},
	}
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.ENBS1APID = 1

	xres := []byte{0x66, 0xb2, 0x6d, 0x2c, 0xac, 0x1a, 0xe7, 0x8d}
	kasme := mustHexForS1AP(t, "410d87ad18eb7135366d55a4c12d593360a92e33644c6eba01fb9adeb1fb3542")
	initialAttach := mustHexForS1AP(t, "0741620bf61351347fa601c100da0805f0f0e0e01d00320201d031272c8080211001010010810600000000830600000000000100000300000c00000d000007000008000009000012005213513400015c4108310375607e901103575892200b6014205230200002c00480400800021f00040260045d0103e0c1")
	ue.Lock()
	ue.XRES = append([]byte(nil), xres...)
	ue.KASME = append([]byte(nil), kasme...)
	ue.UENetworkCapability = mustHexForS1AP(t, "f0f0e0e01d")
	ue.InitialAttachRequestNAS = append([]byte(nil), initialAttach...)
	ue.Unlock()

	body := append([]byte{byte(len(xres))}, xres...)
	if err := srv.processAuthResponse(ue, body, srv.log.With(zap.String("test", "smc-real-ue-cap"))); err != nil {
		t.Fatalf("processAuthResponse: %v", err)
	}

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromPDU(t, msg)
	wantPlain := []byte{0x07, emm.MsgSecurityModeCommand, 0x22, 0x00, 0x04, 0xf0, 0xf0, 0xe0, 0x60}
	if !bytes.Equal(nasPDU[6:], wantPlain) {
		t.Fatalf("plain SMC: got %x, want %x", nasPDU[6:], wantPlain)
	}
}

func TestProcessAuthResponseProtectedAttachFiveByteReplayNoHashMME(t *testing.T) {
	srv := newTAUTestServer()
	srv.secCfg = config.SecurityConfig{
		IntegrityAlgorithms: []string{"EIA2"},
		CipheringAlgorithms: []string{"EEA2"},
	}
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.ENBS1APID = 1

	xres := []byte{0x31, 0x13, 0xfc, 0x4e, 0x6a, 0xf5, 0x32, 0x48}
	kasme := mustHexForS1AP(t, "dace988497fb805cb9fc3c4e0b89e3949c97ec9404207cfa8b566122ed2e3249")
	ue.Lock()
	ue.XRES = append([]byte(nil), xres...)
	ue.KASME = append([]byte(nil), kasme...)
	ue.UENetworkCapability = mustHexForS1AP(t, "f0f0c04009")
	ue.MSNetworkCapability = mustHexForS1AP(t, "65a07e")
	ue.InitialAttachRequestNAS = nil
	ue.Unlock()

	body := append([]byte{byte(len(xres))}, xres...)
	if err := srv.processAuthResponse(ue, body, srv.log.With(zap.String("test", "smc-five-byte-no-hash"))); err != nil {
		t.Fatalf("processAuthResponse: %v", err)
	}

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromPDU(t, msg)
	wantPlain := []byte{0x07, emm.MsgSecurityModeCommand, 0x22, 0x00, 0x05, 0xf0, 0xf0, 0xc0, 0x40, 0x10}
	if !bytes.Equal(nasPDU[6:], wantPlain) {
		t.Fatalf("plain SMC: got %x, want %x", nasPDU[6:], wantPlain)
	}
}

func TestInitialUEProtectedAttachSuppressesHashMME(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.11:36412"
	setupSendCapture(srv, remoteAddr)

	protectedAttach := mustHexForS1AP(t, "17f6f440a64f0741620bf61351347fa601c100da0805f0f0e0e01d00320201d031272c8080211001010010810600000000830600000000000100000300000c00000d000007000008000009000012005213513400015c4108310375607e901103575892200b6014205230200002c00480400800021f00040260045d0103e0c1")
	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: 0, Value: ies.EncodeENBUEApID(268200)},
		{ID: pdu.IENAS_PDU, Criticality: 0, Value: ies.EncodeNASPDU(protectedAttach)},
		{ID: pdu.IETAI, Criticality: 0, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}
	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, 0, ieList))

	list := srv.ueManager.List()
	if len(list) != 1 {
		t.Fatalf("UE contexts got %d, want 1", len(list))
	}
	list[0].Lock()
	stored := append([]byte(nil), list[0].InitialAttachRequestNAS...)
	list[0].Unlock()
	if len(stored) != 0 {
		t.Fatalf("protected Initial UE Attach should not prepare HASH MME input: got %x", stored[:minLen(len(stored), 8)])
	}
}

func decodeNASPDUFromPDU(t *testing.T, msg *pdu.PDU) []byte {
	t.Helper()
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

func mustHexForS1AP(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func minLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}
