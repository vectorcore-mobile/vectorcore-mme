package s1ap

import (
	"bytes"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/nas/emm"
	smsservice "github.com/vectorcore/mme/internal/sms"
	"github.com/vectorcore/mme/internal/uecontext"
)

const mtOutcomeIMSI = "001010123456789"

func assertAbsentUser(t *testing.T, name string, got sgd.MTOutcome, diag uint32) {
	t.Helper()
	if got.ExperimentalResultCode != sgd.ResultErrorAbsentUser || got.ResultCode != 0 ||
		got.AbsentUserDiagnostic == nil || *got.AbsentUserDiagnostic != diag {
		t.Fatalf("%s: outcome = %+v, want 5550 with Absent-User-Diagnostic-SM %d", name, got, diag)
	}
}

func assertDeliveryFailure(t *testing.T, name string, got sgd.MTOutcome, cause uint32, diagInfo []byte) {
	t.Helper()
	if got.ExperimentalResultCode != sgd.ResultErrorSMDeliveryFailure || got.ResultCode != 0 ||
		got.DeliveryFailureCause == nil || *got.DeliveryFailureCause != cause || !bytes.Equal(got.DiagnosticInfo, diagInfo) {
		t.Fatalf("%s: outcome = %+v, want 5555 cause %d diag %x", name, got, cause, diagInfo)
	}
}

// newMTOutcomeServer returns a server with one SMS-registered UE whose
// downlink NAS goes to the returned channel.
func newMTOutcomeServer(t *testing.T, connected bool) (*Server, *uecontext.Context, chan []byte) {
	t.Helper()
	manager := uecontext.NewManager()
	ue := manager.Allocate()
	ue.Lock()
	ue.IMSI = mtOutcomeIMSI
	ue.ENBGlobalID = "test-enb"
	ue.ENBS1APID = 1
	ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
	if connected {
		ue.ECMState = emm.ECMConnected
	} else {
		ue.ECMState = emm.ECMIdle
	}
	ue.Unlock()
	manager.Register(ue)
	s := &Server{ueManager: manager, sms: smsservice.New(nil), log: zap.NewNop(), nextMTSMSTI: map[string]uint8{}}
	downlink := make(chan []byte, 8)
	s.sends.Store("test-enb", (chan<- []byte)(downlink))
	return s, ue, downlink
}

func mtRequest() *sgd.MTRequest {
	return &sgd.MTRequest{SessionID: "tfr-1", IMSI: mtOutcomeIMSI, SCAddress: []byte{0x51, 0x55, 0xf0}, SMRPUI: []byte{0x04, 0xaa}}
}

func TestHandleSGdMTUnreachableUEIsAbsentUser(t *testing.T) {
	s, ue, _ := newMTOutcomeServer(t, true)

	unknown := mtRequest()
	unknown.IMSI = "001019999999999"
	assertAbsentUser(t, "unknown IMSI", s.HandleSGdMT(unknown), sgd.AbsentDiagIMSIDetached)

	ue.Lock()
	ue.SMSRegistrationState = uecontext.SMSRegistrationState("")
	ue.Unlock()
	assertAbsentUser(t, "not SMS-registered", s.HandleSGdMT(mtRequest()), sgd.AbsentDiagIMSIDetached)

	// ECM-IDLE with no GUTI/TAI: paging cannot even be started.
	s, _, _ = newMTOutcomeServer(t, false)
	assertAbsentUser(t, "paging not started", s.HandleSGdMT(mtRequest()), sgd.AbsentDiagTemporarilyUnavailable)
}

func TestHandleSGdMTSecondTransactionIsUserBusy(t *testing.T) {
	s, _, _ := newMTOutcomeServer(t, true)
	s.pendingMTSMS.Store(mtOutcomeIMSI, &pendingMTSMS{result: make(chan sgd.MTOutcome, 1)})
	got := s.HandleSGdMT(mtRequest())
	if got.ExperimentalResultCode != sgd.ResultErrorUserBusyForMTSMS || got.ResultCode != 0 {
		t.Fatalf("outcome = %+v, want 5551", got)
	}
}

func TestHandleSGdMTNoRPAnswerAfterDeliveryIsTemporarilyUnavailable(t *testing.T) {
	s, _, downlink := newMTOutcomeServer(t, true)
	s.smsTimeout = 50 * time.Millisecond
	assertAbsentUser(t, "RP timeout", s.HandleSGdMT(mtRequest()), sgd.AbsentDiagTemporarilyUnavailable)
	select {
	case <-downlink:
	default:
		t.Fatal("CP-DATA was not sent before the timeout")
	}
}

func TestMTTimeoutOutcomeDistinguishesPagingFromRPTimeout(t *testing.T) {
	pending := &pendingMTSMS{}
	assertAbsentUser(t, "paging unanswered", mtTimeoutOutcome(pending), sgd.AbsentDiagNoPagingResponse)
	pending.cpDataSent.Store(true)
	assertAbsentUser(t, "RP-DATA unanswered", mtTimeoutOutcome(pending), sgd.AbsentDiagTemporarilyUnavailable)
}

// TestMTUplinkErrorsMapToTS29338 drives UE CP-ERROR / RP-ERROR through the
// uplink NAS path and checks the outcome handed to the waiting TFR.
func TestMTUplinkErrorsMapToTS29338(t *testing.T) {
	deliverReport := []byte{0x00, 0xd2, 0x00} // SMS-DELIVER-REPORT, TP-FCS 0xD2
	cases := []struct {
		name  string
		cpdu  []byte // CP layer PDU from the UE (TI 0, TI flag set)
		check func(*testing.T, sgd.MTOutcome)
	}{
		{"RP-ERROR memory capacity exceeded",
			append([]byte{0x89, 0x01, 9, 0x04, 0x00, 1, 22, 0x41, 3}, deliverReport...),
			func(t *testing.T, o sgd.MTOutcome) {
				assertDeliveryFailure(t, "memory full", o, sgd.DeliveryFailureMemoryCapacityExceeded, deliverReport)
			}},
		{"RP-ERROR protocol error with diagnostic octet",
			[]byte{0x89, 0x01, 5, 0x04, 0x00, 2, 0x80 | 111, 0x00},
			func(t *testing.T, o sgd.MTOutcome) {
				assertDeliveryFailure(t, "protocol error", o, sgd.DeliveryFailureEquipmentProtocolError, nil)
			}},
		{"CP-ERROR congestion", []byte{0x89, 0x10, 22},
			func(t *testing.T, o sgd.MTOutcome) {
				if o.ExperimentalResultCode != sgd.ResultErrorUserBusyForMTSMS {
					t.Fatalf("outcome = %+v, want 5551", o)
				}
			}},
		{"CP-ERROR invalid TI", []byte{0x89, 0x10, 81},
			func(t *testing.T, o sgd.MTOutcome) {
				assertDeliveryFailure(t, "CP protocol error", o, sgd.DeliveryFailureEquipmentProtocolError, nil)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ue, _ := newMTOutcomeServer(t, true)
			pending := &pendingMTSMS{ti: 0, rpReference: 0, result: make(chan sgd.MTOutcome, 1)}
			s.pendingMTSMS.Store(mtOutcomeIMSI, pending)
			if err := s.processUplinkSMS(ue, append([]byte{byte(len(tc.cpdu))}, tc.cpdu...)); err != nil {
				t.Fatalf("processUplinkSMS: %v", err)
			}
			select {
			case o := <-pending.result:
				tc.check(t, o)
			case <-time.After(time.Second):
				t.Fatal("MT transaction not completed")
			}
		})
	}
}

func TestNetworkDetachCompletesPendingMTAsAbsentUser(t *testing.T) {
	s, ue, _ := newMTOutcomeServer(t, true)
	pending := &pendingMTSMS{result: make(chan sgd.MTOutcome, 1)}
	s.pendingMTSMS.Store(mtOutcomeIMSI, pending)
	s.HandleNetworkDetach(ue)
	assertAbsentUser(t, "CLR detach", <-pending.result, sgd.AbsentDiagIMSIDetached)

	// Implicit-detach cleanup used to send a zero Result-Code.
	pending = &pendingMTSMS{result: make(chan sgd.MTOutcome, 1)}
	s.pendingMTSMS.Store(mtOutcomeIMSI, pending)
	s.cleanupUEOwnedSMS(ue)
	got := <-pending.result
	if got.Code() == 0 {
		t.Fatal("implicit-detach cleanup produced a zero result code")
	}
	assertAbsentUser(t, "implicit detach", got, sgd.AbsentDiagIMSIDetached)
}
