package s1ap

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/diameter/sgd"
	smsservice "github.com/vectorcore/mme/internal/sms"
	"github.com/vectorcore/mme/internal/uecontext"
)

type capturedMOTransport struct{ requests chan *smsservice.MORequest }

func (t *capturedMOTransport) SendMobileOriginatedSMS(_ context.Context, req *smsservice.MORequest) (*smsservice.MOResult, error) {
	t.requests <- req
	return &smsservice.MOResult{}, nil
}

func TestAllocateMTSMSTIWrapsPerUE(t *testing.T) {
	s := &Server{nextMTSMSTI: make(map[string]uint8)}
	for i := uint8(0); i < 8; i++ {
		if got := s.allocateMTSMSTI("00101"); got != i {
			t.Fatalf("TI %d = %d", i, got)
		}
	}
	if got := s.allocateMTSMSTI("00101"); got != 0 {
		t.Fatalf("wrapped TI = %d", got)
	}
	if got := s.allocateMTSMSTI("00102"); got != 0 {
		t.Fatalf("separate UE TI = %d", got)
	}
}

func TestCapturedMOSMSDispatchesToSMSService(t *testing.T) {
	transport := &capturedMOTransport{requests: make(chan *smsservice.MORequest, 1)}
	manager := uecontext.NewManager()
	ue := manager.Allocate()
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.MSISDN = "15551230000"
	ue.ENBGlobalID = "test-enb"
	ue.ENBS1APID = 1
	ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
	ue.Unlock()
	manager.Register(ue)
	s := &Server{ueManager: manager, sms: smsservice.New(transport), log: zap.NewNop(), nextMTSMSTI: make(map[string]uint8)}
	downlink := make(chan []byte, 4)
	s.sends.Store("test-enb", (chan<- []byte)(downlink))
	pdu, err := hex.DecodeString("07632129011e00030007915155000000f01205240b816157022138f4000005d4f29c0e02")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.processUplinkSMS(ue, pdu[2:]); err != nil {
		t.Fatalf("processUplinkSMS: %v", err)
	}
	select {
	case req := <-transport.requests:
		if req.IMSI != "001010123456789" || req.RPReference != 3 || len(req.SMRPUI) != 18 {
			t.Fatalf("MO request = %#v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("captured MO SMS did not reach SMS service")
	}
	// A UE may retransmit the same CP-DATA when its first immediate CP-ACK is
	// lost. The MME must re-ACK it without creating another MO-FSM request.
	if err := s.processUplinkSMS(ue, pdu[2:]); err != nil {
		t.Fatalf("duplicate MO CP-DATA: %v", err)
	}
	select {
	case <-transport.requests:
		t.Fatal("duplicate CP-DATA created a second MO request")
	case <-time.After(50 * time.Millisecond):
	}
	// This test stops at service dispatch; explicitly release the asynchronous
	// CP transaction so it cannot leave a timer running after the test.
	key := moSMSKey("001010123456789", 2)
	if v, ok := s.pendingMOSMS.Load(key); ok {
		tx := v.(*pendingMOSMS)
		tx.mu.Lock()
		tx.state = moSMSFailed
		tx.mu.Unlock()
		s.finishMOSMS("001010123456789", 2, tx)
	}
}

func TestMOSMSTransactionWaitsForFinalCPAck(t *testing.T) {
	transport := &capturedMOTransport{requests: make(chan *smsservice.MORequest, 1)}
	manager := uecontext.NewManager()
	ue := manager.Allocate()
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.MSISDN = "15551230000"
	ue.ENBGlobalID = "test-enb"
	ue.ENBS1APID = 1
	ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
	ue.Unlock()
	manager.Register(ue)
	s := &Server{ueManager: manager, sms: smsservice.New(transport), log: zap.NewNop(), nextMTSMSTI: make(map[string]uint8)}
	downlink := make(chan []byte, 4)
	s.sends.Store("test-enb", (chan<- []byte)(downlink))
	pdu, err := hex.DecodeString("07632129011e00030007915155000000f01205240b816157022138f4000005d4f29c0e02")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.processUplinkSMS(ue, pdu[2:]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.requests:
	case <-time.After(time.Second):
		t.Fatal("MO request was not submitted")
	}
	key := moSMSKey("001010123456789", 2)
	deadline := time.Now().Add(time.Second)
	for {
		if v, ok := s.pendingMOSMS.Load(key); ok {
			tx := v.(*pendingMOSMS)
			tx.mu.Lock()
			state := tx.state
			tx.mu.Unlock()
			if state == moSMSWaitingFinalCPAck {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("MO transaction did not wait for final CP-ACK")
		}
		time.Sleep(time.Millisecond)
	}
	// Cisco's final acknowledgement has the UE-originated TIO again: 29 04.
	if err := s.processUplinkSMS(ue, []byte{2, 0x29, 0x04}); err != nil {
		t.Fatalf("final CP-ACK: %v", err)
	}
	if _, ok := s.pendingMOSMS.Load(key); ok {
		t.Fatal("MO transaction was retained after final CP-ACK")
	}
}

func TestCapturedCPErrorIsDispatchedWithoutCPDataDecode(t *testing.T) {
	ue := uecontext.NewContext(7)
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.Unlock()
	s := &Server{log: zap.NewNop()}
	// Plain Uplink NAS Transport: 07 63 03 89 10 51.
	if err := s.processUplinkSMS(ue, []byte{3, 0x89, 0x10, 0x51}); err != nil {
		t.Fatalf("valid CP-ERROR rejected: %v", err)
	}
}

func TestMTRPAckPreservesReferenceAndSendsFinalCPAck(t *testing.T) {
	manager := uecontext.NewManager()
	ue := manager.Allocate()
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.ENBGlobalID = "test-enb"
	ue.ENBS1APID = 1
	ue.Unlock()
	manager.Register(ue)
	s := &Server{ueManager: manager, log: zap.NewNop()}
	downlink := make(chan []byte, 1)
	s.sends.Store("test-enb", (chan<- []byte)(downlink))
	pending := &pendingMTSMS{ti: 0, rpReference: 0xff, result: make(chan mtSMSResult, 1)}
	s.pendingMTSMS.Store("001010123456789", pending)
	defer s.pendingMTSMS.Delete("001010123456789")

	// Cisco's MT RP result: UE CP-DATA 89 01 02 02 ff. The MME must
	// preserve 0xff and return standalone CP-ACK 09 04.
	if err := s.processUplinkSMS(ue, []byte{5, 0x89, 0x01, 2, 0x02, 0xff}); err != nil {
		t.Fatalf("MT RP-ACK: %v", err)
	}
	select {
	case result := <-pending.result:
		if result.resultCode != 2001 {
			t.Fatalf("MT result code = %d", result.resultCode)
		}
	case <-time.After(time.Second):
		t.Fatal("MT RP-ACK did not complete pending delivery")
	}
	select {
	case <-downlink:
	case <-time.After(time.Second):
		t.Fatal("final CP-ACK was not sent")
	}
}

func TestPendingMTDeliversOnlyAfterServiceRequestResume(t *testing.T) {
	manager := uecontext.NewManager()
	ue := manager.Allocate()
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.ENBGlobalID = "test-enb"
	ue.ENBS1APID = 1
	ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
	ue.Unlock()
	manager.Register(ue)
	s := &Server{ueManager: manager, sms: smsservice.New(nil), log: zap.NewNop()}
	downlink := make(chan []byte, 1)
	s.sends.Store("test-enb", (chan<- []byte)(downlink))
	pending := &pendingMTSMS{
		ti: 0, rpReference: 0xff, result: make(chan mtSMSResult, 1), state: "paging",
		request: &sgd.MTRequest{SessionID: "tfr-1", IMSI: "001010123456789", SCAddress: []byte("15550000000"), SMRPUI: []byte{4, 0xaa}},
	}
	s.pendingMTSMS.Store("001010123456789", pending)
	defer s.pendingMTSMS.Delete("001010123456789")

	s.deliverPendingMTSMS(ue)
	if pending.state != "waiting_for_rp_ack" {
		t.Fatalf("MT state = %q", pending.state)
	}
	select {
	case <-downlink:
	case <-time.After(time.Second):
		t.Fatal("pending MT was not delivered after Service Request resume")
	}
}
