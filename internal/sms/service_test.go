package sms

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type testTransport struct{ got *MORequest }

func (t *testTransport) SendMobileOriginatedSMS(_ context.Context, r *MORequest) (*MOResult, error) {
	t.got = r
	return &MOResult{}, nil
}

type alertTestTransport struct {
	testTransport
	alerts []*AlertRequest
	err    error
}

func (t *alertTestTransport) SendAlertServiceCentre(_ context.Context, req *AlertRequest) error {
	t.alerts = append(t.alerts, req)
	return t.err
}
func TestHandleMOExtractsTPDUForSGd(t *testing.T) {
	tr := &testTransport{}
	svc := New(tr)
	rp := []byte{0, 7, 0, 2, 0x91, 0x21, 3, 1, 2, 3}
	_, err := svc.HandleMO(context.Background(), "00101", "", rp)
	if err != nil || !bytes.Equal(tr.got.SMRPUI, []byte{1, 2, 3}) {
		t.Fatalf("%#v %v", tr.got, err)
	}
}

func TestNotifyUEReachableConsumesOnlyAfterAlertSuccess(t *testing.T) {
	tr := &alertTestTransport{}
	svc := New(tr)
	if _, err := svc.QueueMT("00101", "tfr-1", []byte{1}, time.Minute); err != nil {
		t.Fatal(err)
	}
	alerted, err := svc.NotifyUEReachable(context.Background(), "00101", "15551230000")
	if err != nil || !alerted || len(tr.alerts) != 1 || tr.alerts[0].IMSI != "00101" {
		t.Fatalf("NotifyUEReachable = alerted=%v alerts=%#v err=%v", alerted, tr.alerts, err)
	}
	if svc.HasPendingMT("00101") {
		t.Fatal("successful alert left pending MT marker")
	}
	if _, err := svc.QueueMT("00101", "tfr-2", []byte{2}, time.Minute); err != nil {
		t.Fatal(err)
	}
	tr.err = context.DeadlineExceeded
	if _, err := svc.NotifyUEReachable(context.Background(), "00101", "15551230000"); err == nil {
		t.Fatal("accepted failed alert")
	}
	if !svc.HasPendingMT("00101") {
		t.Fatal("failed alert discarded retry marker")
	}
}
