package sms

import (
	"testing"
	"time"
)

func TestPendingMTLifecycle(t *testing.T) {
	s := New(nil)
	p, err := s.QueueMT("001010123456789", "corr-1", []byte{1, 2}, time.Second)
	if err != nil || p.IMSI != "001010123456789" {
		t.Fatalf("QueueMT = %#v, %v", p, err)
	}
	dup, err := s.QueueMT("001010123456789", "corr-2", []byte{3}, time.Second)
	if err != nil || dup.Correlation != "corr-1" {
		t.Fatalf("duplicate = %#v, %v", dup, err)
	}
	got, ok := s.TakePendingMT("001010123456789")
	if !ok || got.Correlation != "corr-1" {
		t.Fatalf("TakePendingMT = %#v, %v", got, ok)
	}
	if _, ok := s.TakePendingMT("001010123456789"); ok {
		t.Fatal("pending MT not removed")
	}
}

func TestPendingMTExpiresWithoutReachability(t *testing.T) {
	s := New(nil)
	if _, err := s.QueueMT("001010123456789", "corr-1", []byte{1}, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if s.HasPendingMT("001010123456789") {
		t.Fatal("expired MT remained pending")
	}
}
