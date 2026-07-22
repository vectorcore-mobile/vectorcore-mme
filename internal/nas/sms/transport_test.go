package sms

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNASContainerRoundTrip(t *testing.T) {
	b, err := EncodeNASContainer([]byte{9, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeNASContainer(b)
	if err != nil || !bytes.Equal(got, []byte{9, 1, 2}) {
		t.Fatalf("%x %v", got, err)
	}
}

func TestDecodeUplinkNASTransportExactCapturedMOSMS(t *testing.T) {
	pdu, err := hex.DecodeString("07632129011e00030007915155000000f01205240b816157022138f4000005d4f29c0e02")
	if err != nil {
		t.Fatal(err)
	}
	container, err := DecodeUplinkNASTransport(pdu)
	if err != nil {
		t.Fatal(err)
	}
	want := "29011e00030007915155000000f01205240b816157022138f4000005d4f29c0e02"
	if len(pdu) != 36 || pdu[1] != uplinkNASTransportType || int(pdu[2]) != 33 || len(pdu)-3 != 33 {
		t.Fatalf("captured framing pdu=%d type=%#x declared=%d available=%d", len(pdu), pdu[1], pdu[2], len(pdu)-3)
	}
	if len(container) != 33 || container[0] != 0x29 || hex.EncodeToString(container) != want {
		t.Fatalf("container=%x", container)
	}
	if !bytes.Equal(container, pdu[3:]) {
		t.Fatalf("container does not begin at byte offset 3: %x", container)
	}
}

func TestDecodeNASContainerLengths(t *testing.T) {
	max := append([]byte{255}, bytes.Repeat([]byte{0x29}, 255)...)
	cases := []struct {
		name    string
		payload []byte
		valid   bool
	}{
		{"minimum", []byte{1, 0x29}, true},
		{"maximum", max, true},
		{"short", nil, false},
		{"declared-too-large", []byte{2, 0x29}, false},
		{"nonzero-no-payload", []byte{1}, false},
		{"trailing-bytes", []byte{1, 0x29, 0x00}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeNASContainer(tc.payload)
			if (err == nil) != tc.valid {
				t.Fatalf("DecodeNASContainer(%x) err=%v", tc.payload, err)
			}
		})
	}
}
