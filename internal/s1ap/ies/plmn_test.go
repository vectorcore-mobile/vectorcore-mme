package ies

import (
	"bytes"
	"testing"
)

func TestPLMNEncodeDecodeTBCD(t *testing.T) {
	tests := []struct {
		name string
		mcc  string
		mnc  string
		wire []byte
	}{
		{name: "three digit 311/435", mcc: "311", mnc: "435", wire: []byte{0x13, 0x41, 0x53}},
		{name: "three digit 310/260", mcc: "310", mnc: "260", wire: []byte{0x13, 0x20, 0x06}},
		{name: "two digit 001/01", mcc: "001", mnc: "01", wire: []byte{0x00, 0xF1, 0x10}},
		{name: "two digit 262/01", mcc: "262", mnc: "01", wire: []byte{0x62, 0xF2, 0x10}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePLMN(tt.mcc, tt.mnc)
			if err != nil {
				t.Fatalf("EncodePLMN: %v", err)
			}
			if !bytes.Equal(got, tt.wire) {
				t.Fatalf("EncodePLMN: got % X, want % X", got, tt.wire)
			}

			mcc, mnc, err := DecodePLMN(tt.wire)
			if err != nil {
				t.Fatalf("DecodePLMN: %v", err)
			}
			if mcc != tt.mcc || mnc != tt.mnc {
				t.Fatalf("DecodePLMN: got %s/%s, want %s/%s", mcc, mnc, tt.mcc, tt.mnc)
			}
		})
	}
}

func TestECGIRoundTripThreeDigitMNC(t *testing.T) {
	wire, err := EncodeECGI(ECGI{MCC: "311", MNC: "435", ECGI: 0x05300c81})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	want := []byte{0x13, 0x41, 0x53, 0x53, 0x00, 0xC8, 0x10}
	if !bytes.Equal(wire, want) {
		t.Fatalf("EncodeECGI: got % X, want % X", wire, want)
	}
	decoded, err := DecodeECGI(wire)
	if err != nil {
		t.Fatalf("DecodeECGI: %v", err)
	}
	if decoded.MCC != "311" || decoded.MNC != "435" || decoded.ECGI != 0x05300c81 {
		t.Fatalf("DecodeECGI: got %+v, want MCC=311 MNC=435 ECGI=0x05300c81", decoded)
	}
}
