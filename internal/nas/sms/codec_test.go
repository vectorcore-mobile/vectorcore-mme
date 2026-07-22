package sms

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCPRPDataMO(t *testing.T) {
	rp := []byte{0, 7, 0, 2, 0x91, 0x21, 3, 1, 2, 3}
	cp, err := EncodeCPData(3, rp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCP(cp)
	if err != nil || !bytes.Equal(got.RPDU, rp) {
		t.Fatalf("CP %#v %v", got, err)
	}
	data, err := DecodeRPDataMO(got.RPDU)
	if err != nil || data.Reference != 7 || !bytes.Equal(data.TPDU, []byte{1, 2, 3}) {
		t.Fatalf("RP %#v %v", data, err)
	}
}

func TestCPTransactionIdentifierDirection(t *testing.T) {
	cp, err := EncodeCPDataWithDirection(5, true, []byte{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if cp[0] != 0xd9 {
		t.Fatalf("CP header = %#x", cp[0])
	}
	decoded, err := DecodeCP(cp)
	if err != nil || decoded.TI != 5 || !decoded.TransactionIDFlag {
		t.Fatalf("DecodeCP = %#v, %v", decoded, err)
	}
	ack, err := EncodeCPAckWithDirection(decoded.TI, decoded.TransactionIDFlag)
	if err != nil || !bytes.Equal(ack, []byte{0xd9, CPAck}) {
		t.Fatalf("CP-ACK = %x, %v", ack, err)
	}
}

func TestCiscoMOCPAcknowledgementTransactionIdentifierDirection(t *testing.T) {
	// Cisco trace: UE 29 01 ...; MME  a9 04; MME a9 01 02 03 11;
	// UE 29 04.  The MME must invert TIO for both of its CP responses.
	const ueHeader = byte(0x29)
	ue, err := DecodeCP([]byte{ueHeader, CPData, 2, RPDataMO, 0x11})
	if err != nil {
		t.Fatal(err)
	}
	immediateAck, err := EncodeCPAckWithDirection(ue.TI, !ue.TransactionIDFlag)
	if err != nil || !bytes.Equal(immediateAck, []byte{0xa9, CPAck}) {
		t.Fatalf("immediate CP-ACK = %x, %v", immediateAck, err)
	}
	rpAck, err := EncodeRPAckToMS(0x11, nil)
	if err != nil {
		t.Fatal(err)
	}
	finalData, err := EncodeCPDataWithDirection(ue.TI, !ue.TransactionIDFlag, rpAck)
	if err != nil || !bytes.Equal(finalData, []byte{0xa9, CPData, 2, RPAckNetwork, 0x11}) {
		t.Fatalf("CP-DATA/RP-ACK = %x, %v", finalData, err)
	}
	finalAck, err := DecodeCP([]byte{ueHeader, CPAck})
	if err != nil || finalAck.TI != ue.TI || finalAck.TransactionIDFlag != ue.TransactionIDFlag {
		t.Fatalf("final UE CP-ACK = %#v, %v", finalAck, err)
	}
}

func TestCiscoMTCPAcknowledgementTransactionIdentifierDirection(t *testing.T) {
	// Cisco MT trace: MME 09 01 ...; UE 89 01 ...; MME 09 04.
	rpData, err := EncodeRPDataMT(0xff, []byte{0x91, 0x51, 0x55, 0x00, 0x00, 0x00, 0xf0}, []byte{4, 0xaa})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := EncodeCPDataWithDirection(0, false, rpData)
	if err != nil || initial[0] != 0x09 {
		t.Fatalf("MT CP-DATA header = %x, %v", initial, err)
	}
	ueRP, err := EncodeCPDataWithDirection(0, true, []byte{RPAckMO, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	ue, err := DecodeCP(ueRP)
	if err != nil || !ue.TransactionIDFlag || ue.TI != 0 {
		t.Fatalf("UE RP-ACK CP-DATA = %#v, %v", ue, err)
	}
	finalAck, err := EncodeCPAckWithDirection(ue.TI, !ue.TransactionIDFlag)
	if err != nil || !bytes.Equal(finalAck, []byte{0x09, CPAck}) {
		t.Fatalf("final MT CP-ACK = %x, %v", finalAck, err)
	}
}
func TestRejectMalformed(t *testing.T) {
	if _, err := DecodeCP([]byte{0x09, CPData, 2, 9}); err == nil {
		t.Fatal("accepted malformed CP")
	}
	if _, err := DecodeRPDataMO([]byte{0, 1, 0}); err == nil {
		t.Fatal("accepted malformed RP")
	}
}

func TestDecodeCPDataExactCapturedMOSMS(t *testing.T) {
	container, err := hex.DecodeString("29011e00030007915155000000f01205240b816157022138f4000005d4f29c0e02")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := DecodeCP(container)
	if err != nil {
		t.Fatalf("DecodeCP(captured MO SMS): %v", err)
	}
	if cp.TI != 2 || cp.Type != CPData || len(cp.RPDU) != 30 {
		t.Fatalf("CP = %#v", cp)
	}
	rp, err := DecodeRPDataMO(cp.RPDU)
	if err != nil || rp.Reference != 3 || len(rp.TPDU) != 18 {
		t.Fatalf("RP = %#v, %v", rp, err)
	}
}

func TestDecodeRPAckAndErrorMO(t *testing.T) {
	ref, payload, err := DecodeRPAckMO([]byte{RPAckMO, 9, RPUserDataIEI, 2, 0xaa, 0xbb})
	if err != nil || ref != 9 || !bytes.Equal(payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("RP-ACK: ref=%d payload=%x err=%v", ref, payload, err)
	}
	ref, cause, err := DecodeRPErrorMO([]byte{RPErrorMO, 9, 1, 95})
	if err != nil || ref != 9 || cause != 95 {
		t.Fatalf("RP-ERROR: ref=%d cause=%d err=%v", ref, cause, err)
	}
}

func TestEncodeNetworkRPAckMatchesCiscoMOSMS(t *testing.T) {
	ack, err := EncodeRPAckToMS(0x11, nil)
	if err != nil || !bytes.Equal(ack, []byte{0x03, 0x11}) {
		t.Fatalf("network RP-ACK = %x, %v", ack, err)
	}
	// Captured VectorCore UE rejection: 07 63 07 19 01 04 17 01 61.
	// The inner RP-ERROR is MS-to-network, reference 0x17, cause 0x61.
	ref, cause, err := DecodeRPErrorMO([]byte{0x04, 0x17, 0x01, 0x61})
	if err != nil || ref != 0x17 || cause != 0x61 {
		t.Fatalf("captured RP-ERROR: ref=%#x cause=%#x err=%v", ref, cause, err)
	}
}

func TestDecodeCPErrorExactCapture(t *testing.T) {
	cp, err := DecodeCP([]byte{0x89, CPError, 0x51})
	if err != nil {
		t.Fatal(err)
	}
	if cp.TI != 0 || !cp.TransactionIDFlag || cp.Cause == nil || *cp.Cause != 0x51 {
		t.Fatalf("CP-ERROR = %#v", cp)
	}
	encoded, err := EncodeCPErrorWithDirection(0, true, 0x51)
	if err != nil || !bytes.Equal(encoded, []byte{0x89, CPError, 0x51}) {
		t.Fatalf("EncodeCPError = %x, %v", encoded, err)
	}
}

func TestEncodeRPDataMTFromTBCDAndCiscoASCIIAddress(t *testing.T) {
	for _, sc := range [][]byte{{0x51, 0x55, 0x21, 0x03, 0x00, 0xf0}, []byte("15551230000")} {
		rp, err := EncodeRPDataMT(6, sc, []byte{0x04, 0xaa})
		if err != nil {
			t.Fatalf("EncodeRPDataMT(%x): %v", sc, err)
		}
		want := []byte{RPDataMT, 6, 7, 0x91, 0x51, 0x55, 0x21, 0x03, 0x00, 0xf0, 0, 2, 0x04, 0xaa}
		if !bytes.Equal(rp, want) {
			t.Fatalf("RP-DATA = %x, want %x", rp, want)
		}
	}
	if _, err := EncodeRPDataMT(1, []byte{0xff}, []byte{1}); err == nil {
		t.Fatal("accepted malformed SC address")
	}
}
