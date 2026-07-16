package esm

import "testing"

func TestDecodeBearerResourceModificationRequest(t *testing.T) {
	data := []byte{0x02, 0x02, MsgBearerResourceModificationRequest, 0x09, 0x05, 0xa4, 0x20, 0x21, 0x12, 0x13, 0x58, 0x24}
	req, err := DecodeBearerResourceModificationRequest(data)
	if err != nil {
		t.Fatalf("DecodeBearerResourceModificationRequest: %v", err)
	}
	if got, want := req.EPSBearerID, uint8(0); got != want {
		t.Fatalf("EPSBearerID got %d, want %d", got, want)
	}
	if got, want := req.ProcedureTransactionID, uint8(2); got != want {
		t.Fatalf("PTI got %d, want %d", got, want)
	}
	if got, want := req.LinkedEPSBearerID, uint8(9); got != want {
		t.Fatalf("LinkedEPSBearerID got %d, want %d", got, want)
	}
	if got, want := req.TFA, []byte{0x05, 0xa4, 0x20, 0x21, 0x12, 0x13, 0x58, 0x24}; string(got) != string(want) {
		t.Fatalf("TFA got %x, want %x", got, want)
	}
}
