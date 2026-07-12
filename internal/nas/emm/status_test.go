package emm

import "testing"

func TestDecodeEMMStatusCauses(t *testing.T) {
	tests := []struct {
		plain []byte
		cause uint8
		name  string
	}{
		{[]byte{0x07, MsgEMMStatus, CauseSemanticallyIncorrectMessage}, CauseSemanticallyIncorrectMessage, "Semantically incorrect message"},
		{[]byte{0x07, MsgEMMStatus, CauseInvalidMandatoryInformation}, CauseInvalidMandatoryInformation, "Invalid mandatory information"},
		{[]byte{0x07, MsgEMMStatus, CauseMessageTypeNonExistent}, CauseMessageTypeNonExistent, "Message type non-existent or not implemented"},
		{[]byte{0x07, MsgEMMStatus, CauseMessageTypeNotCompatible}, CauseMessageTypeNotCompatible, "Message type not compatible with protocol state"},
		{[]byte{0x07, MsgEMMStatus, CauseIENonExistent}, CauseIENonExistent, "Information element non-existent or not implemented"},
		{[]byte{0x07, MsgEMMStatus, CauseConditionalIEError}, CauseConditionalIEError, "Conditional IE error"},
		{[]byte{0x07, MsgEMMStatus, CauseMessageNotCompatible}, CauseMessageNotCompatible, "Message not compatible with protocol state"},
		{[]byte{0x07, MsgEMMStatus, CauseProtocolError}, CauseProtocolError, "Protocol error, unspecified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgType, body, err := ParsePlainNASMessage(tt.plain)
			if err != nil {
				t.Fatalf("ParsePlainNASMessage: %v", err)
			}
			if msgType != MsgEMMStatus {
				t.Fatalf("msg type got 0x%02x, want 0x%02x", msgType, MsgEMMStatus)
			}
			status, err := DecodeEMMStatus(body)
			if err != nil {
				t.Fatalf("DecodeEMMStatus: %v", err)
			}
			if status.Cause != tt.cause {
				t.Fatalf("cause got 0x%02x, want 0x%02x", status.Cause, tt.cause)
			}
			if got := CauseName(status.Cause); got != tt.name {
				t.Fatalf("cause name got %q, want %q", got, tt.name)
			}
		})
	}
}

func TestDecodeEMMStatusInvalidLength(t *testing.T) {
	if _, err := DecodeEMMStatus(nil); err == nil {
		t.Fatal("DecodeEMMStatus(nil) expected error")
	}
}

func TestEncodeEMMStatus(t *testing.T) {
	got := EncodeEMMStatus(CauseProtocolError)
	want := []byte{0x07, MsgEMMStatus, CauseProtocolError}
	if string(got) != string(want) {
		t.Fatalf("EncodeEMMStatus got %x, want %x", got, want)
	}
}
