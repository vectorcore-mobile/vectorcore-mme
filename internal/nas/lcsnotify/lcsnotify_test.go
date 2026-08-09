package lcsnotify

import (
	"bytes"
	"testing"
)

func TestEncodeRegisterWireLayout(t *testing.T) {
	msg, err := EncodeRegister(NotifyAndVerifyLocationAllowedIfNoResponse)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x0B,       // TI=0/flag=0 | PD=supplementary services
		0x3B,       // REGISTER
		0x1C, 0x12, // Facility IEI, length=18
		0xA1, 0x10, // Invoke, length=16
		0x02, 0x01, 0x01, // Invoke ID = 1
		0x02, 0x01, 0x74, // Operation Code = 116
		0x30, 0x08, // LocationNotificationArg SEQUENCE, length=8
		0x80, 0x01, 0x01, // notificationType [0] = 1 (NotifyAndVerifyLocationAllowedIfNoResponse)
		0xA1, 0x03, // locationType [1], length=3
		0x80, 0x01, 0x05, // locationEstimateType [0] = 5 (notificationVerificationOnly)
	}
	if !bytes.Equal(msg, want) {
		t.Fatalf("got  %x\nwant %x", msg, want)
	}
}

func TestEncodeRegisterRejectsInvalidNotificationType(t *testing.T) {
	if _, err := EncodeRegister(NotificationType(3)); err == nil {
		t.Fatal("want error for out-of-range notification type")
	}
}

func TestDecodeReleaseCompleteBareGrant(t *testing.T) {
	// RELEASE COMPLETE with a Facility IE carrying a bare Return Result
	// (Invoke ID only, no parameters): implicit consent.
	msg := []byte{
		0x8B, 0x2A, // TI=0/flag=1 | PD, RELEASE COMPLETE
		0x1C, 0x05, // Facility IEI, length=5
		0xA2, 0x03, // Return Result, length=3
		0x02, 0x01, 0x01, // Invoke ID = 1
	}
	granted, err := DecodeReleaseComplete(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Fatal("want granted=true for bare Return Result")
	}
}

func TestDecodeReleaseCompleteExplicitGrantAndDenial(t *testing.T) {
	build := func(verification byte) []byte {
		res := tlv(tagSequence, tlv(0x80, []byte{verification}))             // LocationNotificationRes{verificationResponse}
		seq := tlv(tagSequence, append(tlv(tagOpCode, []byte{116}), res...)) // Sequence{OpCode, Parameters}
		rr := append(tlv(tagInvokeID, []byte{1}), seq...)
		component := tlv(tagReturnResult, rr)
		facility := tlv(ieiFacility, component)
		return append([]byte{0x8B, 0x2A}, facility...)
	}
	granted, err := DecodeReleaseComplete(build(verificationResponsePermissionGranted))
	if err != nil || !granted {
		t.Fatalf("permissionGranted: granted=%v err=%v", granted, err)
	}
	granted, err = DecodeReleaseComplete(build(0)) // permissionDenied
	if err != nil || granted {
		t.Fatalf("permissionDenied: granted=%v err=%v", granted, err)
	}
}

func TestDecodeReleaseCompleteReturnErrorAndReject(t *testing.T) {
	for _, tag := range []byte{tagReturnError, tagReject} {
		component := tlv(tag, tlv(tagInvokeID, []byte{1}))
		facility := tlv(ieiFacility, component)
		msg := append([]byte{0x8B, 0x2A}, facility...)
		granted, err := DecodeReleaseComplete(msg)
		if err != nil {
			t.Fatalf("tag 0x%02x: unexpected error %v", tag, err)
		}
		if granted {
			t.Fatalf("tag 0x%02x: want granted=false", tag)
		}
	}
}

func TestDecodeReleaseCompleteNoFacility(t *testing.T) {
	msg := []byte{0x8B, 0x2A} // no optional IEs at all
	granted, err := DecodeReleaseComplete(msg)
	if err != nil {
		t.Fatal(err)
	}
	if granted {
		t.Fatal("want granted=false when UE releases with no Facility IE")
	}
}

func TestDecodeReleaseCompleteRejectsWrongMessage(t *testing.T) {
	if _, err := DecodeReleaseComplete([]byte{0x0B, 0x3B}); err == nil {
		t.Fatal("want error for non-RELEASE-COMPLETE message")
	}
}
