package gtpv2

import (
	"bytes"
	"net"
	"testing"
)

func topLevelIETypes(ies []IE) []uint8 {
	out := make([]uint8, 0, len(ies))
	for _, ie := range ies {
		out = append(out, ie.Type)
	}
	return out
}

func hasTopLevelIE(ies []IE, ieType uint8) bool {
	for _, ie := range ies {
		if ie.Type == ieType {
			return true
		}
	}
	return false
}

func TestReferencePcapCreateBearerAndPiggybackShapesMatch(t *testing.T) {
	t.Run("piggybacked_create_bearer_response_and_mbr", func(t *testing.T) {
		cbrsp := EncodeCreateBearerResponseWithMeta(0xc04dad7b, 0x239, CauseRequestAccepted, []CreateBearerBearer{
			{
				EBI:        7,
				ENBS1UTEID: 0xd68bc10f,
				ENBS1UIP:   mustDecodeHex(t, "c0a869f7"),
				SGWS1UTEID: 0x2df38f08,
				SGWS1UIP:   mustDecodeHex(t, "0a5afa3b"),
			},
			{
				EBI:        8,
				ENBS1UTEID: 0xb9df33db,
				ENBS1UIP:   mustDecodeHex(t, "c0a869f7"),
				SGWS1UTEID: 0x60f1b739,
				SGWS1UIP:   mustDecodeHex(t, "0a5afa3b"),
			},
		}, &CreateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x000c8001,
		})
		mbr := (&ModifyBearerRequest{
			SGWC_TEID:             0xc04dad7b,
			EBI:                   6,
			ENBU_TEID:             0x885fb60a,
			ENBU_IP:               mustDecodeHex(t, "c0a869f7"),
			IncludeIndicationCRSI: true,
			OmitRATType:           true,
		}).Encode(0x129c08)
		got, err := EncodePiggybacked(cbrsp, mbr)
		if err != nil {
			t.Fatalf("EncodePiggybacked: %v", err)
		}
		want := mustDecodeHex(t, "58600071c04dad7b0002390002000200100056000d00181351340001135134000c80015d00250049000100070200020010005700090080d68bc10fc0a869f757000901812df38f080a5afa3b5d00250049000100080200020010005700090080b9df33dbc0a869f7570009018160f1b7390a5afa3b4822002ac04dad7b129c08004d00080000100000000000005d00120049000100065700090080885fb60ac0a869f7")
		if !bytes.Equal(got, want) {
			t.Fatalf("piggyback mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("single_create_bearer_response_ebi_9", func(t *testing.T) {
		got := EncodeCreateBearerResponseWithMeta(0xc04dad7b, 0x23a, CauseRequestAccepted, []CreateBearerBearer{{
			EBI:        9,
			ENBS1UTEID: 0x547c9343,
			ENBS1UIP:   mustDecodeHex(t, "c0a869f7"),
			SGWS1UTEID: 0x7d02a085,
			SGWS1UIP:   mustDecodeHex(t, "0a5afa3b"),
		}}, &CreateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x000c8001,
		})
		want := mustDecodeHex(t, "48600048c04dad7b00023a0002000200100056000d00181351340001135134000c80015d00250049000100090200020010005700090080547c9343c0a869f757000901817d02a0850a5afa3b")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 23 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("single_create_bearer_response_ebi_10", func(t *testing.T) {
		got := EncodeCreateBearerResponseWithMeta(0xc04dad7b, 0x23c, CauseRequestAccepted, []CreateBearerBearer{{
			EBI:        10,
			ENBS1UTEID: 0xbb4fd88b,
			ENBS1UIP:   mustDecodeHex(t, "c0a869f7"),
			SGWS1UTEID: 0x499e1aa1,
			SGWS1UIP:   mustDecodeHex(t, "0a5afa3b"),
		}}, &CreateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x000c8001,
		})
		want := mustDecodeHex(t, "48600048c04dad7b00023c0002000200100056000d00181351340001135134000c80015d002500490001000a0200020010005700090080bb4fd88bc0a869f75700090181499e1aa10a5afa3b")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 30 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("single_create_bearer_response_later_retransmission", func(t *testing.T) {
		got := EncodeCreateBearerResponseWithMeta(0xc04dad7b, 0x243, CauseRequestAccepted, []CreateBearerBearer{{
			EBI:        9,
			ENBS1UTEID: 0x29bb23a1,
			ENBS1UIP:   mustDecodeHex(t, "c0a869f7"),
			SGWS1UTEID: 0x74e97f13,
			SGWS1UIP:   mustDecodeHex(t, "0a5afa3b"),
		}}, &CreateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x000c8001,
		})
		want := mustDecodeHex(t, "48600048c04dad7b0002430002000200100056000d00181351340001135134000c80015d0025004900010009020002001000570009008029bb23a1c0a869f7570009018174e97f130a5afa3b")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 53 mismatch\n got  %x\n want %x", got, want)
		}
	})
}

func TestReferencePcapKnownCompatibilityGaps(t *testing.T) {
	t.Run("delete_session_request_frame_59_matches_reference_ies", func(t *testing.T) {
		got := (&DeleteSessionRequest{
			SGWC_TEID:           0xc04dad7b,
			EBI:                 6,
			LocalS11TEID:        0x803de008,
			LocalS11IP:          net.ParseIP("10.90.250.77").To4(),
			IncludeIndicationOI: true,
			IncludeULI:          true,
			ULIPLMN:             [3]byte{0x13, 0x51, 0x34},
			ULITAC:              1,
			ULIECI:              0x000c8001,
			IncludeULITimestamp: true,
			ULITimestamp:        0xedfe9032,
		}).Encode(0x12ac08)
		want := mustDecodeHex(t, "4824003fc04dad7b12ac0800490001000656000d00181351340001135134000c80014d0008000800000000000000570009008a803de0080a5afa4daa000400edfe9032")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 59 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("delete_session_request_frame_63_matches_reference_ies", func(t *testing.T) {
		got := (&DeleteSessionRequest{
			SGWC_TEID:           0xc04dad7b,
			EBI:                 5,
			LocalS11TEID:        0x803de008,
			LocalS11IP:          net.ParseIP("10.90.250.77").To4(),
			IncludeIndicationOI: true,
			IncludeULI:          true,
			ULIPLMN:             [3]byte{0x13, 0x51, 0x34},
			ULITAC:              1,
			ULIECI:              0x000c8001,
			IncludeULITimestamp: true,
			ULITimestamp:        0xedfe9032,
		}).Encode(0x12ae08)
		want := mustDecodeHex(t, "4824003fc04dad7b12ae0800490001000556000d00181351340001135134000c80014d0008000800000000000000570009008a803de0080a5afa4daa000400edfe9032")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 63 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("echo_response_recovery_value_differs", func(t *testing.T) {
		got := EncodeNoTEID(&Message{
			Type:   MsgEchoResponse,
			SeqNum: 0x241,
			IEs:    []IE{EncodeRecovery(0)},
		})
		want := mustDecodeHex(t, "40020009000241000300010019")
		if bytes.Equal(got, want) {
			t.Fatal("echo response unexpectedly matches reference capture")
		}
		msg, err := Decode(want)
		if err != nil {
			t.Fatalf("Decode reference echo response: %v", err)
		}
		recovery := FindIE(msg.IEs, IETypeRecovery, 0)
		if recovery == nil || len(recovery.Value) != 1 || recovery.Value[0] != 0x19 {
			t.Fatalf("reference recovery IE got %+v, want 0x19", recovery)
		}
	})

	t.Run("delete_bearer_response_frame_39_matches_reference_ies", func(t *testing.T) {
		got := EncodeDeleteBearerResponseWithMeta(0xc04dad7b, 0x23e, CauseRequestAccepted, []uint8{9}, &DeleteBearerResponseMeta{
			IncludeULI:          true,
			ULIPLMN:             [3]byte{0x13, 0x51, 0x34},
			ULITAC:              1,
			ULIECI:              0x000c8001,
			IncludeULITimestamp: true,
			ULITimestamp:        0xedfe9032,
		})
		want := mustDecodeHex(t, "48640036c04dad7b00023e0002000200100056000d00181351340001135134000c80015d000b004900010009020002001000aa000400edfe9032")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 189 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("delete_bearer_response_frame_43_ebi_10_matches_reference_ies", func(t *testing.T) {
		got := EncodeDeleteBearerResponseWithMeta(0xc04dad7b, 0x23f, CauseRequestAccepted, []uint8{10}, &DeleteBearerResponseMeta{
			IncludeULI:          true,
			ULIPLMN:             [3]byte{0x13, 0x51, 0x34},
			ULITAC:              1,
			ULIECI:              0x000c8001,
			IncludeULITimestamp: true,
			ULITimestamp:        0xedfe9032,
		})
		want := mustDecodeHex(t, "48640036c04dad7b00023f0002000200100056000d00181351340001135134000c80015d000b00490001000a020002001000aa000400edfe9032")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 43 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("delete_bearer_response_frame_57_later_retransmission_matches_reference_ies", func(t *testing.T) {
		got := EncodeDeleteBearerResponseWithMeta(0xc04dad7b, 0x244, CauseRequestAccepted, []uint8{9}, &DeleteBearerResponseMeta{
			IncludeULI:          true,
			ULIPLMN:             [3]byte{0x13, 0x51, 0x34},
			ULITAC:              1,
			ULIECI:              0x000c8001,
			IncludeULITimestamp: true,
			ULITimestamp:        0xedfe9032,
		})
		want := mustDecodeHex(t, "48640036c04dad7b0002440002000200100056000d00181351340001135134000c80015d000b004900010009020002001000aa000400edfe9032")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 57 mismatch\n got  %x\n want %x", got, want)
		}
	})
}

func TestReferencePcapUpdateBearerResponseShapesMatch(t *testing.T) {
	t.Run("accepted_update_bearer_response", func(t *testing.T) {
		got := EncodeUpdateBearerResponseWithMeta(0xc04dad7b, 0x23b, CauseRequestAccepted, []UpdateBearerBearer{{EBI: 9}}, &UpdateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x000c8001,
		})
		want := mustDecodeHex(t, "4862002ec04dad7b00023b000200020010005d000b00490001000902000200100056000d00181351340001135134000c8001")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 29 mismatch\n got  %x\n want %x", got, want)
		}
	})

	t.Run("rejected_update_bearer_response", func(t *testing.T) {
		got := EncodeUpdateBearerResponseWithMeta(0xc04dad7b, 0x23d, CauseUERefuses, []UpdateBearerBearer{{EBI: 9}}, &UpdateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x000c8001,
		})
		want := mustDecodeHex(t, "4862002ec04dad7b00023d000200020058005d000b00490001000902000200580056000d00181351340001135134000c8001")
		if !bytes.Equal(got, want) {
			t.Fatalf("frame 35 mismatch\n got  %x\n want %x", got, want)
		}
	})
}
