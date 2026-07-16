package gtpv2

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func mustDecodeFuzzHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func addGTPv2Seeds(f *testing.F) {
	f.Add(Encode(&Message{
		Type:   MsgCreateSessionRequest,
		TEID:   0x11223344,
		SeqNum: 0x010203,
		IEs: []IE{
			EncodeEBI(6, 0),
			EncodeFTEID(IFTypeS11MME, 0xaabbccdd, net.ParseIP("10.0.0.1").To4(), 0),
		},
	}))
	f.Add(EncodeNoTEID(&Message{
		Type:   MsgEchoRequest,
		SeqNum: 0x010204,
		IEs:    []IE{{Type: IETypeRecovery, Instance: 0, Value: []byte{1}}},
	}))
	primary := Encode(&Message{
		Type:   MsgCreateBearerResponse,
		TEID:   0x55667788,
		SeqNum: 0x020304,
		IEs:    []IE{EncodeCause(CauseRequestAccepted)},
	})
	piggyback := Encode(&Message{
		Type:   MsgModifyBearerRequest,
		TEID:   0x99aabbcc,
		SeqNum: 0x020305,
		IEs: []IE{
			EncodeIndicationCRSI(),
			EncodeEBI(6, 0),
		},
	})
	joined, err := EncodePiggybacked(primary, piggyback)
	if err != nil {
		panic(err)
	}
	f.Add(joined)
	f.Add(mustDecodeFuzzHex("5821009d803de008129a0800020002001000570009008bc04dad7b0a5afa3b5700090187801080060a5afa5c4f000500010a96039c7f000100004800080000000f0a000005fa4e002e0080000d040a5afa0a000d040a5afa0c000c040a5afa328021100301001081060a5afa0a83060a5afa0c00100205785d0025004900010006020002001000570009008169eb85ee0a5afa3b570009028580a580060a5afa5c485f00ad803de0080002390049000100065d004c00490001000054000f002130300b100a96039cffffffff301157000900812df38f080a5afa3b570009018580a5a0060a5afa5c50001600100200000000800000000080000000008000000000805d004c00490001000054000f002130350b100a96039cffffffff3011570009008160f1b7390a5afa3b570009018580a5c0060a5afa5c5000160008010000000080000000008000000000800000000080"))
}

func FuzzGTPv2Decode(f *testing.F) {
	addGTPv2Seeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Decode(data)
		if err != nil {
			return
		}

		var wire []byte
		if len(data) > 0 && (data[0]>>3)&0x01 == 0 {
			wire = EncodeNoTEID(msg)
		} else {
			wire = Encode(msg)
		}
		rt, err := Decode(wire)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if rt.Type != msg.Type || rt.TEID != msg.TEID || rt.SeqNum != msg.SeqNum {
			t.Fatalf("header mismatch after round-trip: got %+v want %+v", rt, msg)
		}
		if !bytes.Equal(EncodeIEs(rt.IEs), EncodeIEs(msg.IEs)) {
			t.Fatalf("IE mismatch after round-trip")
		}
	})
}

func FuzzGTPv2DecodeAll(f *testing.F) {
	addGTPv2Seeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		msgs, err := DecodeAll(data)
		if err != nil {
			return
		}
		if len(msgs) == 0 {
			t.Fatal("DecodeAll succeeded with zero messages")
		}
		for i, msg := range msgs {
			if msg == nil {
				t.Fatalf("message %d is nil", i)
			}
			wire := Encode(msg)
			if i == 0 && len(data) > 0 && (data[0]>>3)&0x01 == 0 {
				wire = EncodeNoTEID(msg)
			}
			if _, err := Decode(wire); err != nil {
				t.Fatalf("message %d does not re-decode: %v", i, err)
			}
		}
	})
}

func FuzzBearerResponseShapes(f *testing.F) {
	f.Add(uint8(CauseRequestAccepted), uint8(9), uint32(0x23b), uint32(0xc04dad7b), true, uint32(0xedfe9032))
	f.Add(uint8(CauseUERefuses), uint8(9), uint32(0x23d), uint32(0xc04dad7b), true, uint32(0xedfe9032))
	f.Add(uint8(CauseRequestAccepted), uint8(10), uint32(0x23f), uint32(0xc04dad7b), true, uint32(0xedfe9032))
	f.Fuzz(func(t *testing.T, cause uint8, ebi uint8, seq uint32, teid uint32, includeULI bool, uliTimestamp uint32) {
		ebi = 5 + (ebi % 11)
		seq &= 0x00ffffff
		updateMeta := &UpdateBearerResponseMeta{}
		deleteMeta := &DeleteBearerResponseMeta{}
		if includeULI {
			updateMeta.IncludeULI = true
			updateMeta.ULIPLMN = [3]byte{0x13, 0x51, 0x34}
			updateMeta.ULITAC = 1
			updateMeta.ULIECI = 0x000c8001
			deleteMeta.IncludeULI = true
			deleteMeta.ULIPLMN = updateMeta.ULIPLMN
			deleteMeta.ULITAC = updateMeta.ULITAC
			deleteMeta.ULIECI = updateMeta.ULIECI
			deleteMeta.IncludeULITimestamp = true
			deleteMeta.ULITimestamp = uliTimestamp
		}

		updateWire := EncodeUpdateBearerResponseWithMeta(teid, seq, cause, []UpdateBearerBearer{{EBI: ebi}}, updateMeta)
		updateMsg, err := Decode(updateWire)
		if err != nil {
			t.Fatalf("decode update bearer response: %v", err)
		}
		assertUpdateBearerResponseShape(t, updateMsg, cause, ebi, includeULI)

		deleteWire := EncodeDeleteBearerResponseWithMeta(teid, seq, cause, []uint8{ebi}, deleteMeta)
		deleteMsg, err := Decode(deleteWire)
		if err != nil {
			t.Fatalf("decode delete bearer response: %v", err)
		}
		assertDeleteBearerResponseShape(t, deleteMsg, cause, ebi, includeULI)
	})
}

func assertUpdateBearerResponseShape(t *testing.T, msg *Message, cause uint8, ebi uint8, includeULI bool) {
	t.Helper()
	if msg.Type != MsgUpdateBearerResponse {
		t.Fatalf("unexpected update response type %d", msg.Type)
	}
	wantTypes := []uint8{IETypeCause, IETypeBearerContext}
	if includeULI {
		wantTypes = append(wantTypes, IETypeULI)
	}
	if got := topLevelIETypes(msg.IEs); !bytes.Equal(got, wantTypes) {
		t.Fatalf("update response top-level IE order got %v want %v", got, wantTypes)
	}
	if gotCause, err := DecodeCause(FindIE(msg.IEs, IETypeCause, 0)); err != nil || gotCause != cause {
		t.Fatalf("update response cause got %d err=%v want %d", gotCause, err, cause)
	}
	bearer := FindIE(msg.IEs, IETypeBearerContext, 0)
	if bearer == nil {
		t.Fatal("update response missing bearer context")
	}
	children, err := FindGroupedIEs(bearer)
	if err != nil {
		t.Fatalf("decode update bearer response bearer context: %v", err)
	}
	if got := topLevelIETypes(children); !bytes.Equal(got, []uint8{IETypeEBI, IETypeCause}) {
		t.Fatalf("update response bearer IE order got %v want [73 2]", got)
	}
	if gotEBI, err := DecodeEBI(FindIE(children, IETypeEBI, 0)); err != nil || gotEBI != ebi {
		t.Fatalf("update response bearer EBI got %d err=%v want %d", gotEBI, err, ebi)
	}
	if gotCause, err := DecodeCause(FindIE(children, IETypeCause, 0)); err != nil || gotCause != cause {
		t.Fatalf("update response bearer cause got %d err=%v want %d", gotCause, err, cause)
	}
}

func assertDeleteBearerResponseShape(t *testing.T, msg *Message, cause uint8, ebi uint8, includeULI bool) {
	t.Helper()
	if msg.Type != MsgDeleteBearerResponse {
		t.Fatalf("unexpected delete response type %d", msg.Type)
	}
	wantTypes := []uint8{IETypeCause}
	if includeULI {
		wantTypes = append(wantTypes, IETypeULI)
	}
	wantTypes = append(wantTypes, IETypeBearerContext)
	if includeULI {
		wantTypes = append(wantTypes, IETypeULITimestamp)
	}
	if got := topLevelIETypes(msg.IEs); !bytes.Equal(got, wantTypes) {
		t.Fatalf("delete response top-level IE order got %v want %v", got, wantTypes)
	}
	if gotCause, err := DecodeCause(FindIE(msg.IEs, IETypeCause, 0)); err != nil || gotCause != cause {
		t.Fatalf("delete response cause got %d err=%v want %d", gotCause, err, cause)
	}
	bearer := FindIE(msg.IEs, IETypeBearerContext, 0)
	if bearer == nil {
		t.Fatal("delete response missing bearer context")
	}
	children, err := FindGroupedIEs(bearer)
	if err != nil {
		t.Fatalf("decode delete bearer response bearer context: %v", err)
	}
	if got := topLevelIETypes(children); !bytes.Equal(got, []uint8{IETypeEBI, IETypeCause}) {
		t.Fatalf("delete response bearer IE order got %v want [73 2]", got)
	}
	if gotEBI, err := DecodeEBI(FindIE(children, IETypeEBI, 0)); err != nil || gotEBI != ebi {
		t.Fatalf("delete response bearer EBI got %d err=%v want %d", gotEBI, err, ebi)
	}
	if gotCause, err := DecodeCause(FindIE(children, IETypeCause, 0)); err != nil || gotCause != cause {
		t.Fatalf("delete response bearer cause got %d err=%v want %d", gotCause, err, cause)
	}
}
