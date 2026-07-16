package s1ap

import (
	"fmt"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

type erabReleaseRequestItemForTest struct {
	EBI        uint8
	CauseGroup ies.CauseGroup
	Cause      uint8
}

func TestBuildERABReleaseRequestUsesNASNormalReleaseCause(t *testing.T) {
	raw, err := BuildERABReleaseRequest(1, 2, []ERABReleaseItem{{
		EBI:        6,
		CauseGroup: ies.CauseGroupNAS,
		Cause:      ies.CauseNASNormalRelease,
	}})
	if err != nil {
		t.Fatalf("BuildERABReleaseRequest: %v", err)
	}

	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IEERABToBeReleasedList {
			continue
		}
		items, err := decodeReleaseRequestItemsForTest(ie.Value)
		if err != nil {
			t.Fatalf("decodeReleaseRequestItemsForTest: %v", err)
		}
		if len(items) != 1 {
			t.Fatalf("release items got %d, want 1", len(items))
		}
		if items[0].EBI != 6 {
			t.Fatalf("release EBI got %d, want 6", items[0].EBI)
		}
		if items[0].CauseGroup != ies.CauseGroupNAS || items[0].Cause != ies.CauseNASNormalRelease {
			t.Fatalf("release cause got group=%d cause=%d, want group=%d cause=%d",
				items[0].CauseGroup, items[0].Cause, ies.CauseGroupNAS, ies.CauseNASNormalRelease)
		}
		return
	}
	t.Fatal("E-RABToBeReleasedList IE missing")
}

func decodeReleaseRequestItemsForTest(data []byte) ([]erabReleaseRequestItemForTest, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, err
	}
	r.AlignToByte()
	out := make([]erabReleaseRequestItemForTest, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, err
		}
		if uint16(ieID) != pdu.IEERABItem {
			return nil, fmt.Errorf("unexpected E-RAB item IE ID %d", ieID)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, err
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, err
		}
		item, err := decodeReleaseRequestItemForTest(itemBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func decodeReleaseRequestItemForTest(data []byte) (erabReleaseRequestItemForTest, error) {
	r := aper.NewBitReader(data)
	if _, err := r.ReadBit(); err != nil {
		return erabReleaseRequestItemForTest{}, err
	}
	if _, err := r.ReadBit(); err != nil {
		return erabReleaseRequestItemForTest{}, err
	}
	if _, err := r.ReadBit(); err != nil {
		return erabReleaseRequestItemForTest{}, err
	}
	ebi, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		return erabReleaseRequestItemForTest{}, err
	}
	r.AlignToByte()
	causeBytes, err := r.ReadOctets(r.Remaining() / 8)
	if err != nil {
		return erabReleaseRequestItemForTest{}, err
	}
	group, cause, err := ies.DecodeCause(causeBytes)
	if err != nil {
		return erabReleaseRequestItemForTest{}, err
	}
	return erabReleaseRequestItemForTest{
		EBI:        uint8(ebi),
		CauseGroup: group,
		Cause:      cause,
	}, nil
}
