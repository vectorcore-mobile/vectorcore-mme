package s6a

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"github.com/vectorcore/mme/internal/diameter/sgd"
)

func TestMTTFRResultCacheOnlyMatchesExactDiameterTransaction(t *testing.T) {
	h := &Handlers{}
	request := func(sessionID string, hop, end uint32) *diam.Message {
		m := diam.NewRequest(sgd.CommandMTForwardShortMessage, sgd.ApplicationID, dict.Default)
		m.Header.HopByHopID = hop
		m.Header.EndToEndID = end
		_ = sessionID
		return m
	}
	req := &sgd.MTRequest{SessionID: "smsc;1", IMSI: "001010123456789", SMRPUI: []byte{4, 1, 2, 3}}
	m := request(req.SessionID, 1, 2)
	key := mtTFRCacheKey(m, req)
	h.storeMTResult(key, diam.Success, []byte{0, 0})
	result, rpui, ok := h.lookupMTResult(key)
	if !ok || result != diam.Success || !bytes.Equal(rpui, []byte{0, 0}) {
		t.Fatalf("cached TFA = %d %x %v", result, rpui, ok)
	}
	newTransaction := *req
	newTransaction.SessionID = "smsc;2"
	if _, _, ok := h.lookupMTResult(mtTFRCacheKey(request(newTransaction.SessionID, 3, 4), &newTransaction)); ok {
		t.Fatal("new Diameter transaction incorrectly deduplicated")
	}
}
