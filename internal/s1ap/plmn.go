package s1ap

import (
	"fmt"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func encodeNASPLMN(mcc, mnc string) ([3]byte, error) {
	var out [3]byte
	plmn, err := security.EncodePLMN(mcc, mnc)
	if err != nil {
		return out, err
	}
	if len(plmn) != 3 {
		return out, fmt.Errorf("unexpected NAS PLMN length %d", len(plmn))
	}
	copy(out[:], plmn)
	return out, nil
}

func emmTAIFromS1AP(t *ies.TAI) *emm.TAI {
	if t == nil {
		return nil
	}
	emmTAI := &emm.TAI{TAC: t.TAC}
	plmn, err := encodeNASPLMN(t.MCC, t.MNC)
	if err == nil {
		emmTAI.PLMN = plmn
	}
	return emmTAI
}
