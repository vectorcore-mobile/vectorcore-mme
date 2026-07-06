package s1ap

import (
	"go.uber.org/zap"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/metrics"
)

// sendEMMInformation sends an EMM Information message to the UE identified by mmeUEID.
// It is always called as a goroutine after attach or TAU completion.
func (s *Server) sendEMMInformation(mmeUEID uint32, trigger string, log *zap.Logger) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return // UE departed before goroutine ran
	}

	ue.Lock()
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	dlCount := ue.IncrementDLCount()
	ue.Unlock()

	if len(knasInt) == 0 {
		metrics.EMMInformationTotal.WithLabelValues(trigger, "no_security").Inc()
		return
	}

	cfg := s.operCfg
	pdu := emm.EncodeEMMInformation(
		cfg.Name.Full, cfg.Name.ShowFull,
		cfg.Name.Short, cfg.Name.ShowShort,
		cfg.NITZ.Enabled, cfg.NITZ.TimezoneOffsetMinutes, cfg.NITZ.DaylightSaving,
	)
	if pdu == nil {
		return
	}

	var wrapped []byte
	var err error
	if encAlg != security.AlgIDEEA0 {
		wrapped, err = nas.EncodeIntegrityAndCiphered(pdu, intAlg, encAlg, knasInt, knasEnc, dlCount)
	} else {
		wrapped, err = nas.EncodeIntegrityProtected(pdu, intAlg, knasInt, dlCount)
	}
	if err != nil {
		metrics.EMMInformationTotal.WithLabelValues(trigger, "encode_error").Inc()
		log.Warn("nas: EMM Information encode failed",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return
	}

	if err := s.SendDownlinkNAS(mmeUEID, wrapped); err != nil {
		metrics.EMMInformationTotal.WithLabelValues(trigger, "send_error").Inc()
		log.Warn("nas: EMM Information send failed",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return
	}

	metrics.EMMInformationTotal.WithLabelValues(trigger, "sent").Inc()
	log.Info("nas: EMM Information sent", zap.Uint32("mme_ue_id", mmeUEID), zap.String("trigger", trigger))
}
