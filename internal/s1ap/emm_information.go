package s1ap

import (
	"encoding/hex"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

// sendEMMInformation sends an optional EMM Information message to the UE identified by mmeUEID.
// It is called after attach or TAU completion, after NAS security is active.
func (s *Server) sendEMMInformation(mmeUEID uint32, trigger string, log *zap.Logger) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return // UE departed before goroutine ran
	}

	cfg := s.operCfg
	if !cfg.EMMInformation.Enabled {
		log.Debug("nas: EMM Information disabled", zap.Uint32("mme_ue_id", mmeUEID), zap.String("trigger", trigger))
		return
	}

	pdu := emm.EncodeEMMInformation(
		cfg.Name.Full, cfg.Name.ShowFull,
		cfg.Name.Short, cfg.Name.ShowShort,
		cfg.Name.Encoding,
		cfg.Name.AddCountryInitials,
		cfg.NITZ.Enabled, cfg.NITZ.TimezoneOffsetMinutes, cfg.NITZ.DaylightSaving,
	)
	if pdu == nil {
		log.Debug("nas: EMM Information has no configured IEs",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("trigger", trigger),
			zap.Bool("full_network_name_configured", cfg.Name.ShowFull && cfg.Name.Full != ""),
			zap.Bool("short_network_name_configured", cfg.Name.ShowShort && cfg.Name.Short != ""),
			zap.Bool("nitz_enabled", cfg.NITZ.Enabled))
		return
	}

	ue.Lock()
	imsi := ue.IMSI
	enbUEID := ue.ENBS1APID
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	if len(knasInt) == 0 {
		ue.Unlock()
		metrics.EMMInformationTotal.WithLabelValues(trigger, "no_security").Inc()
		log.Warn("nas: EMM Information not sent, NAS security unavailable",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("trigger", trigger))
		return
	}
	dlCount := ue.IncrementDLCount()
	ue.Unlock()

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
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Error(err))
		return
	}

	if err := s.SendDownlinkNAS(mmeUEID, wrapped); err != nil {
		metrics.EMMInformationTotal.WithLabelValues(trigger, "send_error").Inc()
		log.Warn("nas: EMM Information send failed",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Error(err))
		return
	}

	metrics.EMMInformationTotal.WithLabelValues(trigger, "sent").Inc()
	log.Info("nas: EMM Information sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.String("imsi", imsi),
		zap.String("trigger", trigger),
		zap.Bool("full_network_name_configured", cfg.Name.ShowFull && cfg.Name.Full != ""),
		zap.Bool("short_network_name_configured", cfg.Name.ShowShort && cfg.Name.Short != ""),
		zap.String("encoding", cfg.Name.Encoding),
		zap.Uint32("nas_downlink_count", dlCount),
		zap.String("plain_nas_hex", hex.EncodeToString(pdu)))
}
