package s1ap

import (
	"encoding/hex"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
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

	nowUTC := time.Now().UTC()
	tzOffsetMinutes := cfg.NITZ.TimezoneOffsetMinutes
	dst := cfg.NITZ.DaylightSaving
	timezoneSource := "configured-offset"
	var localTime time.Time
	if cfg.NITZ.Enabled && cfg.NITZ.Timezone != "" {
		loc, err := time.LoadLocation(cfg.NITZ.Timezone)
		if err != nil {
			metrics.EMMInformationTotal.WithLabelValues(trigger, "encode_error").Inc()
			log.Warn("nas: EMM Information timezone invalid",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("timezone", cfg.NITZ.Timezone),
				zap.Error(err))
			return
		}
		localTime = nowUTC.In(loc)
		_, offsetSeconds := localTime.Zone()
		tzOffsetMinutes = offsetSeconds / 60
		dst = 0
		if localTime.IsDST() {
			dst = 1
		}
		timezoneSource = cfg.NITZ.Timezone
	} else {
		localTime = nowUTC.Add(time.Duration(tzOffsetMinutes) * time.Minute)
	}
	if cfg.NITZ.Enabled {
		if tzOffsetMinutes%15 != 0 || tzOffsetMinutes < -14*60 || tzOffsetMinutes > 14*60 {
			metrics.EMMInformationTotal.WithLabelValues(trigger, "encode_error").Inc()
			log.Warn("nas: EMM Information not sent, invalid NITZ timezone offset",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("timezone_source", timezoneSource),
				zap.Int("timezone_offset_minutes", tzOffsetMinutes))
			return
		}
		if dst > 2 {
			metrics.EMMInformationTotal.WithLabelValues(trigger, "encode_error").Inc()
			log.Warn("nas: EMM Information not sent, invalid NITZ daylight saving value",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("timezone_source", timezoneSource),
				zap.Uint8("daylight_saving", dst))
			return
		}
	}

	pdu := emm.EncodeEMMInformationWithOptions(emm.EMMInformationOptions{
		FullName:             cfg.Name.Full,
		ShowFullName:         cfg.Name.ShowFull,
		ShortName:            cfg.Name.Short,
		ShowShortName:        cfg.Name.ShowShort,
		NameEncoding:         cfg.Name.Encoding,
		AddCountryInitials:   cfg.Name.AddCountryInitials,
		IncludeLocalTimeZone: cfg.NITZ.Enabled && cfg.NITZ.IncludeLocalTimeZone,
		IncludeUniversalTime: cfg.NITZ.Enabled && cfg.NITZ.IncludeUniversalTimeAndLocalTimeZone,
		IncludeDST:           cfg.NITZ.Enabled && cfg.NITZ.IncludeDaylightSavingTime,
		UniversalTime:        nowUTC,
		TimezoneOffsetMin:    tzOffsetMinutes,
		DaylightSaving:       dst,
	})
	if pdu == nil {
		log.Debug("nas: EMM Information has no configured IEs",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("trigger", trigger),
			zap.Bool("full_network_name_configured", cfg.Name.ShowFull && cfg.Name.Full != ""),
			zap.Bool("short_network_name_configured", cfg.Name.ShowShort && cfg.Name.Short != ""),
			zap.Bool("nitz_enabled", cfg.NITZ.Enabled),
			zap.Bool("include_local_time_zone", cfg.NITZ.IncludeLocalTimeZone),
			zap.Bool("include_universal_time_and_local_time_zone", cfg.NITZ.IncludeUniversalTimeAndLocalTimeZone),
			zap.Bool("include_daylight_saving_time", cfg.NITZ.IncludeDaylightSavingTime))
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
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()

	wrapped, err := nas.EncodeIntegrityAndCiphered(pdu, intAlg, encAlg, knasInt, knasEnc, dlCount)
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
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.LastDownlinkNASMessage = "EMM Information"
	ue.Unlock()

	metrics.EMMInformationTotal.WithLabelValues(trigger, "sent").Inc()
	log.Info("nas: EMM Information sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.String("imsi", imsi),
		zap.String("trigger", trigger),
		zap.Bool("full_network_name_configured", cfg.Name.ShowFull && cfg.Name.Full != ""),
		zap.Bool("short_network_name_configured", cfg.Name.ShowShort && cfg.Name.Short != ""),
		zap.String("encoding", cfg.Name.Encoding),
		zap.Bool("include_local_time_zone", cfg.NITZ.Enabled && cfg.NITZ.IncludeLocalTimeZone),
		zap.Bool("include_universal_time_and_local_time_zone", cfg.NITZ.Enabled && cfg.NITZ.IncludeUniversalTimeAndLocalTimeZone),
		zap.Bool("include_daylight_saving_time", cfg.NITZ.Enabled && cfg.NITZ.IncludeDaylightSavingTime),
		zap.String("timezone_source", timezoneSource),
		zap.String("source_utc_time", nowUTC.Format(time.RFC3339)),
		zap.String("source_local_time", localTime.Format(time.RFC3339)),
		zap.Int("timezone_offset_minutes", tzOffsetMinutes),
		zap.Uint8("daylight_saving", dst),
		zap.Uint8("inner_protocol_discriminator", pdu[0]&0x0f),
		zap.Uint8("inner_message_type", pdu[1]),
		zap.Uint8("protected_security_header_type", wrapped[0]>>4),
		zap.Uint32("nas_downlink_count", dlCount),
		zap.Uint8("sequence_number", uint8(dlCount&0xff)),
		zap.String("plain_nas_hex", hex.EncodeToString(pdu)))
}
