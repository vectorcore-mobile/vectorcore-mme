package s1ap

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

func (s *Server) persistUERecoverySnapshot(ue *uecontext.Context, recoveryState, sessionState string) {
	if !s.recoveryPersistent || s.store == nil || ue == nil {
		return
	}
	ueRec, sessRec := s.buildRecoveryRecordsLocked(ue, recoveryState, sessionState)
	if ueRec.IMSI == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.UpsertUERecoveryRecord(ctx, ueRec); err != nil {
			s.log.Warn("s1ap: failed to persist UE recovery record",
				zap.String("imsi", ueRec.IMSI), zap.Error(err))
		}
		if sessRec != nil {
			if err := s.store.UpsertSessionRecoveryRecord(ctx, sessRec); err != nil {
				s.log.Warn("s1ap: failed to persist session recovery record",
					zap.String("imsi", sessRec.IMSI), zap.String("apn", sessRec.APN), zap.Error(err))
			}
		}
	}()
}

func (s *Server) buildRecoveryRecordsLocked(ue *uecontext.Context, recoveryState, sessionState string) (*models.UERecoveryRecord, *models.SessionRecoveryRecord) {
	now := time.Now().UTC()
	ue.Lock()
	defer ue.Unlock()

	rec := &models.UERecoveryRecord{
		IMSI:                   ue.IMSI,
		IMEISV:                 ue.IMEI,
		MSISDN:                 ue.MSISDN,
		CallID:                 ue.MMEUES1APID,
		ContextID:              ue.MMEUES1APID,
		MMEInstance:            s.nfCfg.OriginHost,
		RestartEpoch:           s.restartEpoch,
		LastEMMState:           ue.EMMState.String(),
		LastECMState:           ue.ECMState.String(),
		RecoveryState:          recoveryState,
		NASIntegrityAlg:        ue.IntAlg,
		NASCipheringAlg:        ue.EncAlg,
		UplinkNASCount:         uint32(ue.ULNASCount),
		DownlinkNASCount:       uint32(ue.DLNASCount),
		KASME:                  append([]byte(nil), ue.KASME...),
		ENBID:                  ue.ENBGlobalID,
		LastSeenAt:             &now,
		UpdatedAt:              now,
		ReachabilityState:      ue.ReachabilityState,
		LastReachabilityReason: ue.LastReachabilityReason,
		TerminalCleanupActive:  ue.ImplicitDetachCleanupStarted,
		ReachabilityGeneration: ue.MobileReachableGeneration,
	}
	if !ue.MobileReachableDeadline.IsZero() {
		v := ue.MobileReachableDeadline
		rec.MobileReachableDeadline = &v
	}
	if !ue.ImplicitDetachDeadline.IsZero() {
		v := ue.ImplicitDetachDeadline
		rec.ImplicitDetachDeadline = &v
	}
	if !ue.ImplicitDetachCleanupDeadline.IsZero() {
		v := ue.ImplicitDetachCleanupDeadline
		rec.TerminalCleanupDeadline = &v
	}
	if !ue.LastReachabilityRefresh.IsZero() {
		v := ue.LastReachabilityRefresh
		rec.LastReachabilityRefresh = &v
	}
	if recoveryState == models.RecoveryStateActiveSnapshot || recoveryState == models.RecoveryStateRecovered {
		rec.AttachedAt = &now
	}
	if recoveryState == models.RecoveryStateStaleAfterRestart {
		rec.StaleAt = &now
	}
	if ue.GUTI != nil {
		rec.CurrentGUTI = uecontext.SerialiseGUTI(ue.GUTI)
		rec.GUTIMMEGID = ue.GUTI.MMEGI
		rec.GUTIMMECode = ue.GUTI.MMEC
		rec.GUTIMTMSI = ue.GUTI.MTMSI
		rec.GUTIMCC, rec.GUTIMNC = decodePLMNFields(ue.GUTI.PLMN)
	}
	if ue.TAI != nil {
		rec.TAC = ue.TAI.TAC
		rec.TAIMCC, rec.TAIMNC = decodePLMNFields(ue.TAI.PLMN)
	}
	if ue.ECGIECI != 0 {
		rec.ECGI = fmt.Sprintf("%02X%02X%02X%07X", ue.ECGIPLMN[0], ue.ECGIPLMN[1], ue.ECGIPLMN[2], ue.ECGIECI)
	}

	var sess *models.SessionRecoveryRecord
	if ue.APN != "" || ue.DefaultEBI != 0 || ue.SGWC_TEID != 0 || ue.SGWAddress != "" {
		sess = &models.SessionRecoveryRecord{
			IMSI:          ue.IMSI,
			CallID:        ue.MMEUES1APID,
			ContextID:     ue.MMEUES1APID,
			MMEInstance:   s.nfCfg.OriginHost,
			RestartEpoch:  s.restartEpoch,
			APN:           ue.APN,
			PDNType:       "IPv4",
			DefaultEBI:    ue.DefaultEBI,
			LinkedEBI:     ue.DefaultEBI,
			MMES11TEID:    ue.LocalS11TEID,
			SGWS11TEID:    ue.SGWC_TEID,
			SGWS11IP:      ipString(ue.SGWC_IP),
			PGWIP:         ipString(s.pgwIP),
			SessionState:  sessionState,
			RecoveryState: recoveryState,
			UpdatedAt:     now,
		}
		if ue.UEIPv4 != nil {
			sess.UEIPv4 = ue.UEIPv4.String()
		}
		if sess.SGWS11IP == "" {
			sess.SGWS11IP = hostOnly(ue.SGWAddress)
		}
		sess.BearerSummaryJSON = fmt.Sprintf(`{"default_ebi":%d,"sgw_s1u_teid":%d,"sgw_s1u_ip":%q,"enb_s1u_teid":%d,"enb_s1u_ip":%q}`,
			ue.DefaultEBI, ue.SGWU_TEID, ipString(ue.SGWU_IP), ue.ENBU_TEID, ipString(ue.ENBU_IP))
		if recoveryState == models.RecoveryStateStaleAfterRestart {
			sess.StaleAt = &now
		}
	}
	return rec, sess
}

func decodePLMNFields(plmn [3]byte) (string, string) {
	mcc, mnc, err := ies.DecodePLMN(plmn[:])
	if err != nil {
		return hex.EncodeToString(plmn[:]), ""
	}
	return mcc, mnc
}

func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func hostOnly(addr string) string {
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
