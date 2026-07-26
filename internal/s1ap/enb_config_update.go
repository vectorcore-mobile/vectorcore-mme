package s1ap

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func (s *Server) handleENBConfigurationUpdate(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "ENBConfigurationUpdate"))

	var enbName string
	var supportedTAs []SupportedTA
	var supportedTAsPresent bool

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEeNBname:
			r := aper.NewBitReader(ie.Value)
			name, err := aper.DecodeVisibleStringExt(r, 1, 150)
			if err != nil {
				log.Warn("s1ap: ENBConfigurationUpdate eNBname decode error", zap.Error(err))
				s.sendENBConfigurationUpdateFailure(remoteAddr, p, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage,
					criticalityDiagnosticItem{Criticality: aper.CriticalityIgnore, IEID: pdu.IEeNBname, TypeOfError: typeOfErrorNotUnderstood},
				)
				return
			}
			enbName = name
		case pdu.IESupportedTAs:
			decoded, err := decodeSupportedTAsStrict(ie.Value)
			if err != nil {
				log.Warn("s1ap: ENBConfigurationUpdate SupportedTAs decode error", zap.Error(err))
				s.sendENBConfigurationUpdateFailure(remoteAddr, p, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage,
					criticalityDiagnosticItem{Criticality: aper.CriticalityReject, IEID: pdu.IESupportedTAs, TypeOfError: typeOfErrorNotUnderstood},
				)
				return
			}
			supportedTAs = decoded
			supportedTAsPresent = true
		}
	}

	var enb *ENBContext
	if existing, ok := s.enbs.Load(remoteAddr); ok {
		enb = existing.(*ENBContext)
	} else {
		enb = &ENBContext{RemoteAddr: remoteAddr}
	}
	enb.mu.Lock()
	if enbName != "" {
		enb.ENBName = enbName
	}
	if supportedTAsPresent {
		enb.SupportedTAs = supportedTAs
		enb.AcceptedTAs = s.acceptedSupportedTAs(supportedTAs)
	}
	globalID := enb.GlobalENBID
	currentName := enb.ENBName
	currentTAs := append([]SupportedTA(nil), enb.SupportedTAs...)
	enb.mu.Unlock()
	s.enbs.Store(remoteAddr, enb)

	tasJSON := encodeSupportedTAsJSON(currentTAs)
	now := time.Now().UTC()
	s.enbTracker.Add(peertracker.Peer{
		Name:         currentName,
		GlobalENBID:  globalID.Serialise(),
		SupportedTAs: tasJSON,
		RemoteAddr:   remoteAddr,
		Transport:    "sctp",
		LastSeen:     now,
	})

	go func() {
		reg := &models.ENBRegistration{
			GlobalENBID:  globalID.Serialise(),
			ENBName:      currentName,
			SupportedTAs: tasJSON,
			RemoteAddr:   remoteAddr,
			LastSeen:     now.Format(time.RFC3339),
			LastModified: now.Format(time.RFC3339),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.UpsertENBRegistration(ctx, reg); err != nil {
			log.Warn("s1ap: ENB configuration update store error", zap.Error(err))
		}
	}()

	resp := pdu.BuildSuccessfulOutcome(pdu.ProcENBConfigurationUpdate, aper.CriticalityReject, nil)
	if err := s.sendToAddr(remoteAddr, resp); err != nil {
		log.Warn("s1ap: ENBConfigurationUpdate acknowledge send failed", zap.Error(err))
		return
	}
	log.Info("s1ap: ENB Configuration Update acknowledged",
		zap.String("enb_name", currentName),
		zap.String("supported_tas", func() string {
			b, err := json.Marshal(currentTAs)
			if err != nil {
				return "[]"
			}
			return string(b)
		}()))
	metrics.S1APMessagesTotal.WithLabelValues("ENBConfigurationUpdate", "inbound", "success").Inc()
}

func (s *Server) sendENBConfigurationUpdateFailure(remoteAddr string, trigger *pdu.PDU, group ies.CauseGroup, cause uint8, items ...criticalityDiagnosticItem) {
	ieList := []pdu.ProtocolIE{
		{
			ID:          pdu.IECause,
			Criticality: aper.CriticalityIgnore,
			Value:       ies.EncodeCause(group, cause),
		},
		{
			ID:          pdu.IETimeToWait,
			Criticality: aper.CriticalityIgnore,
			Value:       ies.EncodeTimeToWait(ies.TimeToWaitV10s),
		},
	}
	if trigger != nil && len(items) > 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IECriticalityDiagnostics,
			Criticality: aper.CriticalityIgnore,
			Value:       encodeCriticalityDiagnostics(trigger.ProcedureCode, trigger.Type, trigger.Criticality, items),
		})
	}
	msg := pdu.BuildUnsuccessfulOutcome(pdu.ProcENBConfigurationUpdate, aper.CriticalityReject, ieList)
	_ = s.sendToAddr(remoteAddr, msg)
	metrics.S1APMessagesTotal.WithLabelValues("ENBConfigurationUpdate", "inbound", "failure").Inc()
}
