// Package vlr owns the MME side of the SGs interface (TS 29.118): one
// outbound SCTP association per configured VLR, the node-level Reset
// procedure (§5.8), and TAI-to-VLR selection. The wire codec lives in
// internal/sgsap; per-UE SGs association state (SGs-NULL /
// LA-UPDATE-REQUESTED / SGs-ASSOCIATED, TS 29.118 §4.3.3) lives on
// uecontext.Context, not here. This mirrors the split already used for SMS
// over SGd: internal/diameter/sgd owns the wire codec, internal/sms owns
// UE-facing state, and internal/s1ap wires the two together.
package vlr

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/sgsap"
)

// Handler receives every SGsAP message the VLR sends to the MME. Method
// implementations are expected on the s1ap server, mirroring how
// s1ap.Server implements sgd's MT-SMS delivery callback.
type Handler interface {
	HandleLocationUpdateAccept(vlrName string, a *sgsap.LocationUpdateAccept)
	HandleLocationUpdateReject(vlrName string, r *sgsap.LocationUpdateReject)
	HandlePagingRequest(vlrName string, r *sgsap.PagingRequest)
	HandleDownlinkUnitdata(vlrName string, d *sgsap.DownlinkUnitdata)
	HandleReleaseRequest(vlrName string, imsi string, cause *sgsap.Cause)
	HandleEPSDetachAck(vlrName string, imsi string)
	HandleIMSIDetachAck(vlrName string, imsi string)
	HandleAlertRequest(vlrName string, imsi string)
	HandleMMInformationRequest(vlrName string, r *sgsap.MMInformationRequest)
	HandleServiceAbortRequest(vlrName string, imsi string)
	HandleStatus(vlrName string, s *sgsap.Status)
	// OnVLRReset fires when the VLR signals it restarted (an SGsAP-RESET-
	// INDICATION was received): every UE association with this VLR name
	// must move back to SGs-NULL, since the VLR has forgotten them (TS
	// 29.118 §4.2.2 note, §5.8.3).
	OnVLRReset(vlrName string)
	// OnVLRAssociationUp fires once the node-level Reset procedure with a
	// VLR completes in either direction (our Reset Indication was
	// acknowledged, or we acknowledged the VLR's), meaning the association
	// is confirmed usable for UE-level procedures such as Location Update.
	OnVLRAssociationUp(vlrName string)
}

// transport is the seam between Manager's FSM/dispatch logic and the actual
// SCTP association, satisfied by *sctpTransport. Tests substitute a fake to
// exercise the Reset procedure and message dispatch without real sockets.
type transport interface {
	setHandlers(onMessage func([]byte), onConnect func(), onLoss func(error))
	available() bool
	send(ctx context.Context, b []byte) error
	start(ctx context.Context)
	close() error
}

type association struct {
	name      string
	address   string
	port      int
	transport transport

	mu          sync.Mutex
	vlrReliable bool // TS 29.118 §4.3.2 "VLR-Reliable"
	confirmed   bool // node-level Reset procedure has completed at least once
}

// Manager owns every configured VLR association and the TAI-to-VLR lookup
// derived from config.SGsConfig.TAILAIMap.
type Manager struct {
	log     *zap.Logger
	mmeName string
	handler Handler

	associations map[string]*association // by VLR name
	taiIndex     map[taiKey]config.SGsTAILAIMapItem

	requestTimeout time.Duration
}

type taiKey struct {
	mcc, mnc string
	tac      uint16
}

// New builds a Manager from a validated, enabled SGsConfig. mmeName is the
// FQDN this MME advertises in Location Update Request / Reset Indication /
// detach indications (TS 29.118 MME name IE, §9.4.13).
func New(cfg config.SGsConfig, mmeName string, handler Handler, log *zap.Logger) *Manager {
	if log == nil {
		log = zap.NewNop()
	}
	m := &Manager{
		log:            log,
		mmeName:        mmeName,
		handler:        handler,
		associations:   make(map[string]*association, len(cfg.VLR)),
		taiIndex:       make(map[taiKey]config.SGsTAILAIMapItem, len(cfg.TAILAIMap)),
		requestTimeout: cfg.RequestTimeout,
	}
	for _, v := range cfg.VLR {
		m.associations[v.Name] = &association{
			name:      v.Name,
			address:   v.Address,
			port:      v.Port,
			transport: newSCTPTransport(v.Address, v.Port, cfg.ReconnectInterval, log.With(zap.String("vlr_name", v.Name))),
		}
	}
	for _, item := range cfg.TAILAIMap {
		m.taiIndex[taiKey{mcc: item.TAI.MCC, mnc: item.TAI.MNC, tac: item.TAI.TAC}] = item
	}
	return m
}

// Start dials every configured VLR and begins reconnect loops; it returns
// immediately, the same non-blocking contract as sls.SCTPTransport.Start.
func (m *Manager) Start(ctx context.Context) {
	for name, a := range m.associations {
		name, a := name, a
		a.transport.setHandlers(
			func(data []byte) { m.onMessage(name, data) },
			func() { m.onConnect(name) },
			func(err error) { m.onLoss(name, err) },
		)
		a.transport.start(ctx)
	}
}

func (m *Manager) Close() {
	for _, a := range m.associations {
		_ = a.transport.close()
	}
}

// LookupVLR returns the LAI/VLR-name mapping for a served TAI, per the
// TAI-to-LAI map from configuration.
func (m *Manager) LookupVLR(mcc, mnc string, tac uint16) (config.SGsTAILAIMapItem, bool) {
	item, ok := m.taiIndex[taiKey{mcc: mcc, mnc: mnc, tac: tac}]
	return item, ok
}

// Available reports whether the named VLR's SCTP association is up and its
// node-level Reset procedure has completed.
func (m *Manager) Available(vlrName string) bool {
	a, ok := m.associations[vlrName]
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.transport.available() && a.confirmed
}

// VLRStatus is a point-in-time snapshot of one configured VLR association,
// for OAM/API reporting.
type VLRStatus struct {
	Name      string
	Address   string
	Port      int
	Available bool // transport up and node-level Reset procedure completed
}

// Snapshot returns the current status of every configured VLR, in no
// particular order (m.associations is a map).
func (m *Manager) Snapshot() []VLRStatus {
	out := make([]VLRStatus, 0, len(m.associations))
	for _, a := range m.associations {
		a.mu.Lock()
		available := a.transport.available() && a.confirmed
		a.mu.Unlock()
		out = append(out, VLRStatus{Name: a.name, Address: a.address, Port: a.port, Available: available})
	}
	return out
}

func (m *Manager) association(vlrName string) (*association, error) {
	a, ok := m.associations[vlrName]
	if !ok {
		return nil, fmt.Errorf("vlr: unknown VLR %q", vlrName)
	}
	return a, nil
}

func (m *Manager) send(vlrName string, data []byte) error {
	a, err := m.association(vlrName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.requestTimeout)
	defer cancel()
	return a.transport.send(ctx, data)
}

// onConnect runs once a fresh SCTP association to a VLR is established (TS
// 29.118 §6.3: "The MME shall establish the SCTP association"). It starts
// the node-level Reset procedure by sending our own Reset Indication;
// per-UE procedures wait for OnVLRAssociationUp before using this VLR.
func (m *Manager) onConnect(vlrName string) {
	a, err := m.association(vlrName)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.confirmed = false
	a.mu.Unlock()
	msg := sgsap.BuildResetIndication(sgsap.Reset{MMEName: m.mmeName})
	if err := m.send(vlrName, msg); err != nil {
		m.log.Warn("vlr: failed to send RESET-INDICATION after association established", zap.String("vlr_name", vlrName), zap.Error(err))
	}
}

// onLoss runs when the SCTP association to a VLR drops. Every UE
// association with this VLR is no longer confirmed usable; the transport
// reconnect loop will retry and onConnect will re-run the Reset procedure.
func (m *Manager) onLoss(vlrName string, err error) {
	a, aerr := m.association(vlrName)
	if aerr != nil {
		return
	}
	a.mu.Lock()
	a.confirmed = false
	a.vlrReliable = false
	a.mu.Unlock()
	m.log.Warn("vlr: SCTP association lost", zap.String("vlr_name", vlrName), zap.Error(err))
}

func (m *Manager) onMessage(vlrName string, data []byte) {
	msgType, err := sgsap.MessageType(data)
	if err != nil {
		m.log.Warn("vlr: dropped empty SGsAP message", zap.String("vlr_name", vlrName))
		return
	}
	switch msgType {
	case sgsap.MsgResetIndication:
		m.handleResetIndication(vlrName, data)
	case sgsap.MsgResetAck:
		m.handleResetAck(vlrName, data)
	case sgsap.MsgLocationUpdateAccept:
		a, err := sgsap.DecodeLocationUpdateAccept(data)
		if err != nil {
			m.log.Warn("vlr: invalid LOCATION-UPDATE-ACCEPT", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleLocationUpdateAccept(vlrName, a)
		}
	case sgsap.MsgLocationUpdateReject:
		r, err := sgsap.DecodeLocationUpdateReject(data)
		if err != nil {
			m.log.Warn("vlr: invalid LOCATION-UPDATE-REJECT", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleLocationUpdateReject(vlrName, r)
		}
	case sgsap.MsgPagingRequest:
		r, err := sgsap.DecodePagingRequest(data)
		if err != nil {
			m.log.Warn("vlr: invalid PAGING-REQUEST", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandlePagingRequest(vlrName, r)
		}
	case sgsap.MsgDownlinkUnitdata:
		d, err := sgsap.DecodeDownlinkUnitdata(data)
		if err != nil {
			m.log.Warn("vlr: invalid DOWNLINK-UNITDATA", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleDownlinkUnitdata(vlrName, d)
		}
	case sgsap.MsgReleaseRequest:
		imsi, cause, err := sgsap.DecodeReleaseRequest(data)
		if err != nil {
			m.log.Warn("vlr: invalid RELEASE-REQUEST", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleReleaseRequest(vlrName, imsi, cause)
		}
	case sgsap.MsgEPSDetachAck:
		imsi, err := sgsap.DecodeEPSDetachAck(data)
		if err != nil {
			m.log.Warn("vlr: invalid EPS-DETACH-ACK", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleEPSDetachAck(vlrName, imsi)
		}
	case sgsap.MsgIMSIDetachAck:
		imsi, err := sgsap.DecodeIMSIDetachAck(data)
		if err != nil {
			m.log.Warn("vlr: invalid IMSI-DETACH-ACK", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleIMSIDetachAck(vlrName, imsi)
		}
	case sgsap.MsgAlertRequest:
		imsi, err := sgsap.DecodeAlertRequest(data)
		if err != nil {
			m.log.Warn("vlr: invalid ALERT-REQUEST", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleAlertRequest(vlrName, imsi)
		}
	case sgsap.MsgMMInformationRequest:
		r, err := sgsap.DecodeMMInformationRequest(data)
		if err != nil {
			m.log.Warn("vlr: invalid MM-INFORMATION-REQUEST", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleMMInformationRequest(vlrName, r)
		}
	case sgsap.MsgServiceAbortRequest:
		imsi, err := sgsap.DecodeServiceAbortRequest(data)
		if err != nil {
			m.log.Warn("vlr: invalid SERVICE-ABORT-REQUEST", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleServiceAbortRequest(vlrName, imsi)
		}
	case sgsap.MsgStatus:
		s, err := sgsap.DecodeStatus(data)
		if err != nil {
			m.log.Warn("vlr: invalid STATUS", zap.String("vlr_name", vlrName), zap.Error(err))
			return
		}
		if m.handler != nil {
			m.handler.HandleStatus(vlrName, s)
		}
	default:
		m.log.Info("vlr: unhandled SGsAP message type", zap.String("vlr_name", vlrName), zap.Uint8("message_type", msgType))
	}
}

// handleResetIndication implements the VLR-initiated Reset procedure (TS
// 29.118 §5.8): acknowledge with our own identity, then tell the handler
// every UE association with this VLR must revert to SGs-NULL.
func (m *Manager) handleResetIndication(vlrName string, data []byte) {
	if _, err := sgsap.DecodeResetIndication(data); err != nil {
		m.log.Warn("vlr: invalid RESET-INDICATION", zap.String("vlr_name", vlrName), zap.Error(err))
		return
	}
	a, err := m.association(vlrName)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.vlrReliable = false
	a.confirmed = true
	a.mu.Unlock()
	ack := sgsap.BuildResetAck(sgsap.Reset{MMEName: m.mmeName})
	if err := m.send(vlrName, ack); err != nil {
		m.log.Warn("vlr: failed to send RESET-ACK", zap.String("vlr_name", vlrName), zap.Error(err))
	}
	if m.handler != nil {
		m.handler.OnVLRReset(vlrName)
		m.handler.OnVLRAssociationUp(vlrName)
	}
}

// handleResetAck completes the MME-initiated Reset procedure: the VLR has
// acknowledged our Reset Indication, so the association is now confirmed
// usable for Location Update and every other UE-level procedure.
func (m *Manager) handleResetAck(vlrName string, data []byte) {
	if _, err := sgsap.DecodeResetAck(data); err != nil {
		m.log.Warn("vlr: invalid RESET-ACK", zap.String("vlr_name", vlrName), zap.Error(err))
		return
	}
	a, err := m.association(vlrName)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.vlrReliable = true
	a.confirmed = true
	a.mu.Unlock()
	if m.handler != nil {
		m.handler.OnVLRAssociationUp(vlrName)
	}
}

// --- outbound message helpers: thin wrappers so callers never build raw
// SGsAP bytes by hand. Only the MME-originated messages phase 1/2 need are
// wrapped here; more are added as later phases use them. ---

func (m *Manager) SendLocationUpdateRequest(vlrName string, r sgsap.LocationUpdateRequest) error {
	data, err := sgsap.BuildLocationUpdateRequest(r)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendUplinkUnitdata(vlrName string, u sgsap.UplinkUnitdata) error {
	data, err := sgsap.BuildUplinkUnitdata(u)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendServiceRequest(vlrName string, r sgsap.ServiceRequest) error {
	data, err := sgsap.BuildServiceRequest(r)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendTMSIReallocationComplete(vlrName, imsi string) error {
	data, err := sgsap.BuildTMSIReallocationComplete(imsi)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendEPSDetachIndication(vlrName string, d sgsap.EPSDetachIndication) error {
	data, err := sgsap.BuildEPSDetachIndication(d)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendIMSIDetachIndication(vlrName string, d sgsap.IMSIDetachIndication) error {
	data, err := sgsap.BuildIMSIDetachIndication(d)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendPagingReject(vlrName, imsi string, cause sgsap.Cause) error {
	data, err := sgsap.BuildPagingReject(imsi, cause)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendAlertAck(vlrName, imsi string) error {
	data, err := sgsap.BuildAlertAck(imsi)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendAlertReject(vlrName, imsi string, cause sgsap.Cause) error {
	data, err := sgsap.BuildAlertReject(imsi, cause)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendUEUnreachable(vlrName string, u sgsap.UEUnreachable) error {
	data, err := sgsap.BuildUEUnreachable(u)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendUEActivityIndication(vlrName, imsi string) error {
	data, err := sgsap.BuildUEActivityIndication(imsi)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}

func (m *Manager) SendMOCSFBIndication(vlrName string, ind sgsap.MOCSFBIndication) error {
	data, err := sgsap.BuildMOCSFBIndication(ind)
	if err != nil {
		return err
	}
	return m.send(vlrName, data)
}
