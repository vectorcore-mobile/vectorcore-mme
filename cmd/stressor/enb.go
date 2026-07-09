package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

// ENB simulates a single eNodeB: one SCTP connection to the MME,
// dispatching downlink messages to per-UE goroutines by ENB-UE-S1AP-ID.
type ENB struct {
	cfg    *Config
	conn   *sctp.SCTPConn
	sendMu sync.Mutex

	ueChans sync.Map // uint32 ENB-UE-S1AP-ID → chan<- []byte
	nextID  atomic.Uint32
	setupCh chan error
}

// NewENB connects to the MME, performs S1 Setup, and starts the receive loop.
func NewENB(cfg *Config) (*ENB, error) {
	host, portStr, err := net.SplitHostPort(cfg.MMEAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid MME address %q: %w", cfg.MMEAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	remote := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP(host)}},
		Port:    port,
	}

	conn, err := sctp.DialSCTP("sctp", nil, remote)
	if err != nil {
		return nil, fmt.Errorf("SCTP dial %s: %w", cfg.MMEAddr, err)
	}

	enb := &ENB{
		cfg:     cfg,
		conn:    conn,
		setupCh: make(chan error, 1),
	}

	go enb.readLoop()

	if err := enb.sendS1SetupRequest(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("S1 Setup send: %w", err)
	}

	select {
	case err := <-enb.setupCh:
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("S1 Setup failed: %w", err)
		}
	case <-time.After(10 * time.Second):
		conn.Close()
		return nil, fmt.Errorf("S1 Setup timeout")
	}

	return enb, nil
}

func (enb *ENB) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := enb.conn.Read(buf)
		if err != nil {
			// Signal any waiting UEs
			enb.ueChans.Range(func(k, v any) bool {
				ch := v.(chan []byte)
				close(ch)
				return true
			})
			return
		}
		if n == 0 {
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		enb.dispatch(msg)
	}
}

func (enb *ENB) dispatch(data []byte) {
	p, err := pdu.Decode(data)
	if err != nil {
		return
	}

	switch p.ProcedureCode {
	case pdu.ProcS1Setup:
		if p.Type == pdu.PDUTypeSuccessfulOutcome {
			enb.setupCh <- nil
		} else {
			enb.setupCh <- fmt.Errorf("S1 Setup Failure (proc=%d)", p.ProcedureCode)
		}
		return
	}

	// For per-UE messages, find the ENB-UE-S1AP-ID
	ieList, err := pdu.DecodeIEContainer(p.Value)
	if err != nil {
		return
	}

	var enbUEID uint32
	for _, ie := range ieList {
		if ie.ID == pdu.IEENBS1APID {
			id, _ := ies.DecodeENBUEApID(ie.Value)
			enbUEID = id
			break
		}
	}

	if v, ok := enb.ueChans.Load(enbUEID); ok {
		ch := v.(chan []byte)
		select {
		case ch <- data:
		default:
		}
	}
}

// Send writes a raw S1AP PDU to the MME.
func (enb *ENB) Send(data []byte) error {
	enb.sendMu.Lock()
	defer enb.sendMu.Unlock()
	_, err := enb.conn.Write(data)
	return err
}

// AllocateUEID returns a unique ENB-UE-S1AP-ID for a new UE.
func (enb *ENB) AllocateUEID() uint32 {
	return enb.nextID.Add(1)
}

// RegisterUE registers a receive channel for the given ENB-UE-S1AP-ID.
func (enb *ENB) RegisterUE(enbUEID uint32, ch chan []byte) {
	enb.ueChans.Store(enbUEID, ch)
}

// UnregisterUE removes the receive channel for the given ENB-UE-S1AP-ID.
func (enb *ENB) UnregisterUE(enbUEID uint32) {
	enb.ueChans.Delete(enbUEID)
}

// ── S1 Setup encoding ────────────────────────────────────────────────────────

func (enb *ENB) sendS1SetupRequest() error {
	plmn, err := ies.EncodePLMN(enb.cfg.MCC, enb.cfg.MNC)
	if err != nil {
		return err
	}
	globalENBID, err := ies.EncodeGlobalENBID(ies.GlobalENBID{
		MCC: enb.cfg.MCC,
		MNC: enb.cfg.MNC,
		ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: enb.cfg.ENBID},
	})
	if err != nil {
		return err
	}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEGlobal_ENB_ID, Criticality: aper.CriticalityReject, Value: globalENBID},
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: encodeSupportedTAs(plmn, enb.cfg.TAC)},
		{ID: pdu.IEDefaultPagingDRX, Criticality: aper.CriticalityIgnore, Value: ies.EncodePagingDRX(1)},
	}
	msg := pdu.Encode(&pdu.PDU{
		Type:          pdu.PDUTypeInitiatingMessage,
		ProcedureCode: pdu.ProcS1Setup,
		Criticality:   aper.CriticalityReject,
		Value:         pdu.EncodeProcedureIEContainer(ieList),
	})
	return enb.Send(msg)
}

// encodeSupportedTAs encodes the SupportedTAs IE for a single TA.
func encodeSupportedTAs(plmn []byte, tac uint16) []byte {
	w := aper.NewBitWriter()
	// SEQUENCE OF (SIZE 1..256) — constrained count: 1..256
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 256)
	// SupportedTA: extension marker + optional map + tAC OCTET STRING (SIZE 2) + broadcastPLMNs SEQUENCE OF (SIZE 1..6)
	w.WriteBit(0) // SupportedTAs-Item SEQUENCE extension = 0
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeOctetString(w, []byte{byte(tac >> 8), byte(tac)}, 2, 2)
	// broadcastPLMNs count: 1..6
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 6)
	w.AlignToByte()
	w.WriteOctets(plmn)
	return w.Bytes()
}
