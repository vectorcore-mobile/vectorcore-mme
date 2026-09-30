package s11

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gtpv2"
)

func TestBuildEchoResponseUsesConfiguredRecoveryRestartCounter(t *testing.T) {
	client, err := NewClient(config.S11Config{
		BindAddress:            "127.0.0.1",
		BindPort:               2123,
		RecoveryRestartCounter: 0x19,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got := client.buildEchoResponse(0x241)
	want := []byte{
		0x40, 0x02, 0x00, 0x09,
		0x00, 0x02, 0x41, 0x00,
		0x03, 0x00, 0x01, 0x00, 0x19,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Echo Response\n got %x\nwant %x", got, want)
	}
}

// resolverHandler is a ResultHandler that also maps local S11 TEIDs to the
// S-GW's, as the S1AP server does.
type resolverHandler struct{ peer map[uint32]uint32 }

func (h *resolverHandler) HandleCSRResult(uint32, *gtpv2.CreateSessionResponse, error)        {}
func (h *resolverHandler) HandleMBRResult(uint32, string, *gtpv2.ModifyBearerResponse, error) {}
func (h *resolverHandler) HandleDSRResult(uint32, uint8, error)                               {}
func (h *resolverHandler) HandleRABRResult(uint32, *gtpv2.ReleaseAccessBearersResult, error)  {}
func (h *resolverHandler) HandleDownlinkDataNotification(string, *gtpv2.DownlinkDataNotification) {
}
func (h *resolverHandler) HandleCreateBearerRequest(string, *gtpv2.CreateBearerRequest) {}
func (h *resolverHandler) HandleUpdateBearerRequest(string, *gtpv2.UpdateBearerRequest) {}
func (h *resolverHandler) HandleDeleteBearerRequest(string, *gtpv2.DeleteBearerRequest) {}
func (h *resolverHandler) S11PeerTEID(local uint32) uint32                              { return h.peer[local] }

// A bearer request the client cannot decode is rejected by the client itself.
// Its header must carry the S-GW's TEID, or 0 when that is not known (TS
// 29.274 §5.5.1/§5.5.2), never the MME's own TEID from the request.
func TestMalformedBearerRequestRejectHeaderTEID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		handler  ResultHandler
		wantTEID uint32
	}{
		{name: "resolved S-GW TEID", handler: &resolverHandler{peer: map[uint32]uint32{1: 0x9cb50f87}}, wantTEID: 0x9cb50f87},
		{name: "unknown TEID", handler: &resolverHandler{peer: map[uint32]uint32{}}, wantTEID: 0},
		{name: "no handler", handler: nil, wantTEID: 0},
	} {
		for _, msgType := range []uint8{gtpv2.MsgCreateBearerRequest, gtpv2.MsgUpdateBearerRequest, gtpv2.MsgDeleteBearerRequest} {
			t.Run(fmt.Sprintf("%s/type-%d", tc.name, msgType), func(t *testing.T) {
				mme, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatalf("ListenUDP mme: %v", err)
				}
				defer mme.Close()
				sgw, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatalf("ListenUDP sgw: %v", err)
				}
				defer sgw.Close()

				c := &Client{log: zap.NewNop(), conn: mme}
				if tc.handler != nil {
					c.SetHandler(tc.handler)
				}
				// No IEs at all: every bearer request decoder rejects it.
				req := gtpv2.Encode(&gtpv2.Message{Type: msgType, TEID: 1, SeqNum: 0x3c3})
				c.dispatch(req, sgw.LocalAddr().(*net.UDPAddr))

				buf := make([]byte, 1500)
				_ = sgw.SetReadDeadline(time.Now().Add(time.Second))
				n, _, err := sgw.ReadFromUDP(buf)
				if err != nil {
					t.Fatalf("no reject received: %v", err)
				}
				resp, err := gtpv2.Decode(buf[:n])
				if err != nil {
					t.Fatalf("Decode reject: %v", err)
				}
				if resp.Type != msgType+1 {
					t.Fatalf("reject type got %d, want %d", resp.Type, msgType+1)
				}
				if resp.TEID != tc.wantTEID {
					t.Fatalf("reject header TEID got %#x, want %#x", resp.TEID, tc.wantTEID)
				}
				if resp.SeqNum != 0x3c3 {
					t.Fatalf("reject seq got %#x, want 0x3c3", resp.SeqNum)
				}
			})
		}
	}
}

// TS 29.274 Table 7.2.1-1: the Recovery IE is in the Create Session Request
// when the MME contacts an S-GW for the first time, so the S-GW can detect
// an MME restart without waiting for an Echo exchange.
func TestSendCSRRecoveryOnFirstContactPerSGW(t *testing.T) {
	mme, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP mme: %v", err)
	}
	defer mme.Close()
	sgwA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP sgw: %v", err)
	}
	defer sgwA.Close()
	sgwB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP sgw: %v", err)
	}
	defer sgwB.Close()

	c := &Client{cfg: config.S11Config{RecoveryRestartCounter: 0x2a}, log: zap.NewNop(), conn: mme}
	recovery := func(sgw *net.UDPConn) (uint8, bool) {
		t.Helper()
		req := &gtpv2.CreateSessionRequest{
			SGWAddress:   sgw.LocalAddr().String(),
			IMSI:         "001010000000001",
			APN:          "internet",
			LocalS11TEID: 0x10001,
			LocalS11IP:   net.IPv4(127, 0, 0, 1),
			DefaultEBI:   5,
			BearerQCI:    9,
		}
		if err := c.SendCSR(1, req); err != nil {
			t.Fatalf("SendCSR: %v", err)
		}
		if req.Recovery != nil {
			t.Fatal("SendCSR modified the caller's request")
		}
		buf := make([]byte, 1500)
		_ = sgw.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := sgw.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no CSR received: %v", err)
		}
		msg, err := gtpv2.Decode(buf[:n])
		if err != nil {
			t.Fatalf("Decode CSR: %v", err)
		}
		ie := gtpv2.FindIE(msg.IEs, gtpv2.IETypeRecovery, 0)
		if ie == nil {
			return 0, false
		}
		return ie.Value[0], true
	}

	if v, ok := recovery(sgwA); !ok || v != 0x2a {
		t.Fatalf("first CSR to S-GW A: recovery %#x present %v, want 0x2a", v, ok)
	}
	if _, ok := recovery(sgwA); ok {
		t.Fatal("second CSR to S-GW A carries Recovery IE")
	}
	if v, ok := recovery(sgwB); !ok || v != 0x2a {
		t.Fatalf("first CSR to S-GW B: recovery %#x present %v, want 0x2a", v, ok)
	}
}
