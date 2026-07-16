package s11

import (
	"bytes"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
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
