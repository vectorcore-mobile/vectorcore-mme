package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
)

func TestLoadGatewaySelectionConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	data := []byte(`
nf:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  mcc: "001"
  mnc: "01"
s11:
  bind_address: "127.0.0.1"
  bind_port: 2123
s6a:
  peer_address: "127.0.0.1:3868"
gateway_selection:
  dns:
    enabled: true
    root_domain: ""
    sgw_enabled: true
    pgw_enabled: true
  sgw:
    sgw_address: "127.0.0.3:2123"
  pgw:
    pgw_address: "127.0.0.4"
    prefer_s6a_static: true
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.S11.BindAddress != "127.0.0.1" || cfg.S11.BindPort != 2123 {
		t.Fatalf("S11 bind config not parsed: %+v", cfg.S11)
	}
	if cfg.GatewaySelection.SGW.SGWAddress != "127.0.0.3:2123" {
		t.Fatalf("SGW fallback = %q", cfg.GatewaySelection.SGW.SGWAddress)
	}
	if cfg.GatewaySelection.PGW.PGWAddress != "127.0.0.4" {
		t.Fatalf("PGW fallback = %q", cfg.GatewaySelection.PGW.PGWAddress)
	}
	if !cfg.GatewaySelection.PGW.PreferS6AStatic {
		t.Fatal("prefer_s6a_static not parsed")
	}
	if got, want := gateway.RootDomain(cfg.NF, cfg.GatewaySelection.DNS.RootDomain), "epc.mnc001.mcc001.3gppnetwork.org"; got != want {
		t.Fatalf("derived root domain = %q, want %q", got, want)
	}
}

func TestLoadOperatorNameEncodingDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	data := []byte(`
nf:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  mcc: "001"
  mnc: "01"
s6a:
  peer_address: "127.0.0.1:3868"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.Operator.Name.Encoding != "gsm7" {
		t.Fatalf("operator.name.encoding = %q, want gsm7", cfg.Operator.Name.Encoding)
	}
}

func TestLoadOperatorNameEncodingInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	data := []byte(`
nf:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  mcc: "001"
  mnc: "01"
s6a:
  peer_address: "127.0.0.1:3868"
operator:
  name:
    encoding: "latin1"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("Load() expected invalid operator.name.encoding error")
	}
}
