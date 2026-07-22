package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
)

// load appends the mandatory shared Diameter configuration to legacy-focused
// test fixtures. Individual tests can stay focused on the setting under test.
func load(t *testing.T, path string) (*config.Config, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = append(data, []byte(`
diameter:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  peers:
    - name: "dra-1"
      address: "127.0.0.1:3868"
`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return config.Load(path)
}

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
	cfg, err := load(t, path)
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

func TestLoadS13DefaultsAndPolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	if err := os.WriteFile(path, []byte(`
nf:
  origin_host: mme.example
  mcc: "001"
  mnc: "01"
s13:
  enabled: true
  blacklist_policy: reject
  greylist_policy: reject
`), 0o600); err != nil { t.Fatal(err) }
	cfg, err := load(t, path)
	if err != nil { t.Fatal(err) }
	if !cfg.S13.Enabled || cfg.S13.WhitelistPolicy != "allow" || cfg.S13.BlacklistPolicy != "reject" || cfg.S13.GreylistPolicy != "reject" { t.Fatalf("unexpected S13 config: %+v", cfg.S13) }
}

func TestLoadRejectsInvalidS13Policy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	if err := os.WriteFile(path, []byte(`
nf:
  origin_host: mme.example
  mcc: "001"
  mnc: "01"
s13:
  failure_policy: ignore
`), 0o600); err != nil { t.Fatal(err) }
	if _, err := load(t, path); err == nil { t.Fatal("expected invalid S13 policy error") }
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
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.Operator.Name.Encoding != "gsm7" {
		t.Fatalf("operator.name.encoding = %q, want gsm7", cfg.Operator.Name.Encoding)
	}
	if !cfg.S6a.SendPUROnDetach {
		t.Fatal("s6a.send_pur_on_detach default got false, want true")
	}
	if cfg.NF.RelativeMMECapacity != 255 {
		t.Fatalf("nf.relative_mme_capacity default got %d, want 255", cfg.NF.RelativeMMECapacity)
	}
	if cfg.NAS.EPSNetworkFeatureSupport.IMSVoiceOverPS {
		t.Fatal("nas.eps_network_feature_support.ims_voice_over_ps default got true, want false")
	}
}

func TestLoadNFRelativeMMECapacity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	data := []byte(`
nf:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  mcc: "001"
  mnc: "01"
  relative_mme_capacity: 128
s6a:
  peer_address: "127.0.0.1:3868"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if got, want := cfg.NF.RelativeMMECapacity, uint8(128); got != want {
		t.Fatalf("nf.relative_mme_capacity got %d, want %d", got, want)
	}
}

func TestLoadNFMMEName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	data := []byte(`
nf:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  mcc: "001"
  mnc: "01"
  mme_name: "vectorcore-mme"
s6a:
  peer_address: "127.0.0.1:3868"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if got, want := cfg.NF.MMEName, "vectorcore-mme"; got != want {
		t.Fatalf("nf.mme_name got %q, want %q", got, want)
	}
}

func TestLoadS6aSendPURToggle(t *testing.T) {
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
  send_pur_on_detach: false
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.S6a.SendPUROnDetach {
		t.Fatal("s6a.send_pur_on_detach got true, want false")
	}
}

func TestLoadS6aRequestShapingDefaults(t *testing.T) {
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
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.S6a.AIR.RequestedVectors != 1 {
		t.Fatalf("s6a.air.requested_vectors default got %d, want 1", cfg.S6a.AIR.RequestedVectors)
	}
	if !cfg.S6a.AIR.ImmediateResponsePreferred {
		t.Fatal("s6a.air.immediate_response_preferred default got false, want true")
	}
	if cfg.S6a.ULR.Flags != 0x02 {
		t.Fatalf("s6a.ulr.flags default got %d, want 2", cfg.S6a.ULR.Flags)
	}
}

func TestLoadS6aRequestShapingOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mme.yaml")
	data := []byte(`
nf:
  origin_host: "mme.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  mcc: "001"
  mnc: "01"
s6a:
  air:
    requested_vectors: 3
    immediate_response_preferred: false
  ulr:
    flags: 18
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.S6a.AIR.RequestedVectors != 3 {
		t.Fatalf("s6a.air.requested_vectors got %d, want 3", cfg.S6a.AIR.RequestedVectors)
	}
	if cfg.S6a.AIR.ImmediateResponsePreferred {
		t.Fatal("s6a.air.immediate_response_preferred got true, want false")
	}
	if cfg.S6a.ULR.Flags != 18 {
		t.Fatalf("s6a.ulr.flags got %d, want 18", cfg.S6a.ULR.Flags)
	}
}

func TestLoadS6aRequestedVectorsRejectsZero(t *testing.T) {
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
  air:
    requested_vectors: 0
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(t, path); err == nil {
		t.Fatal("Load() expected invalid s6a.air.requested_vectors error")
	}
}

func TestLoadNASIMSVoiceOverPS(t *testing.T) {
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
nas:
  eps_network_feature_support:
    ims_voice_over_ps: true
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if !cfg.NAS.EPSNetworkFeatureSupport.IMSVoiceOverPS {
		t.Fatal("ims_voice_over_ps got false, want true")
	}
}

func TestLoadNASTimerDefaults(t *testing.T) {
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
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.NAS.Timers.T3402 != 720 || cfg.NAS.Timers.T3396 != 720 ||
		cfg.NAS.Timers.T3412 != 3240 || cfg.NAS.Timers.T3423 != 720 {
		t.Fatalf("unexpected NAS timer defaults: %+v", cfg.NAS.Timers)
	}
}

func TestLoadNASTimers(t *testing.T) {
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
nas:
  timers:
    t3402: 720
    t3396: 1800
    t3412: 3240
    t3423: 720
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(t, path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.NAS.Timers.T3402 != 720 || cfg.NAS.Timers.T3396 != 1800 ||
		cfg.NAS.Timers.T3412 != 3240 || cfg.NAS.Timers.T3423 != 720 {
		t.Fatalf("unexpected NAS timers: %+v", cfg.NAS.Timers)
	}
}

func TestLoadNASTimersInvalid(t *testing.T) {
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
nas:
  timers:
    t3412: 61
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(t, path); err == nil {
		t.Fatal("Load() expected invalid nas.timers.t3412 error")
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
	if _, err := load(t, path); err == nil {
		t.Fatal("Load() expected invalid operator.name.encoding error")
	}
}

func TestLoadOperatorNITZTimezoneInvalid(t *testing.T) {
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
  nitz:
    enabled: true
    timezone: "Not/AZone"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(t, path); err == nil {
		t.Fatal("Load() expected invalid operator.nitz.timezone error")
	}
}
