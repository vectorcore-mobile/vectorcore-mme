package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vectorcore/mme/internal/config"
)

func TestRoamingConfigValidation(t *testing.T) {
	base := "nf:\n  origin_host: mme.example\n  mcc: \"311\"\n  mnc: \"435\"\nroaming:\n"
	loadRaw := func(t *testing.T, extra string) (*config.Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "mme.yaml")
		data := base + extra + "\ndiameter:\n  origin_host: mme.example\n  origin_realm: example\n  peers: [{name: dra, address: \"127.0.0.1:3868\"}]\n"
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		return config.Load(path)
	}
	cfg, err := loadRaw(t, "  # defaults\n")
	if err != nil || cfg.Roaming.Enabled || cfg.Roaming.Policy.DefaultAction != config.RoamingActionDeny {
		t.Fatalf("defaults = %+v, %v", cfg.Roaming, err)
	}
	cfg, err = loadRaw(t, "  enabled: true\n  policy:\n    default_action: allow\n    plmn_acl:\n      - plmn: {mcc: \"001\", mnc: \"01\"}\n        action: allow\n      - plmn: {mcc: \"310\", mnc: \"260\"}\n        action: deny\n  hss_routes:\n    - plmn: {mcc: \"001\", mnc: \"01\"}\n      host: hss.example\n")
	if err != nil || cfg.Roaming.Policy.PLMNACL[0].PLMN.MNC != "01" || cfg.Roaming.Policy.PLMNACL[1].PLMN.MNC != "260" {
		t.Fatalf("valid PLMNs = %+v, %v", cfg.Roaming, err)
	}
	for _, tc := range []struct{ name, extra, want string }{
		{"bad mcc", "  policy:\n    plmn_acl: [{plmn: {mcc: \"31\", mnc: \"01\"}, action: allow}]\n", "MCC"},
		{"bad mnc", "  policy:\n    plmn_acl: [{plmn: {mcc: \"001\", mnc: \"1\"}, action: allow}]\n", "MNC"},
		{"numeric mnc", "  policy:\n    plmn_acl: [{plmn: {mcc: \"001\", mnc: 1}, action: allow}]\n", "MNC must be a string"},
		{"bad default", "  policy:\n    default_action: maybe\n", "default_action"},
		{"bad acl", "  policy:\n    plmn_acl: [{plmn: {mcc: \"001\", mnc: \"01\"}, action: maybe}]\n", ".action"},
		{"duplicate acl", "  policy:\n    plmn_acl: [{plmn: {mcc: \"001\", mnc: \"01\"}, action: allow}, {plmn: {mcc: \"001\", mnc: \"01\"}, action: deny}]\n", "duplicate"},
		{"duplicate route", "  hss_routes: [{plmn: {mcc: \"001\", mnc: \"01\"}}, {plmn: {mcc: \"001\", mnc: \"01\"}}]\n", "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadRaw(t, tc.extra)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
