package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NF               NFConfig               `yaml:"nf"`
	S1AP             S1APConfig             `yaml:"s1ap"`
	S6a              S6aConfig              `yaml:"s6a"`
	S10              S10Config              `yaml:"s10"`
	S11              S11Config              `yaml:"s11"`
	GatewaySelection GatewaySelectionConfig `yaml:"gateway_selection"`
	Database         DatabaseConfig         `yaml:"database"`
	Logging          LoggingConfig          `yaml:"logging"`
	API              APIConfig              `yaml:"api"`
	Security         SecurityConfig         `yaml:"security"`
	Operator         OperatorConfig         `yaml:"operator"`
}

// OperatorConfig holds network identity and NITZ settings pushed to UEs via EMM Information.
type OperatorConfig struct {
	PLMN struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	Name struct {
		Full      string `yaml:"full"`
		Short     string `yaml:"short"`
		ShowFull  bool   `yaml:"show_full"`
		ShowShort bool   `yaml:"show_short"`
	} `yaml:"name"`
	NITZ struct {
		Enabled               bool  `yaml:"enabled"`
		TimezoneOffsetMinutes int   `yaml:"timezone_offset_minutes"`
		DaylightSaving        uint8 `yaml:"daylight_saving"` // 0=none, 1=+1h, 2=+2h
	} `yaml:"nitz"`
	EMMInformation struct {
		Enabled         bool `yaml:"enabled"`
		SendAfterAttach bool `yaml:"send_after_attach"`
		SendAfterTAU    bool `yaml:"send_after_tau"`
	} `yaml:"emm_information"`
}

// S10Config holds the GTPv2-C S10 interface configuration (MME ↔ MME context transfer).
type S10Config struct {
	Enabled     bool            `yaml:"enabled"`
	BindAddress string          `yaml:"bind_address"` // default "0.0.0.0"
	BindPort    int             `yaml:"bind_port"`    // default 2124
	Peers       []PeerMMEConfig `yaml:"peers"`
}

// PeerMMEConfig identifies a remote MME reachable over S10.
type PeerMMEConfig struct {
	Name    string `yaml:"name"`
	MMEC    uint8  `yaml:"mmec"`    // peer MME Code (identifies peer within a pool)
	MMEGI   uint16 `yaml:"mmegi"`   // peer MME Group ID (0 = match any)
	MCC     string `yaml:"mcc"`     // peer PLMN MCC (empty = match local PLMN)
	MNC     string `yaml:"mnc"`     // peer PLMN MNC (empty = match local PLMN)
	Address string `yaml:"address"` // "ip:port" UDP endpoint
}

// S11Config holds the GTPv2-C S11 interface configuration (MME ↔ S-GW).
type S11Config struct {
	Enabled     bool   `yaml:"enabled"`
	BindAddress string `yaml:"bind_address"` // local IP for MME S11 socket
	BindPort    int    `yaml:"bind_port"`    // default 2123
}

type GatewaySelectionConfig struct {
	DNS GatewaySelectionDNSConfig `yaml:"dns"`
	SGW GatewaySelectionSGWConfig `yaml:"sgw"`
	PGW GatewaySelectionPGWConfig `yaml:"pgw"`
}

type GatewaySelectionDNSConfig struct {
	Enabled    bool                           `yaml:"enabled"`
	RootDomain string                         `yaml:"root_domain"`
	SGWEnabled bool                           `yaml:"sgw_enabled"`
	PGWEnabled bool                           `yaml:"pgw_enabled"`
	Resolver   GatewaySelectionResolverConfig `yaml:"resolver"`
	Cache      GatewaySelectionCacheConfig    `yaml:"cache"`
}

type GatewaySelectionResolverConfig struct {
	Servers    []string      `yaml:"servers"`
	Timeout    time.Duration `yaml:"timeout"`
	Retries    int           `yaml:"retries"`
	PreferIPv6 bool          `yaml:"prefer_ipv6"`
}

type GatewaySelectionCacheConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MinTTL      time.Duration `yaml:"min_ttl"`
	MaxTTL      time.Duration `yaml:"max_ttl"`
	NegativeTTL time.Duration `yaml:"negative_ttl"`
}

type GatewaySelectionSGWConfig struct {
	SGWAddress string `yaml:"sgw_address"`
}

type GatewaySelectionPGWConfig struct {
	PGWAddress      string `yaml:"pgw_address"`
	PreferS6AStatic bool   `yaml:"prefer_s6a_static"`
}

type NFConfig struct {
	OriginHost  string    `yaml:"origin_host"`
	OriginRealm string    `yaml:"origin_realm"`
	MCC         string    `yaml:"mcc"`
	MNC         string    `yaml:"mnc"`
	MMEGI       uint16    `yaml:"mmegi"` // MME Group ID
	MMEC        uint8     `yaml:"mmec"`  // MME Code
	TAIList     []TAIItem `yaml:"tai_list"`
}

type TAIItem struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
	TAC uint16 `yaml:"tac"`
}

type S1APConfig struct {
	BindAddress string `yaml:"bind_address"`
	BindPort    int    `yaml:"bind_port"`
	SCTPStreams int    `yaml:"sctp_streams"`
}

type S6aConfig struct {
	Enabled     bool          `yaml:"enabled"`
	HSSAddress  string        `yaml:"hss_address"`  // client mode: connect outbound to HSS/DRA
	BindAddress string        `yaml:"bind_address"` // server mode: listen for inbound Diameter connections
	BindPort    int           `yaml:"bind_port"`    // server mode port (default 3868)
	OriginHost  string        `yaml:"origin_host"`
	OriginRealm string        `yaml:"origin_realm"`
	RetryDelay  time.Duration `yaml:"retry_delay"`
}

type DatabaseConfig struct {
	Type            string `yaml:"db_type"`
	Host            string `yaml:"server"`
	Port            int    `yaml:"port"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	Database        string `yaml:"database"`
	MaxOpenConns    int    `yaml:"pool_size"`
	MaxIdleConns    int    `yaml:"pool_idle"`
	ConnMaxLifetime int    `yaml:"pool_recycle"` // seconds
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

type APIConfig struct {
	Enabled     bool     `yaml:"enabled"`
	BindAddress string   `yaml:"bind_address"`
	BindPort    int      `yaml:"bind_port"`
	TLSCertFile string   `yaml:"tls_cert_file"`
	TLSKeyFile  string   `yaml:"tls_key_file"`
	AuthEnabled bool     `yaml:"auth_enabled"`
	APIKeys     []string `yaml:"api_keys"`
}

type SecurityConfig struct {
	IntegrityAlgorithms []string `yaml:"integrity_algorithms"` // EIA2, EIA1, EIA0
	CipheringAlgorithms []string `yaml:"ciphering_algorithms"` // EEA2, EEA1, EEA0
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg := &Config{
		NF: NFConfig{
			MMEGI: 1,
			MMEC:  1,
		},
		S1AP: S1APConfig{
			BindAddress: "0.0.0.0",
			BindPort:    36412,
			SCTPStreams: 2,
		},
		S6a: S6aConfig{
			Enabled:    false,
			RetryDelay: 5 * time.Second,
		},
		S10: S10Config{
			BindAddress: "0.0.0.0",
			BindPort:    2124,
		},
		S11: S11Config{
			BindAddress: "0.0.0.0",
			BindPort:    2123,
		},
		GatewaySelection: GatewaySelectionConfig{
			DNS: GatewaySelectionDNSConfig{
				Resolver: GatewaySelectionResolverConfig{
					Timeout: 2 * time.Second,
					Retries: 2,
				},
				Cache: GatewaySelectionCacheConfig{
					Enabled:     true,
					MinTTL:      30 * time.Second,
					MaxTTL:      300 * time.Second,
					NegativeTTL: 10 * time.Second,
				},
			},
			PGW: GatewaySelectionPGWConfig{
				PreferS6AStatic: true,
			},
		},
		Database: DatabaseConfig{
			Type:            "postgres",
			Port:            5432,
			MaxOpenConns:    30,
			MaxIdleConns:    10,
			ConnMaxLifetime: 300,
		},
		Logging: LoggingConfig{Level: "info"},
		API: APIConfig{
			Enabled:     true,
			BindAddress: "0.0.0.0",
			BindPort:    8080,
		},
		Security: SecurityConfig{
			IntegrityAlgorithms: []string{"EIA2", "EIA1", "EIA0"},
			CipheringAlgorithms: []string{"EEA2", "EEA1", "EEA0"},
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}

	if cfg.NF.OriginHost == "" {
		return nil, fmt.Errorf("config: nf.origin_host is required")
	}
	if cfg.NF.MCC == "" || cfg.NF.MNC == "" {
		return nil, fmt.Errorf("config: nf.mcc and nf.mnc are required")
	}
	if cfg.S6a.OriginHost == "" {
		cfg.S6a.OriginHost = cfg.NF.OriginHost
	}
	if cfg.S6a.OriginRealm == "" {
		cfg.S6a.OriginRealm = cfg.NF.OriginRealm
	}

	return cfg, nil
}
