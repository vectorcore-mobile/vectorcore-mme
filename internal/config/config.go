package config

import (
	"fmt"
	"os"
	"time"

	nastimer "github.com/vectorcore/mme/internal/nas/timer"
	"gopkg.in/yaml.v3"
)

type Config struct {
	NF               NFConfig               `yaml:"nf"`
	Diameter         DiameterConfig         `yaml:"diameter"`
	S1AP             S1APConfig             `yaml:"s1ap"`
	S6a              S6aConfig              `yaml:"s6a"`
	S13              S13Config              `yaml:"s13"`
	S10              S10Config              `yaml:"s10"`
	S11              S11Config              `yaml:"s11"`
	Paging           PagingConfig           `yaml:"paging"`
	GatewaySelection GatewaySelectionConfig `yaml:"gateway_selection"`
	Database         DatabaseConfig         `yaml:"database"`
	Logging          LoggingConfig          `yaml:"logging"`
	API              APIConfig              `yaml:"api"`
	Security         SecurityConfig         `yaml:"security"`
	NAS              NASConfig              `yaml:"nas"`
	Operator         OperatorConfig         `yaml:"operator"`
}

type NASConfig struct {
	EPSNetworkFeatureSupport EPSNetworkFeatureSupportConfig `yaml:"eps_network_feature_support"`
	Timers                   NASTimersConfig                `yaml:"timers"`
}

type EPSNetworkFeatureSupportConfig struct {
	IMSVoiceOverPS bool `yaml:"ims_voice_over_ps"`
}

type NASTimersConfig struct {
	T3402 int `yaml:"t3402"`
	T3396 int `yaml:"t3396"`
	T3412 int `yaml:"t3412"`
	T3423 int `yaml:"t3423"`
}

// OperatorConfig holds network identity and NITZ settings pushed to UEs via EMM Information.
type OperatorConfig struct {
	Name struct {
		Full               string `yaml:"full"`
		Short              string `yaml:"short"`
		ShowFull           bool   `yaml:"show_full"`
		ShowShort          bool   `yaml:"show_short"`
		Encoding           string `yaml:"encoding"`
		AddCountryInitials bool   `yaml:"add_country_initials"`
	} `yaml:"name"`
	NITZ struct {
		Enabled                              bool   `yaml:"enabled"`
		Timezone                             string `yaml:"timezone"`
		TimezoneOffsetMinutes                int    `yaml:"timezone_offset_minutes"`
		DaylightSaving                       uint8  `yaml:"daylight_saving"` // 0=none, 1=+1h, 2=+2h
		IncludeLocalTimeZone                 bool   `yaml:"include_local_time_zone"`
		IncludeUniversalTimeAndLocalTimeZone bool   `yaml:"include_universal_time_and_local_time_zone"`
		IncludeDaylightSavingTime            bool   `yaml:"include_daylight_saving_time"`
	} `yaml:"nitz"`
	EMMInformation struct {
		Enabled         bool `yaml:"enabled"`
		SendAfterAttach bool `yaml:"send_after_attach"`
		SendAfterTAU    bool `yaml:"send_after_tau"`
	} `yaml:"emm_information"`
	TAU struct {
		// ReallocateGUTI controls same-MME GUTI reallocation in TAU Accept.
		// The default false avoids forcing TAU Complete for ordinary same-MME TAU.
		ReallocateGUTI bool `yaml:"reallocate_guti"`
	} `yaml:"tau"`
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
	BindAddress            string `yaml:"bind_address"`             // local IP for MME S11 socket
	BindPort               int    `yaml:"bind_port"`                // default 2123
	RecoveryRestartCounter uint8  `yaml:"recovery_restart_counter"` // GTPv2 Recovery IE value used in Echo Response
}

type PagingConfig struct {
	DDNEnabled         bool          `yaml:"ddn_enabled"`
	RetryInterval      time.Duration `yaml:"retry_interval"`
	MaxAttempts        uint8         `yaml:"max_attempts"`
	TransactionTimeout time.Duration `yaml:"transaction_timeout"`
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
	OriginHost          string    `yaml:"origin_host"`
	OriginRealm         string    `yaml:"origin_realm"`
	MMEName             string    `yaml:"mme_name"` // optional S1AP MMEname VisibleString
	MCC                 string    `yaml:"mcc"`
	MNC                 string    `yaml:"mnc"`
	MMEGI               uint16    `yaml:"mmegi"`                 // MME Group ID
	MMEC                uint8     `yaml:"mmec"`                  // MME Code
	RelativeMMECapacity uint8     `yaml:"relative_mme_capacity"` // S1AP RelativeMMECapacity
	TAIList             []TAIItem `yaml:"tai_list"`
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

// DiameterConfig contains shared Diameter transport and peer-routing settings.
// Peer capability is learned during CER/CEA; applications are deliberately not
// configured here.
type DiameterConfig struct {
	OriginHost    string               `yaml:"origin_host"`
	OriginRealm   string               `yaml:"origin_realm"`
	BindAddress   string               `yaml:"bind_addr"`
	BindTransport string               `yaml:"bind_transport"` // tcp (default) or sctp; applies only with bind_addr
	RetryDelay    time.Duration        `yaml:"retry_delay"`
	Peers         []DiameterPeerConfig `yaml:"peers"`
}

// S13Config controls the 3GPP S13 Equipment Identity Register application.
// It deliberately lives under diameter because S13 uses the shared Diameter
// transport and application-aware routing table.
type S13Config struct {
	Enabled         bool          `yaml:"enabled"`
	CheckOnAttach   bool          `yaml:"check_on_attach"`
	CheckOnTAU      bool          `yaml:"check_on_tau"`
	FailurePolicy   string        `yaml:"failure_policy"`
	WhitelistPolicy string        `yaml:"whitelist_policy"`
	BlacklistPolicy string        `yaml:"blacklist_policy"`
	GreylistPolicy  string        `yaml:"greylist_policy"`
	Timeout         time.Duration `yaml:"timeout"`
}

type DiameterPeerConfig struct {
	Name      string `yaml:"name"`
	Address   string `yaml:"address"`
	Transport string `yaml:"transport"` // tcp (default) or sctp
	Priority  *int   `yaml:"priority"`  // lower wins; nil falls back to config order
}

type S6aConfig struct {
	SendPUROnDetach bool         `yaml:"send_pur_on_detach"`
	AIR             S6aAIRConfig `yaml:"air"`
	ULR             S6aULRConfig `yaml:"ulr"`
}

type S6aAIRConfig struct {
	RequestedVectors           uint32 `yaml:"requested_vectors"`
	ImmediateResponsePreferred bool   `yaml:"immediate_response_preferred"`
}

type S6aULRConfig struct {
	Flags uint32 `yaml:"flags"`
}

type DatabaseConfig struct {
	Mode            string `yaml:"mode"`
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
			MMEGI:               1,
			MMEC:                1,
			RelativeMMECapacity: 255,
		},
		S1AP: S1APConfig{
			BindAddress: "0.0.0.0",
			BindPort:    36412,
			SCTPStreams: 2,
		},
		S6a: S6aConfig{
			SendPUROnDetach: true,
			AIR: S6aAIRConfig{
				RequestedVectors:           1,
				ImmediateResponsePreferred: true,
			},
			ULR: S6aULRConfig{
				Flags: 0x02,
			},
		},
		Diameter: DiameterConfig{RetryDelay: 5 * time.Second},
		S13: S13Config{
			FailurePolicy:   "allow",
			WhitelistPolicy: "allow",
			BlacklistPolicy: "reject",
			GreylistPolicy:  "allow",
			Timeout:         5 * time.Second,
		},
		S10: S10Config{
			BindAddress: "0.0.0.0",
			BindPort:    2124,
		},
		S11: S11Config{
			BindAddress: "0.0.0.0",
			BindPort:    2123,
		},
		Paging: PagingConfig{
			DDNEnabled:         true,
			RetryInterval:      2 * time.Second,
			MaxAttempts:        3,
			TransactionTimeout: 8 * time.Second,
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
			Mode:            "persistent",
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
		NAS: NASConfig{
			Timers: NASTimersConfig{
				T3402: nastimer.DefaultT3402,
				T3396: nastimer.DefaultT3396,
				T3412: nastimer.DefaultT3412,
				T3423: nastimer.DefaultT3423,
			},
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
	if cfg.Diameter.OriginHost == "" || cfg.Diameter.OriginRealm == "" {
		return nil, fmt.Errorf("config: diameter.origin_host and diameter.origin_realm are required")
	}
	if len(cfg.Diameter.Peers) == 0 {
		return nil, fmt.Errorf("config: diameter.peers must contain at least one peer")
	}
	if cfg.Diameter.BindAddress != "" {
		if cfg.Diameter.BindTransport == "" {
			cfg.Diameter.BindTransport = "tcp"
		}
		if cfg.Diameter.BindTransport != "tcp" && cfg.Diameter.BindTransport != "sctp" {
			return nil, fmt.Errorf("config: diameter.bind_transport must be tcp or sctp")
		}
	}
	for i := range cfg.Diameter.Peers {
		peer := &cfg.Diameter.Peers[i]
		if peer.Name == "" || peer.Address == "" {
			return nil, fmt.Errorf("config: diameter.peers[%d] name and address are required", i)
		}
		if peer.Transport == "" {
			peer.Transport = "tcp"
		}
		if peer.Transport != "tcp" && peer.Transport != "sctp" {
			return nil, fmt.Errorf("config: diameter.peers[%d].transport must be tcp or sctp", i)
		}
	}
	if cfg.S13.FailurePolicy != "allow" && cfg.S13.FailurePolicy != "reject" {
		return nil, fmt.Errorf("config: s13.failure_policy must be allow or reject")
	}
	for name, value := range map[string]string{
		"whitelist_policy": cfg.S13.WhitelistPolicy,
		"blacklist_policy": cfg.S13.BlacklistPolicy,
		"greylist_policy":  cfg.S13.GreylistPolicy,
	} {
		if value != "allow" && value != "reject" {
			return nil, fmt.Errorf("config: s13.%s must be allow or reject", name)
		}
	}
	if cfg.S13.Timeout <= 0 {
		return nil, fmt.Errorf("config: s13.timeout must be greater than 0")
	}
	if cfg.S6a.AIR.RequestedVectors == 0 {
		return nil, fmt.Errorf("config: s6a.air.requested_vectors must be greater than 0")
	}
	if cfg.Operator.Name.Encoding == "" {
		cfg.Operator.Name.Encoding = "gsm7"
	}
	if cfg.NAS.Timers.T3412 <= 0 {
		return nil, fmt.Errorf("config: nas.timers.t3412 must be greater than 0")
	}
	if _, err := nastimer.EncodeGPRSTimer(cfg.NAS.Timers.T3412); err != nil {
		return nil, fmt.Errorf("config: nas.timers.t3412: %w", err)
	}
	if cfg.NAS.Timers.T3402 > 0 {
		if _, err := nastimer.EncodeGPRSTimer(cfg.NAS.Timers.T3402); err != nil {
			return nil, fmt.Errorf("config: nas.timers.t3402: %w", err)
		}
	}
	if cfg.NAS.Timers.T3423 > 0 {
		if _, err := nastimer.EncodeGPRSTimer(cfg.NAS.Timers.T3423); err != nil {
			return nil, fmt.Errorf("config: nas.timers.t3423: %w", err)
		}
	}
	if cfg.NAS.Timers.T3396 > 0 {
		if _, err := nastimer.EncodeGPRSTimer3(cfg.NAS.Timers.T3396); err != nil {
			return nil, fmt.Errorf("config: nas.timers.t3396: %w", err)
		}
	}
	switch cfg.Operator.Name.Encoding {
	case "gsm7", "ucs2":
	default:
		return nil, fmt.Errorf("config: operator.name.encoding must be \"gsm7\" or \"ucs2\", got %q", cfg.Operator.Name.Encoding)
	}
	if cfg.Operator.NITZ.Enabled {
		if !cfg.Operator.NITZ.IncludeLocalTimeZone &&
			!cfg.Operator.NITZ.IncludeUniversalTimeAndLocalTimeZone &&
			!cfg.Operator.NITZ.IncludeDaylightSavingTime {
			cfg.Operator.NITZ.IncludeLocalTimeZone = true
			cfg.Operator.NITZ.IncludeUniversalTimeAndLocalTimeZone = true
			cfg.Operator.NITZ.IncludeDaylightSavingTime = true
		}
		if cfg.Operator.NITZ.Timezone != "" {
			if _, err := time.LoadLocation(cfg.Operator.NITZ.Timezone); err != nil {
				return nil, fmt.Errorf("config: operator.nitz.timezone %q: %w", cfg.Operator.NITZ.Timezone, err)
			}
		}
	}

	return cfg, nil
}
