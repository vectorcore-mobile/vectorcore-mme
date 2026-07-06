package models

// UEContext stores the active EMM context for an attached UE.
// One row per attached UE; survives MME restart.
type UEContext struct {
	MMEUES1APID uint32  `gorm:"column:mme_ue_s1ap_id;primaryKey"              json:"mme_ue_s1ap_id"`
	IMSI        string  `gorm:"column:imsi;size:15;uniqueIndex;not null"       json:"imsi"`
	GUTI        *string `gorm:"column:guti;size:40;uniqueIndex"               json:"guti,omitempty"`
	EMMState    string  `gorm:"column:emm_state;size:40;not null"             json:"emm_state"`
	KASME       []byte  `gorm:"column:kasme;size:32"                          json:"-"`
	KNASint     []byte  `gorm:"column:knas_int;size:16"                       json:"-"`
	KNASenc     []byte  `gorm:"column:knas_enc;size:16"                       json:"-"`
	ULNASCount  uint32  `gorm:"column:ul_nas_count"                           json:"ul_nas_count"`
	DLNASCount  uint32  `gorm:"column:dl_nas_count"                           json:"dl_nas_count"`
	IntAlg      uint8   `gorm:"column:int_alg"                                json:"int_alg"`
	EncAlg      uint8   `gorm:"column:enc_alg"                                json:"enc_alg"`
	ENBS1APID   uint32  `gorm:"column:enb_s1ap_id"                            json:"enb_s1ap_id"`
	ENBGlobalID string  `gorm:"column:enb_global_id;type:text"               json:"enb_global_id,omitempty"`
	TAI         string  `gorm:"column:tai;size:16"                            json:"tai,omitempty"`
	MSISDN      *string `gorm:"column:msisdn;size:15"                         json:"msisdn,omitempty"`
	APN         *string `gorm:"column:apn;size:100"                           json:"apn,omitempty"`
	// Default EPS bearer fields (populated after S11 CSRsp / ICS Response)
	DefaultEBI uint32 `gorm:"column:default_ebi"                            json:"default_ebi,omitempty"`
	UEIPv4     string `gorm:"column:ue_ipv4;size:15"                        json:"ue_ipv4,omitempty"`
	SGWU_TEID  uint32 `gorm:"column:sgw_u_teid"                             json:"sgw_u_teid,omitempty"`
	SGWU_IP    string `gorm:"column:sgw_u_ip;size:39"                       json:"sgw_u_ip,omitempty"`
	SGWC_TEID  uint32 `gorm:"column:sgw_c_teid"                             json:"sgw_c_teid,omitempty"`
	SGWC_IP    string `gorm:"column:sgw_c_ip;size:39"                       json:"sgw_c_ip,omitempty"`
	ENBU_TEID  uint32 `gorm:"column:enb_u_teid"                             json:"enb_u_teid,omitempty"`
	ENBU_IP    string `gorm:"column:enb_u_ip;size:39"                       json:"enb_u_ip,omitempty"`
	// Handover security state (TS 33.401 §7.2.8)
	NH           []byte  `gorm:"column:nh;type:bytea"                         json:"-"`
	NCC          uint8   `gorm:"column:ncc"                                   json:"ncc,omitempty"`
	LastModified string  `gorm:"column:last_modified;size:100"                json:"last_modified,omitempty"`
}

func (UEContext) TableName() string { return "ue_contexts" }

// ENBRegistration tracks eNodeBs that have completed S1 Setup.
type ENBRegistration struct {
	GlobalENBID  string `gorm:"column:global_enb_id;primaryKey;size:64"       json:"global_enb_id"`
	ENBName      string `gorm:"column:enb_name;size:150"                     json:"enb_name,omitempty"`
	SupportedTAs string `gorm:"column:supported_tas;type:jsonb"              json:"supported_tas,omitempty"`
	RemoteAddr   string `gorm:"column:remote_addr;type:text"                 json:"remote_addr,omitempty"`
	LastSeen     string `gorm:"column:last_seen;size:100"                    json:"last_seen,omitempty"`
	LastModified string `gorm:"column:last_modified;size:100"                json:"last_modified,omitempty"`
}

func (ENBRegistration) TableName() string { return "enb_registrations" }

// AllModels returns every model for db.AutoMigrate.
func AllModels() []interface{} {
	return []interface{}{
		&UEContext{},
		&ENBRegistration{},
	}
}
