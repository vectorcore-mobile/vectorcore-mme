package models

import "time"

const (
	RecoveryStateActiveSnapshot      = "ACTIVE_SNAPSHOT"
	RecoveryStateStaleAfterRestart   = "STALE_AFTER_RESTART"
	RecoveryStateReturnedForRecovery = "RETURNED_FOR_RECOVERY"
	RecoveryStateRecovered           = "RECOVERED"
	RecoveryStateDetached            = "DETACHED"
	RecoveryStateDisconnected        = "DISCONNECTED"
	RecoveryStateExpired             = "EXPIRED"
	RecoveryStateCleanedUp           = "CLEANED_UP"
)

// UERecoveryRecord stores last-known UE identity and recovery metadata.
// It is not authoritative live UE state; the in-memory UE manager owns that.
type UERecoveryRecord struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	IMSI         string `gorm:"column:imsi;size:15;uniqueIndex;not null" json:"imsi"`
	IMEISV       string `gorm:"column:imeisv;size:16" json:"imeisv,omitempty"`
	MSISDN       string `gorm:"column:msisdn;size:20" json:"msisdn,omitempty"`
	CallID       uint32 `gorm:"column:call_id;index" json:"call_id,omitempty"`
	ContextID    uint32 `gorm:"column:context_id;index" json:"context_id,omitempty"`
	MMEInstance  string `gorm:"column:mme_instance_id;size:255;index" json:"mme_instance_id,omitempty"`
	RestartEpoch string `gorm:"column:restart_epoch;size:64;index" json:"restart_epoch,omitempty"`

	CurrentGUTI             string `gorm:"column:current_guti;size:64;index" json:"current_guti,omitempty"`
	GUTIMCC                 string `gorm:"column:guti_mcc;size:3" json:"guti_mcc,omitempty"`
	GUTIMNC                 string `gorm:"column:guti_mnc;size:3" json:"guti_mnc,omitempty"`
	GUTIMMEGID              uint16 `gorm:"column:guti_mme_gid" json:"guti_mme_gid,omitempty"`
	GUTIMMECode             uint8  `gorm:"column:guti_mme_code" json:"guti_mme_code,omitempty"`
	GUTIMTMSI               uint32 `gorm:"column:guti_m_tmsi" json:"guti_m_tmsi,omitempty"`
	OldGUTI                 string `gorm:"column:old_guti;size:64;index" json:"old_guti,omitempty"`
	OldGUTIMCC              string `gorm:"column:old_guti_mcc;size:3" json:"old_guti_mcc,omitempty"`
	OldGUTIMNC              string `gorm:"column:old_guti_mnc;size:3" json:"old_guti_mnc,omitempty"`
	OldGUTIMMEGID           uint16 `gorm:"column:old_guti_mme_gid" json:"old_guti_mme_gid,omitempty"`
	OldGUTIMMECode          uint8  `gorm:"column:old_guti_mme_code" json:"old_guti_mme_code,omitempty"`
	OldGUTIMTMSI            uint32 `gorm:"column:old_guti_m_tmsi" json:"old_guti_m_tmsi,omitempty"`
	ReallocatedGUTI         string `gorm:"column:reallocated_guti;size:64;index" json:"reallocated_guti,omitempty"`
	ReallocGUTIMCC          string `gorm:"column:reallocated_guti_mcc;size:3" json:"reallocated_guti_mcc,omitempty"`
	ReallocGUTIMNC          string `gorm:"column:reallocated_guti_mnc;size:3" json:"reallocated_guti_mnc,omitempty"`
	ReallocGUTIMMEGID       uint16 `gorm:"column:reallocated_guti_mme_gid" json:"reallocated_guti_mme_gid,omitempty"`
	ReallocGUTIMMECode      uint8  `gorm:"column:reallocated_guti_mme_code" json:"reallocated_guti_mme_code,omitempty"`
	ReallocGUTIMTMSI        uint32 `gorm:"column:reallocated_guti_m_tmsi" json:"reallocated_guti_m_tmsi,omitempty"`
	GUTIReallocationPending bool   `gorm:"column:guti_reallocation_pending" json:"guti_reallocation_pending"`

	LastEMMState  string `gorm:"column:last_emm_state;size:64" json:"last_emm_state,omitempty"`
	LastECMState  string `gorm:"column:last_ecm_state;size:64" json:"last_ecm_state,omitempty"`
	RecoveryState string `gorm:"column:recovery_state;size:64;index" json:"recovery_state"`

	NASIntegrityAlg  uint8  `gorm:"column:nas_integrity_alg" json:"nas_integrity_alg,omitempty"`
	NASCipheringAlg  uint8  `gorm:"column:nas_ciphering_alg" json:"nas_ciphering_alg,omitempty"`
	UplinkNASCount   uint32 `gorm:"column:uplink_nas_count" json:"uplink_nas_count,omitempty"`
	DownlinkNASCount uint32 `gorm:"column:downlink_nas_count" json:"downlink_nas_count,omitempty"`
	KASME            []byte `gorm:"column:kasme;size:32" json:"-"`

	TAIMCC string `gorm:"column:tai_mcc;size:3" json:"tai_mcc,omitempty"`
	TAIMNC string `gorm:"column:tai_mnc;size:3" json:"tai_mnc,omitempty"`
	TAC    uint16 `gorm:"column:tac" json:"tac,omitempty"`
	ECGI   string `gorm:"column:ecgi;size:32" json:"ecgi,omitempty"`
	ENBID  string `gorm:"column:enb_id;size:64" json:"enb_id,omitempty"`

	AttachedAt *time.Time `gorm:"column:attached_at" json:"attached_at,omitempty"`
	LastSeenAt *time.Time `gorm:"column:last_seen_at" json:"last_seen_at,omitempty"`
	StaleAt    *time.Time `gorm:"column:stale_at" json:"stale_at,omitempty"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at" json:"updated_at"`
}

func (UERecoveryRecord) TableName() string { return "mme_ue_recovery_records" }

// SessionRecoveryRecord stores last-known EPS session metadata for stale cleanup.
type SessionRecoveryRecord struct {
	ID                uint       `gorm:"primaryKey" json:"id"`
	IMSI              string     `gorm:"column:imsi;size:15;index;uniqueIndex:idx_session_imsi_apn;not null" json:"imsi"`
	CallID            uint32     `gorm:"column:call_id;index" json:"call_id,omitempty"`
	ContextID         uint32     `gorm:"column:context_id;index" json:"context_id,omitempty"`
	MMEInstance       string     `gorm:"column:mme_instance_id;size:255;index" json:"mme_instance_id,omitempty"`
	RestartEpoch      string     `gorm:"column:restart_epoch;size:64;index" json:"restart_epoch,omitempty"`
	APN               string     `gorm:"column:apn;size:100;uniqueIndex:idx_session_imsi_apn" json:"apn,omitempty"`
	PDNType           string     `gorm:"column:pdn_type;size:32" json:"pdn_type,omitempty"`
	UEIPv4            string     `gorm:"column:ue_ipv4;size:15" json:"ue_ipv4,omitempty"`
	UEIPv6            string     `gorm:"column:ue_ipv6;size:39" json:"ue_ipv6,omitempty"`
	DefaultEBI        uint8      `gorm:"column:default_ebi" json:"default_ebi,omitempty"`
	LinkedEBI         uint8      `gorm:"column:linked_ebi" json:"linked_ebi,omitempty"`
	BearerSummaryJSON string     `gorm:"column:bearer_summary_json;type:jsonb" json:"bearer_summary_json,omitempty"`
	MMES11TEID        uint32     `gorm:"column:mme_s11_teid" json:"mme_s11_teid,omitempty"`
	SGWS11TEID        uint32     `gorm:"column:sgw_s11_teid" json:"sgw_s11_teid,omitempty"`
	SGWS11IP          string     `gorm:"column:sgw_s11_ip;size:39" json:"sgw_s11_ip,omitempty"`
	PGWIP             string     `gorm:"column:pgw_ip;size:39" json:"pgw_ip,omitempty"`
	PGWTEID           uint32     `gorm:"column:pgw_teid" json:"pgw_teid,omitempty"`
	PGWFQDN           string     `gorm:"column:pgw_fqdn;size:255" json:"pgw_fqdn,omitempty"`
	SessionState      string     `gorm:"column:session_state;size:64" json:"session_state,omitempty"`
	RecoveryState     string     `gorm:"column:recovery_state;size:64;index" json:"recovery_state"`
	CreatedAt         time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"column:updated_at" json:"updated_at"`
	StaleAt           *time.Time `gorm:"column:stale_at" json:"stale_at,omitempty"`
	CleanedAt         *time.Time `gorm:"column:cleaned_at" json:"cleaned_at,omitempty"`
}

func (SessionRecoveryRecord) TableName() string { return "mme_session_recovery_records" }

// RecoveryEvent is an audit trail for restart and stale-session cleanup events.
type RecoveryEvent struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	EventType    string    `gorm:"column:event_type;size:80;index" json:"event_type"`
	IMSI         string    `gorm:"column:imsi;size:15;index" json:"imsi,omitempty"`
	GUTI         string    `gorm:"column:guti;size:64;index" json:"guti,omitempty"`
	CallID       uint32    `gorm:"column:call_id;index" json:"call_id,omitempty"`
	MMEInstance  string    `gorm:"column:mme_instance_id;size:255;index" json:"mme_instance_id,omitempty"`
	RestartEpoch string    `gorm:"column:restart_epoch;size:64;index" json:"restart_epoch,omitempty"`
	Message      string    `gorm:"column:message;type:text" json:"message,omitempty"`
	MetadataJSON string    `gorm:"column:metadata_json;type:jsonb" json:"metadata_json,omitempty"`
	CreatedAt    time.Time `gorm:"column:created_at" json:"created_at"`
}

func (RecoveryEvent) TableName() string { return "mme_recovery_events" }

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
		&UERecoveryRecord{},
		&SessionRecoveryRecord{},
		&RecoveryEvent{},
		&ENBRegistration{},
	}
}
