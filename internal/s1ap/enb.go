package s1ap

import (
	"sync"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

// ENBContext holds per-eNB S1AP state.
type ENBContext struct {
	mu            sync.Mutex
	GlobalENBID   ies.GlobalENBID
	ENBName       string
	SupportedTAs  []SupportedTA
	RemoteAddr    string
	SetupComplete bool
}

// SupportedTA represents a Tracking Area supported by an eNB.
type SupportedTA struct {
	TAC            uint16
	BroadcastPLMNs []BroadcastPLMN
}

// BroadcastPLMN is a PLMN broadcast in a TA.
type BroadcastPLMN struct {
	MCC string
	MNC string
}
