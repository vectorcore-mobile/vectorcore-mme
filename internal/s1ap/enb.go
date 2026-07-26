package s1ap

import (
	"sync"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

// ENBContext holds per-eNB S1AP state.
type ENBContext struct {
	mu          sync.Mutex
	GlobalENBID ies.GlobalENBID
	ENBName     string
	// SupportedTAs is the complete topology advertised by the eNB. AcceptedTAs
	// is the exact PLMN+TAC subset served by this MME and is used for local
	// paging/PWS routing admission.
	SupportedTAs  []SupportedTA
	AcceptedTAs   []SupportedTA
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
