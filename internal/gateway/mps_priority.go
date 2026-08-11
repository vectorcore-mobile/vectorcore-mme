package gateway

// MPSPriority mirrors the S6a MPS-Priority AVP (TS 29.272 §7.3.131) — a
// bitmask indicating Multimedia Priority Service subscription. Decoded and
// stored only; no enforcement mechanism exists in this MME yet (see
// docs/specs research: it doesn't plug into EPSNetworkFeatureSupport, and
// the two mechanisms TS 23.401/24.301 tie it to — RRC Establishment Cause
// priority handling and NAS congestion-control exemption — aren't
// implemented here).
type MPSPriority uint32

const (
	MPSPriorityCSBit        MPSPriority = 1 << 0
	MPSPriorityEPSBit       MPSPriority = 1 << 1
	MPSPriorityMessagingBit MPSPriority = 1 << 2
)

func (m MPSPriority) MPSCSPriority() bool   { return m&MPSPriorityCSBit != 0 }
func (m MPSPriority) MPSEPSPriority() bool  { return m&MPSPriorityEPSBit != 0 }
func (m MPSPriority) MPSForMessaging() bool { return m&MPSPriorityMessagingBit != 0 }
