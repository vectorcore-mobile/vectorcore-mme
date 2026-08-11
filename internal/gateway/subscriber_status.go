package gateway

// SubscriberStatus mirrors the S6a Subscriber-Status AVP (TS 29.272 §7.3.29).
type SubscriberStatus int32

const (
	SubscriberStatusServiceGranted            SubscriberStatus = 0
	SubscriberStatusOperatorDeterminedBarring SubscriberStatus = 1
)

// Barred reports whether the HSS has withdrawn service from this subscriber
// (TS 24.301 §5.5.1.2.5: the MME shall reject Attach with a combined
// ATTACH REJECT / PDN CONNECTIVITY REJECT when this is set).
func (s SubscriberStatus) Barred() bool { return s == SubscriberStatusOperatorDeterminedBarring }

// OperatorDeterminedBarring mirrors the S6a Operator-Determined-Barring AVP
// (TS 29.272 §7.3.30) — a bitmask of specific barred services. Only bit 0 is
// EPS-relevant; the remaining bits are legacy CS-domain call-barring
// categories this MME has no use for.
type OperatorDeterminedBarring uint32

const ODBAllPacketOrientedServicesBarred OperatorDeterminedBarring = 1 << 0

// AllPacketOrientedServicesBarred reports bit 0.
func (o OperatorDeterminedBarring) AllPacketOrientedServicesBarred() bool {
	return o&ODBAllPacketOrientedServicesBarred != 0
}
