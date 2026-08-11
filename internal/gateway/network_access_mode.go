package gateway

// NetworkAccessMode mirrors the S6a Network-Access-Mode AVP (code 1417,
// 3GPP TS 29.272 §7.3.21).
type NetworkAccessMode int32

const (
	NAMPacketAndCircuit NetworkAccessMode = 0
	NAMOnlyPacket       NetworkAccessMode = 2 // value 1 is reserved
)

// PSOnly reports whether the subscriber has no CS subscription at all
// (TS 23.272 Annex C.8.1: "For a PS-only subscription... the MME shall not
// establish any SGs association").
func (n NetworkAccessMode) PSOnly() bool { return n == NAMOnlyPacket }
