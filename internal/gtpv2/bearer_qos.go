package gtpv2

import "fmt"

// BearerQoS describes a decoded GTPv2 Bearer Level QoS IE.
// Bitrate fields are stored in the raw on-wire units carried by GTPv2.
type BearerQoS struct {
	PriorityLevel           uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	QCI                     uint8
	UplinkMBR               uint64
	DownlinkMBR             uint64
	UplinkGBR               uint64
	DownlinkGBR             uint64
}

// ParseBearerQoS decodes the 22-byte GTPv2 Bearer Level QoS IE payload.
func ParseBearerQoS(raw []byte) (*BearerQoS, error) {
	if len(raw) < 22 {
		return nil, fmt.Errorf("gtpv2: bearer qos too short: %d", len(raw))
	}
	flags := raw[0]
	out := &BearerQoS{
		PriorityLevel:           (flags >> 2) & 0x0f,
		PreemptionCapability:    flags&0x40 != 0,
		PreemptionVulnerability: flags&0x01 != 0,
		QCI:                     raw[1],
		UplinkMBR:               decodeBearerQoSBitrate(raw[2:7]),
		DownlinkMBR:             decodeBearerQoSBitrate(raw[7:12]),
		UplinkGBR:               decodeBearerQoSBitrate(raw[12:17]),
		DownlinkGBR:             decodeBearerQoSBitrate(raw[17:22]),
	}
	return out, nil
}

func decodeBearerQoSBitrate(raw []byte) uint64 {
	var out uint64
	for _, octet := range raw {
		out = (out << 8) | uint64(octet)
	}
	// TS 29.274 Bearer QoS uses a 5-octet binary value in kilobits per second.
	return out * 1000
}
