package gtpv2

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// IE represents a single GTPv2-C Information Element (TS 29.274 §8.1).
// Wire format: [type:1][length:2][instance:1][value:N]
type IE struct {
	Type     uint8
	Instance uint8
	Value    []byte
}

// EncodeIEs serialises a slice of IEs into wire format.
func EncodeIEs(ies []IE) []byte {
	var buf []byte
	for _, ie := range ies {
		hdr := make([]byte, 4)
		hdr[0] = ie.Type
		binary.BigEndian.PutUint16(hdr[1:3], uint16(len(ie.Value)))
		hdr[3] = ie.Instance & 0x0F
		buf = append(buf, hdr...)
		buf = append(buf, ie.Value...)
	}
	return buf
}

// DecodeIEs parses the IE section of a GTPv2-C message body.
func DecodeIEs(b []byte) ([]IE, error) {
	var ies []IE
	for len(b) >= 4 {
		ieType := b[0]
		length := binary.BigEndian.Uint16(b[1:3])
		instance := b[3] & 0x0F
		b = b[4:]
		if int(length) > len(b) {
			return nil, fmt.Errorf("gtpv2: IE type %d length %d exceeds remaining %d bytes", ieType, length, len(b))
		}
		val := make([]byte, length)
		copy(val, b[:length])
		ies = append(ies, IE{Type: ieType, Instance: instance, Value: val})
		b = b[length:]
	}
	return ies, nil
}

// FindIE returns the first IE with the given type and instance, or nil.
func FindIE(ies []IE, ieType, instance uint8) *IE {
	for i := range ies {
		if ies[i].Type == ieType && ies[i].Instance == instance {
			return &ies[i]
		}
	}
	return nil
}

// FindGroupedIEs parses the value of a grouped IE (e.g. Bearer Context) as a sub-list.
func FindGroupedIEs(ie *IE) ([]IE, error) {
	return DecodeIEs(ie.Value)
}

// --- Per-IE encoders ---

// EncodeIMSI encodes an IMSI string (digits) as BCD with an F filler nibble if odd length.
func EncodeIMSI(imsi string) IE {
	bcd := bcdEncode(imsi)
	return IE{Type: IETypeIMSI, Instance: 0, Value: bcd}
}

// EncodeMSISDN encodes an MSISDN as BCD (international format, no leading +).
// Per TS 29.274 §8.3 and TS 29.002 §17.7.8, the value begins with a TON/NPI
// byte (0x91 = international, ISDN/E.164) followed by the BCD-encoded digits.
func EncodeMSISDN(msisdn string) IE {
	bcd := bcdEncode(msisdn)
	val := make([]byte, 1+len(bcd))
	val[0] = 0x91 // TON=international, NPI=ISDN/E.164
	copy(val[1:], bcd)
	return IE{Type: IETypeMSISDN, Instance: 0, Value: val}
}

// EncodeRATType encodes the RAT-Type IE.
func EncodeRATType(rat uint8) IE {
	return IE{Type: IETypeRATType, Instance: 0, Value: []byte{rat}}
}

// EncodeServingNetwork encodes the Serving Network IE (3-byte PLMN BCD: MCC+MNC TS 24.008 §10.5.1.13).
func EncodeServingNetwork(plmn [3]byte) IE {
	return IE{Type: IETypeServingNetwork, Instance: 0, Value: plmn[:]}
}

// EncodeAPN encodes the APN IE as DNS label format (TS 29.274 §8.6 → TS 23.003 §9.1).
func EncodeAPN(apn string) IE {
	val := encodeDNSLabels(apn)
	return IE{Type: IETypeAPN, Instance: 0, Value: val}
}

// EncodePDNType encodes the PDN Type IE.
func EncodePDNType(t uint8) IE {
	return IE{Type: IETypePDNType, Instance: 0, Value: []byte{t & 0x07}}
}

// EncodePAA encodes the PDN Address Allocation IE for an IPv4 address.
func EncodePAA(ip net.IP) IE {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IP{0, 0, 0, 0}
	}
	val := make([]byte, 5)
	val[0] = PDNTypeIPv4
	copy(val[1:], v4)
	return IE{Type: IETypePAA, Instance: 0, Value: val}
}

// DecodePAA extracts the IPv4 address from a PAA IE.
func DecodePAA(ie *IE) (net.IP, error) {
	if ie == nil || len(ie.Value) < 1 {
		return nil, fmt.Errorf("gtpv2: nil or empty PAA IE")
	}
	pdnType := ie.Value[0] & 0x07
	switch pdnType {
	case PDNTypeIPv4:
		if len(ie.Value) < 5 {
			return nil, fmt.Errorf("gtpv2: PAA IPv4 too short (%d bytes)", len(ie.Value))
		}
		return net.IP(ie.Value[1:5]).To4(), nil
	default:
		return nil, fmt.Errorf("gtpv2: unsupported PDN type %d in PAA", pdnType)
	}
}

// EncodeAMBR encodes the Aggregate Maximum Bit Rate IE (TS 29.274 §8.7).
func EncodeAMBR(ulKbps, dlKbps uint32) IE {
	val := make([]byte, 8)
	binary.BigEndian.PutUint32(val[0:4], ulKbps)
	binary.BigEndian.PutUint32(val[4:8], dlKbps)
	return IE{Type: IETypeAMBR, Instance: 0, Value: val}
}

// EncodeEBI encodes the EPS Bearer ID IE.
func EncodeEBI(ebi uint8, instance uint8) IE {
	return IE{Type: IETypeEBI, Instance: instance, Value: []byte{ebi & 0x0F}}
}

// DecodeEBI extracts the EBI value from an EBI IE.
func DecodeEBI(ie *IE) (uint8, error) {
	if ie == nil || len(ie.Value) < 1 {
		return 0, fmt.Errorf("gtpv2: nil or empty EBI IE")
	}
	return ie.Value[0] & 0x0F, nil
}

// EncodeBearerQoS encodes the Bearer QoS IE (TS 29.274 §8.15).
// pci=0 (may be pre-empted), pl=8 (priority), pvi=1 (pre-emptable), qci=9.
// MBR and GBR are all zero (non-GBR bearer).
func EncodeBearerQoS(qci, pl uint8, pci, pvi bool) IE {
	val := make([]byte, 22)
	// byte 0: PCI[6], PL[5:2], PVI[0]
	var b0 uint8
	if pci {
		b0 |= 0x40
	}
	b0 |= (pl & 0x0F) << 2
	if pvi {
		b0 |= 0x01
	}
	val[0] = b0
	val[1] = qci
	// bytes 2-9: MBR UL/DL = 0
	// bytes 10-21: GBR UL/DL = 0
	return IE{Type: IETypeBearerQoS, Instance: 0, Value: val}
}

// FTEID holds a decoded F-TEID.
type FTEID struct {
	InterfaceType uint8
	TEID          uint32
	IP            net.IP // IPv4 only in this implementation
}

// EncodeFTEID encodes an F-TEID IE (TS 29.274 §8.22). IPv4 only.
// flags byte = 0x80 | (ifaceType & 0x3F)
func EncodeFTEID(ifaceType uint8, teid uint32, ip net.IP, instance uint8) IE {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IP{0, 0, 0, 0}
	}
	val := make([]byte, 9)
	val[0] = 0x80 | (ifaceType & 0x3F) // V4=1, V6=0
	binary.BigEndian.PutUint32(val[1:5], teid)
	copy(val[5:9], v4)
	return IE{Type: IETypeFTEID, Instance: instance, Value: val}
}

// DecodeFTEID parses an F-TEID IE.
func DecodeFTEID(ie *IE) (*FTEID, error) {
	if ie == nil || len(ie.Value) < 5 {
		return nil, fmt.Errorf("gtpv2: nil or short FTEID IE")
	}
	flags := ie.Value[0]
	ifaceType := flags & 0x3F
	v4bit := (flags >> 7) & 0x01
	teid := binary.BigEndian.Uint32(ie.Value[1:5])
	var ip net.IP
	if v4bit == 1 {
		if len(ie.Value) < 9 {
			return nil, fmt.Errorf("gtpv2: FTEID too short for IPv4 (%d)", len(ie.Value))
		}
		ip = make(net.IP, 4)
		copy(ip, ie.Value[5:9])
	}
	return &FTEID{InterfaceType: ifaceType, TEID: teid, IP: ip}, nil
}

// EncodeSelectionMode encodes the Selection Mode IE.
func EncodeSelectionMode(mode uint8) IE {
	return IE{Type: IETypeSelectionMode, Instance: 0, Value: []byte{mode & 0x03}}
}

// EncodeCause encodes a Cause IE.
func EncodeCause(cause uint8) IE {
	// 4 bytes: cause[0], flags[1]=0, offending IE type[2]=0, offending IE instance[3]=0
	return IE{Type: IETypeCause, Instance: 0, Value: []byte{cause, 0, 0, 0}}
}

// DecodeCause extracts the cause value from a Cause IE.
func DecodeCause(ie *IE) (uint8, error) {
	if ie == nil || len(ie.Value) < 1 {
		return 0, fmt.Errorf("gtpv2: nil or empty Cause IE")
	}
	return ie.Value[0], nil
}

// EncodeULI encodes a User Location Information IE with TAI + ECGI (TS 29.274 §8.21).
// plmn is the 3-byte PLMN BCD; tac is the 2-byte TAC; eci is the 28-bit E-UTRAN Cell Identity.
func EncodeULI(plmn [3]byte, tac uint16, eci uint32) IE {
	// flags: TAI(bit4=0x08) + ECGI(bit5=0x10)
	val := make([]byte, 1+5+7)
	val[0] = ULIFlagTAI | ULIFlagECGI
	// TAI: PLMN(3) + TAC(2)
	copy(val[1:4], plmn[:])
	val[4] = byte(tac >> 8)
	val[5] = byte(tac)
	// ECGI: PLMN(3) + spare(4bits)+ECI(28bits in 4 bytes)
	copy(val[6:9], plmn[:])
	val[9] = byte(eci >> 24 & 0x0F) // spare=0, top 4 bits of ECI
	val[10] = byte(eci >> 16)
	val[11] = byte(eci >> 8)
	val[12] = byte(eci)
	return IE{Type: IETypeULI, Instance: 0, Value: val}
}

// EncodeGrouped wraps a list of IEs into a grouped IE value (for Bearer Context).
func EncodeGrouped(ieType uint8, instance uint8, grouped []IE) IE {
	return IE{Type: ieType, Instance: instance, Value: EncodeIEs(grouped)}
}

// --- S10 inter-MME context transfer types and helpers ---

// MMContextParams holds the EPS security context transferred over S10.
type MMContextParams struct {
	IntAlg     uint8
	EncAlg     uint8
	NCC        uint8
	ULNASCount uint32
	DLNASCount uint32
	KASME      []byte // 32 bytes
	NH         []byte // 32 bytes; nil/empty decoded as zeros
	MSISDN     string
	APN        string
}

// PDNParams holds the default bearer state transferred over S10.
type PDNParams struct {
	EBI        uint8
	SGWC_FTEID FTEID // S11 SGW C-plane
	SGWU_FTEID FTEID // S1-U SGW U-plane
	ENBU_FTEID FTEID // S1-U eNB U-plane
	UEIPv4     net.IP
	APN        string
}

// EncodeMMContext encodes an MM Context IE (type 107) using VectorCore's LTE-only blob:
//
//	[0]=0x01 marker, [1]=IntAlg, [2]=EncAlg, [3]=NCC,
//	[4:8]=ULCount BE, [8:12]=DLCount BE, [12:44]=KASME, [44:76]=NH,
//	[76]=len(MSISDN), [77..]=MSISDN, then APN DNS-label encoded.
func EncodeMMContext(p MMContextParams) IE {
	kasme := make([]byte, 32)
	copy(kasme, p.KASME)
	nh := make([]byte, 32)
	copy(nh, p.NH)

	msisdn := []byte(p.MSISDN)
	apnEnc := encodeDNSLabels(p.APN)

	val := make([]byte, 77+len(msisdn)+len(apnEnc))
	val[0] = 0x01
	val[1] = p.IntAlg
	val[2] = p.EncAlg
	val[3] = p.NCC
	binary.BigEndian.PutUint32(val[4:8], p.ULNASCount)
	binary.BigEndian.PutUint32(val[8:12], p.DLNASCount)
	copy(val[12:44], kasme)
	copy(val[44:76], nh)
	val[76] = uint8(len(msisdn))
	copy(val[77:], msisdn)
	copy(val[77+len(msisdn):], apnEnc)
	return IE{Type: IETypeMMContext, Instance: 0, Value: val}
}

// DecodeMMContext decodes an MM Context IE (type 107).
func DecodeMMContext(ie *IE) (*MMContextParams, error) {
	if ie == nil {
		return nil, fmt.Errorf("gtpv2: nil MMContext IE")
	}
	v := ie.Value
	if len(v) < 77 {
		return nil, fmt.Errorf("gtpv2: MMContext IE too short (%d bytes)", len(v))
	}
	if v[0] != 0x01 {
		return nil, fmt.Errorf("gtpv2: MMContext unknown marker 0x%02x", v[0])
	}
	p := &MMContextParams{
		IntAlg:     v[1],
		EncAlg:     v[2],
		NCC:        v[3],
		ULNASCount: binary.BigEndian.Uint32(v[4:8]),
		DLNASCount: binary.BigEndian.Uint32(v[8:12]),
		KASME:      make([]byte, 32),
		NH:         make([]byte, 32),
	}
	copy(p.KASME, v[12:44])
	copy(p.NH, v[44:76])
	msisdnLen := int(v[76])
	off := 77
	if off+msisdnLen > len(v) {
		return nil, fmt.Errorf("gtpv2: MMContext MSISDN overflow (%d+%d > %d)", off, msisdnLen, len(v))
	}
	if msisdnLen > 0 {
		p.MSISDN = string(v[off : off+msisdnLen])
	}
	off += msisdnLen
	if off < len(v) {
		p.APN = decodeDNSLabels(v[off:])
	}
	return p, nil
}

// EncodePDNConnection encodes a PDN Connection grouped IE (type 109) containing
// EBI, SGW C-plane F-TEID, SGW U-plane F-TEID, eNB U-plane F-TEID, PAA, APN.
func EncodePDNConnection(p PDNParams) IE {
	children := []IE{
		EncodeEBI(p.EBI, 0),
		EncodeFTEID(IFTypeS11S4SGW, p.SGWC_FTEID.TEID, p.SGWC_FTEID.IP, 0),
		EncodeFTEID(IFTypeS1USGW, p.SGWU_FTEID.TEID, p.SGWU_FTEID.IP, 1),
		EncodeFTEID(IFTypeS1UENB, p.ENBU_FTEID.TEID, p.ENBU_FTEID.IP, 2),
		EncodePAA(p.UEIPv4),
		EncodeAPN(p.APN),
	}
	return EncodeGrouped(IETypePDNConnection, 0, children)
}

// DecodePDNConnection decodes a PDN Connection grouped IE (type 109).
func DecodePDNConnection(ie *IE) (*PDNParams, error) {
	if ie == nil {
		return nil, fmt.Errorf("gtpv2: nil PDNConnection IE")
	}
	children, err := FindGroupedIEs(ie)
	if err != nil {
		return nil, fmt.Errorf("gtpv2: decode PDNConnection grouped: %w", err)
	}
	p := &PDNParams{}
	if ebiIE := FindIE(children, IETypeEBI, 0); ebiIE != nil {
		p.EBI, _ = DecodeEBI(ebiIE)
	}
	if fteid := FindIE(children, IETypeFTEID, 0); fteid != nil {
		if f, e := DecodeFTEID(fteid); e == nil {
			p.SGWC_FTEID = *f
		}
	}
	if fteid := FindIE(children, IETypeFTEID, 1); fteid != nil {
		if f, e := DecodeFTEID(fteid); e == nil {
			p.SGWU_FTEID = *f
		}
	}
	if fteid := FindIE(children, IETypeFTEID, 2); fteid != nil {
		if f, e := DecodeFTEID(fteid); e == nil {
			p.ENBU_FTEID = *f
		}
	}
	if paaIE := FindIE(children, IETypePAA, 0); paaIE != nil {
		if ip, e := DecodePAA(paaIE); e == nil {
			p.UEIPv4 = ip
		}
	}
	if apnIE := FindIE(children, IETypeAPN, 0); apnIE != nil {
		p.APN = decodeDNSLabels(apnIE.Value)
	}
	return p, nil
}

// EncodeCompleteRequestMsg encodes a Complete Request Message IE (type 116).
// The value is the raw NAS PDU bytes (e.g., a TAU Request).
func EncodeCompleteRequestMsg(data []byte) IE {
	v := make([]byte, len(data))
	copy(v, data)
	return IE{Type: IETypeCompleteRequestMsg, Instance: 0, Value: v}
}

// DecodeIMSI decodes an IMSI IE value from BCD encoding.
func DecodeIMSI(ie *IE) (string, error) {
	if ie == nil || len(ie.Value) == 0 {
		return "", fmt.Errorf("gtpv2: nil or empty IMSI IE")
	}
	return bcdDecode(ie.Value), nil
}

func bcdDecode(bcd []byte) string {
	var digits []byte
	for _, b := range bcd {
		lo := b & 0x0F
		hi := (b >> 4) & 0x0F
		digits = append(digits, '0'+lo)
		if hi != 0x0F {
			digits = append(digits, '0'+hi)
		}
	}
	return string(digits)
}

func decodeDNSLabels(b []byte) string {
	var parts []string
	for i := 0; i < len(b); {
		n := int(b[i])
		i++
		if n == 0 {
			break
		}
		if i+n > len(b) {
			break
		}
		parts = append(parts, string(b[i:i+n]))
		i += n
	}
	return strings.Join(parts, ".")
}

// --- helpers ---

func bcdEncode(digits string) []byte {
	n := len(digits)
	out := make([]byte, (n+1)/2)
	for i, ch := range digits {
		nibble := byte(ch - '0')
		if i%2 == 0 {
			out[i/2] = nibble
		} else {
			out[i/2] |= nibble << 4
		}
	}
	if n%2 != 0 {
		out[n/2] |= 0xF0 // filler nibble
	}
	return out
}

// encodeDNSLabels converts "internet.mnc095.mcc204.gprs" → DNS label encoding.
func encodeDNSLabels(apn string) []byte {
	if len(apn) == 0 {
		return []byte{0}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(apn); i++ {
		if i == len(apn) || apn[i] == '.' {
			label := apn[start:i]
			out = append(out, byte(len(label)))
			out = append(out, []byte(label)...)
			start = i + 1
		}
	}
	return out
}
