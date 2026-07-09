package gtpv2

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func DetailedIESummary(ies []IE) []string {
	out := make([]string, 0, len(ies))
	for _, ie := range ies {
		out = append(out, describeIE(ie))
		if ie.Type != IETypeBearerContext {
			continue
		}
		children, err := FindGroupedIEs(&ie)
		if err != nil {
			out = append(out, fmt.Sprintf("  bearer_context_decode_error=%v", err))
			continue
		}
		for _, child := range children {
			out = append(out, "  "+describeIE(child))
		}
	}
	return out
}

func describeIE(ie IE) string {
	base := fmt.Sprintf("%s(type=%d instance=%d len=%d)", ieTypeName(ie.Type), ie.Type, ie.Instance, len(ie.Value))
	switch ie.Type {
	case IETypeFTEID:
		f, err := DecodeFTEID(&ie)
		if err != nil {
			return base + " decode_error=" + err.Error()
		}
		v4 := len(ie.Value) > 0 && ie.Value[0]&0x80 != 0
		v6 := len(ie.Value) > 0 && ie.Value[0]&0x40 != 0
		return fmt.Sprintf("%s iface=%d(%s) teid=0x%08x v4=%t v6=%t ipv4=%s",
			base, f.InterfaceType, interfaceTypeName(f.InterfaceType), f.TEID, v4, v6, f.IP)
	case IETypeULI:
		return base + " " + describeULI(ie.Value)
	case IETypeEBI:
		ebi, err := DecodeEBI(&ie)
		if err != nil {
			return base + " decode_error=" + err.Error()
		}
		return fmt.Sprintf("%s ebi=%d", base, ebi)
	case IETypeBearerQoS:
		if len(ie.Value) < 2 {
			return base + " short_bearer_qos"
		}
		return fmt.Sprintf("%s arp=0x%02x qci=%d", base, ie.Value[0], ie.Value[1])
	case IETypePCO, IETypeIndication, IETypeChargingChars, IETypeUETimeZone, IETypeAPNRestriction:
		return base + " value_hex=" + hex.EncodeToString(ie.Value)
	default:
		return base
	}
}

func describeULI(v []byte) string {
	if len(v) < 1 {
		return "short_uli"
	}
	flags := v[0]
	off := 1
	parts := []string{fmt.Sprintf("flags=0x%02x tai_present=%t ecgi_present=%t", flags, flags&ULIFlagTAI != 0, flags&ULIFlagECGI != 0)}
	if flags&ULIFlagTAI != 0 {
		if off+5 <= len(v) {
			tac := uint16(v[off+3])<<8 | uint16(v[off+4])
			parts = append(parts, fmt.Sprintf("tai_plmn=%x tac=%d", v[off:off+3], tac))
		} else {
			parts = append(parts, "tai=truncated")
		}
		off += 5
	}
	if flags&ULIFlagECGI != 0 {
		if off+7 <= len(v) {
			eci := uint32(v[off+3]&0x0f)<<24 | uint32(v[off+4])<<16 | uint32(v[off+5])<<8 | uint32(v[off+6])
			parts = append(parts, fmt.Sprintf("ecgi_plmn=%x eci=0x%07x", v[off:off+3], eci))
		} else {
			parts = append(parts, "ecgi=truncated")
		}
	}
	return strings.Join(parts, " ")
}

func ieTypeName(t uint8) string {
	switch t {
	case IETypeIMSI:
		return "IMSI"
	case IETypeCause:
		return "Cause"
	case IETypeMEI:
		return "MEI"
	case IETypeMSISDN:
		return "MSISDN"
	case IETypeIndication:
		return "Indication"
	case IETypePCO:
		return "PCO"
	case IETypePAA:
		return "PAA"
	case IETypeBearerQoS:
		return "BearerQoS"
	case IETypeRATType:
		return "RATType"
	case IETypeServingNetwork:
		return "ServingNetwork"
	case IETypeULI:
		return "ULI"
	case IETypeFTEID:
		return "FTEID"
	case IETypeBearerContext:
		return "BearerContext"
	case IETypeChargingChars:
		return "ChargingCharacteristics"
	case IETypePDNType:
		return "PDNType"
	case IETypeUETimeZone:
		return "UETimeZone"
	case IETypeAPNRestriction:
		return "APNRestriction"
	case IETypeSelectionMode:
		return "SelectionMode"
	default:
		return "IE"
	}
}

func interfaceTypeName(t uint8) string {
	switch t {
	case IFTypeS1UENB:
		return "S1-U eNB GTP-U"
	case IFTypeS1USGW:
		return "S1-U SGW GTP-U"
	case IFTypeS5S8SGWC:
		return "S5/S8 SGW GTP-C"
	case IFTypeS5S8PGWC:
		return "S5/S8 PGW GTP-C"
	case IFTypeS11MME:
		return "S11 MME GTP-C"
	case IFTypeS11S4SGW:
		return "S11/S4 SGW GTP-C"
	case IFTypeS10MME:
		return "S10/N26 MME GTP-C"
	default:
		return "unknown"
	}
}
