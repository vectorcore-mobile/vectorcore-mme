package config

import (
	"fmt"
	"strings"
)

// NormalizeE164 accepts the presentation form used in configuration and
// returns the digits which are carried in 3GPP TBCD address fields.  TS
// 29.272 MME-Number-for-MT-SMS explicitly excludes TON/NPI indicator octets;
// SGd SC-Address uses the same canonical E.164 digits at this boundary.
func NormalizeE164(value string) (string, error) {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, "+")
	if v == "" || len(v) > 15 {
		return "", fmt.Errorf("must contain 1 to 15 E.164 digits")
	}
	for i := range v {
		if v[i] < '0' || v[i] > '9' {
			return "", fmt.Errorf("must be an E.164 number")
		}
	}
	return v, nil
}

// EncodeTBCD encodes an E.164 digit string for the Diameter OctetString AVPs
// used by S6a and SGd. The first digit is the low nibble.
func EncodeTBCD(value string) ([]byte, error) {
	digits, err := NormalizeE164(value)
	if err != nil {
		return nil, err
	}
	out := make([]byte, (len(digits)+1)/2)
	for i := 0; i < len(digits); i += 2 {
		lo := digits[i] - '0'
		hi := byte(0x0f)
		if i+1 < len(digits) {
			hi = digits[i+1] - '0'
		}
		out[i/2] = lo | hi<<4
	}
	return out, nil
}

// EncodeSGdSCAddress applies the explicitly configured interoperability
// encoding. TBCD is required by TS 29.338; ascii_digits exists solely for
// peers such as deployed Cisco SMSCs that use that legacy representation.
func EncodeSGdSCAddress(value, encoding string) ([]byte, error) {
	digits, err := NormalizeE164(value)
	if err != nil {
		return nil, err
	}
	switch encoding {
	case "", "tbcd":
		return EncodeTBCD(digits)
	case "ascii_digits":
		return []byte(digits), nil
	default:
		return nil, fmt.Errorf("unsupported SGd SC-Address encoding %q", encoding)
	}
}
