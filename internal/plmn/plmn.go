// Package plmn provides VectorCore's canonical typed MCC/MNC identity.
package plmn

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PLMN is a public land mobile network identity. MCC and MNC deliberately
// remain strings: their leading zeroes and the explicit two/three digit MNC
// length are part of the identity.
type PLMN struct {
	MCC string `yaml:"mcc" json:"mcc"`
	MNC string `yaml:"mnc" json:"mnc"`
}

// UnmarshalYAML rejects numeric YAML scalars so a configuration cannot lose
// leading zeroes before validation. MCC/MNC are protocol identifiers, not
// integers.
func (p *PLMN) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("PLMN must be a mapping")
	}
	var out PLMN
	for i := 0; i+1 < len(value.Content); i += 2 {
		key, field := value.Content[i], value.Content[i+1]
		switch key.Value {
		case "mcc":
			if field.Kind != yaml.ScalarNode || field.Tag != "!!str" {
				return fmt.Errorf("MCC must be a string")
			}
			out.MCC = field.Value
		case "mnc":
			if field.Kind != yaml.ScalarNode || field.Tag != "!!str" {
				return fmt.Errorf("MNC must be a string")
			}
			out.MNC = field.Value
		}
	}
	*p = out
	return nil
}

func New(mcc, mnc string) (PLMN, error) {
	p := PLMN{MCC: mcc, MNC: mnc}
	return p, p.Validate()
}

func (p PLMN) Validate() error {
	if !decimalDigits(p.MCC, 3) {
		return fmt.Errorf("MCC must contain exactly three decimal digits, got %q", p.MCC)
	}
	if !(decimalDigits(p.MNC, 2) || decimalDigits(p.MNC, 3)) {
		return fmt.Errorf("MNC must contain exactly two or three decimal digits, got %q", p.MNC)
	}
	return nil
}

func (p PLMN) String() string { return p.MCC + "-" + p.MNC }

// IMSIPrefix returns the MCC+MNC prefix used when resolving an IMSI.
func (p PLMN) IMSIPrefix() string { return p.MCC + p.MNC }

func decimalDigits(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, b := range s {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// IsIMSI reports whether s consists only of decimal IMSI digits.
func IsIMSI(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}
