package sls

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// ErrUnsupportedGeographicalArea is returned by ConvertLocationEstimateToGAD
// for any Geographical-Area shape other than point-With-Uncertainty (root
// CHOICE index 1) — the only shape this MME's peer E-SMLC ever produces.
var ErrUnsupportedGeographicalArea = fmt.Errorf("sls: unsupported Geographical-Area shape")

// ConvertLocationEstimateToGAD converts a TS 29.171 LCS-AP Location-Estimate
// IE value — an APER-encoded Geographical-Area CHOICE — into the compact TS
// 23.032 binary GAD format the Diameter SLg Location-Estimate AVP carries
// (TS 29.172 7.4.4). These are two different wire formats for the same
// shape+coordinate data, and MME is the translation boundary between the
// SLs (LCS-AP/APER) and SLg (Diameter) legs: relaying the LCS-AP bytes
// through unconverted produces a PLA the GMLC's TS 23.032 GAD decoder
// rejects, even though the PLA itself reports success.
//
// Only point-With-Uncertainty (Geographical-Area root CHOICE index 1) is
// handled, matching vectorcore-eSMLC/internal/lcsap/codec.go's
// LocationEstimate encoder — the only shape it ever produces, since its
// caller's estimate type carries no altitude. Every other shape, and any
// extension (SEQUENCE or CHOICE) presence bit, fails closed.
func ConvertLocationEstimateToGAD(raw []byte) ([]byte, error) {
	r := aper.NewBitReader(raw)

	choiceExt, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sls: Geographical-Area choice extension: %w", err)
	}
	if choiceExt != 0 {
		return nil, ErrUnsupportedGeographicalArea
	}
	var idx int64
	for i := 0; i < 3; i++ { // root CHOICE has 7 alternatives -> 3-bit index, written one bit at a time
		b, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
		if err != nil {
			return nil, fmt.Errorf("sls: Geographical-Area choice index: %w", err)
		}
		idx = idx<<1 | b
	}
	if idx != 1 {
		return nil, ErrUnsupportedGeographicalArea
	}

	seqExt, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sls: Point-With-Uncertainty extension: %w", err)
	}
	seqOpt, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sls: Point-With-Uncertainty iE-Extensions presence: %w", err)
	}
	if seqExt != 0 || seqOpt != 0 {
		return nil, ErrUnsupportedGeographicalArea
	}

	coordExt, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sls: Geographical-Coordinates extension: %w", err)
	}
	coordOpt, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sls: Geographical-Coordinates iE-Extensions presence: %w", err)
	}
	if coordExt != 0 || coordOpt != 0 {
		return nil, ErrUnsupportedGeographicalArea
	}

	sign, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sls: latitudeSign: %w", err)
	}
	la, err := aper.DecodeConstrainedWholeNumber(r, 0, (1<<23)-1)
	if err != nil {
		return nil, fmt.Errorf("sls: degreesLatitude: %w", err)
	}
	lo, err := aper.DecodeConstrainedWholeNumber(r, -(1<<23), (1<<23)-1)
	if err != nil {
		return nil, fmt.Errorf("sls: degreesLongitude: %w", err)
	}
	unc, err := aper.DecodeConstrainedWholeNumber(r, 0, 127)
	if err != nil {
		return nil, fmt.Errorf("sls: uncertainty-Code: %w", err)
	}

	// TS 23.032 clause 7.3.2 "Ellipsoid Point with uncertainty Circle": byte0
	// shape type (low nibble) 0x1, bytes1-3 sign+23-bit latitude magnitude,
	// bytes4-6 24-bit two's-complement longitude, byte7 uncertainty code.
	out := make([]byte, 8)
	out[0] = 0x01
	latMag := uint32(la) & 0x7fffff
	if sign == 1 {
		latMag |= 0x800000
	}
	out[1] = byte(latMag >> 16)
	out[2] = byte(latMag >> 8)
	out[3] = byte(latMag)
	lonRaw := uint32(int32(lo)) & 0xffffff
	out[4] = byte(lonRaw >> 16)
	out[5] = byte(lonRaw >> 8)
	out[6] = byte(lonRaw)
	out[7] = byte(unc)
	return out, nil
}
