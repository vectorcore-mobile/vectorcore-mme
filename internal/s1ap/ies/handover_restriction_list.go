package ies

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// extIDNRRestrictionInEPSAsSecondaryRAT is the ProtocolExtensionField id for
// NRrestrictioninEPSasSecondaryRAT (TS 36.413 Annex A, value 261).
const extIDNRRestrictionInEPSAsSecondaryRAT uint16 = 261

// EncodeHandoverRestrictionList encodes the minimal form of the Handover
// Restriction List IE (TS 36.413 §9.2.1.22) used by this MME: mandatory
// servingPLMN plus, when nrRestricted is true, the NR-as-secondary-RAT-in-
// EN-DC restriction extension ("for SCG selection during dual connectivity
// operation"). EquivalentPLMNs/forbiddenTAs/forbiddenLAs/forbiddenInterRATs
// are all OPTIONAL per the ASN.1 and are not populated by this MME.
//
// The NR-restriction bit lives in the iE-Extensions field
// (ProtocolExtensionContainer ::= SEQUENCE OF { id, criticality,
// extensionValue as OPEN TYPE }) — the same shape as a top-level
// ProtocolIE-Field, just nested one level deeper. Since this MME only ever
// encodes the one NR-restriction extension, the container (a single-element
// SEQUENCE OF) is written inline here rather than via a general helper.
func EncodeHandoverRestrictionList(servingPLMN [3]byte, nrRestricted bool) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // SEQUENCE extension = 0
	w.WriteBit(0) // equivalentPLMNs absent
	w.WriteBit(0) // forbiddenTAs absent
	w.WriteBit(0) // forbiddenLAs absent
	w.WriteBit(0) // forbiddenInterRATs absent
	if nrRestricted {
		w.WriteBit(1) // iE-Extensions present
	} else {
		w.WriteBit(0) // iE-Extensions absent
	}
	w.AlignToByte()
	w.WriteOctets(servingPLMN[:])
	if nrRestricted {
		// iE-Extensions is a normal (root, non-extension) OPTIONAL field of
		// HandoverRestrictionList's own SEQUENCE — its type,
		// ProtocolExtensionContainer, is an ordinary SEQUENCE (SIZE(1..65535))
		// OF, and per X.691 §19-21 that encodes directly as a length
		// determinant followed by its elements. It must NOT be wrapped in an
		// additional open-type length prefix: only the *unknown-at-compile-time*
		// extensionValue field inside each ProtocolExtensionField is an open
		// type. Verified against an independent reference PER encoder
		// (pycrate's compiled 3GPP S1AP ASN.1 module) — the earlier version of
		// this function added a spurious extra open-type wrapper here, which
		// corrupted every subsequent byte for any real ASN.1 PER decoder even
		// though this package's own round-trip test (sharing the same bug on
		// both sides) didn't catch it.
		//
		// ProtocolExtensionContainer's length-determinant lower bound is 1
		// (SIZE(1..65535)), not 0.
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 65535) // extension count = 1
		_ = aper.EncodeConstrainedWholeNumber(w, int64(extIDNRRestrictionInEPSAsSecondaryRAT), 0, 65535)
		aper.EncodeCriticality(w, aper.CriticalityIgnore)
		aper.WriteOpenType(w, encodeNRRestrictedEnum())
	}
	return w.Bytes()
}

// DecodeHandoverRestrictionList decodes the subset of Handover Restriction
// List this MME can produce (see EncodeHandoverRestrictionList). It is used
// for round-trip test verification; this MME never receives this IE
// (MME → eNB only), so there is no production caller.
func DecodeHandoverRestrictionList(data []byte) (servingPLMN [3]byte, nrRestricted bool, err error) {
	r := aper.NewBitReader(data)
	if _, err = r.ReadBit(); err != nil { // SEQUENCE extension
		return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList extension bit: %w", err)
	}
	var optPresent [5]uint8
	for i := range optPresent {
		if optPresent[i], err = r.ReadBit(); err != nil {
			return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList optional bit %d: %w", i, err)
		}
	}
	for i, name := range []string{"equivalentPLMNs", "forbiddenTAs", "forbiddenLAs", "forbiddenInterRATs"} {
		if optPresent[i] != 0 {
			return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList: decoding %s is not supported", name)
		}
	}
	r.AlignToByte()
	plmnBytes, err := r.ReadOctets(3)
	if err != nil {
		return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList servingPLMN: %w", err)
	}
	copy(servingPLMN[:], plmnBytes)
	if optPresent[4] == 0 {
		return servingPLMN, false, nil
	}
	// iE-Extensions (ProtocolExtensionContainer) is a normal SEQUENCE OF
	// field, not an open type — read its length determinant and elements
	// directly from r, mirroring EncodeHandoverRestrictionList.
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 65535)
	if err != nil {
		return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList extension count: %w", err)
	}
	for i := 0; i < int(count); i++ {
		id, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList extension[%d] id: %w", i, err)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList extension[%d] criticality: %w", i, err)
		}
		val, err := aper.ReadOpenType(r)
		if err != nil {
			return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList extension[%d] value: %w", i, err)
		}
		if uint16(id) != extIDNRRestrictionInEPSAsSecondaryRAT {
			continue
		}
		if nrRestricted, err = decodeNRRestrictedEnum(val); err != nil {
			return servingPLMN, false, fmt.Errorf("ies: HandoverRestrictionList NR restriction extension: %w", err)
		}
	}
	return servingPLMN, nrRestricted, nil
}

// encodeNRRestrictedEnum encodes NRrestrictioninEPSasSecondaryRAT ::=
// ENUMERATED { nRrestrictedinEPSasSecondaryRAT, ... } — an extensible
// ENUMERATED with exactly one root value, always encoding that root value
// (presence of the extension itself is what signals the restriction).
func encodeNRRestrictedEnum() []byte {
	w := aper.NewBitWriter()
	aper.EncodeEnumeratedExt(w, 0, 1)
	return w.Bytes()
}

// decodeNRRestrictedEnum decodes encodeNRRestrictedEnum's output. Any
// successfully decoded value (root or extension addition) means the
// restriction is present — this IE-extension's mere presence in the
// container already signals the restriction; this just validates it
// decodes cleanly.
func decodeNRRestrictedEnum(data []byte) (bool, error) {
	r := aper.NewBitReader(data)
	if _, err := aper.DecodeEnumeratedExt(r, 1); err != nil {
		return false, err
	}
	return true, nil
}
