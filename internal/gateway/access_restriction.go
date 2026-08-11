package gateway

// AccessRestrictionData mirrors the S6a Access-Restriction-Data AVP (code 1426,
// 3GPP TS 29.272 §7.3.31): a bitmask where each set bit denotes a RAT the
// subscriber is barred from using. Bits 10+ (Rel-17+ NTN/satellite variants)
// are intentionally not named here; the raw value still round-trips through
// this type if they're ever needed.
type AccessRestrictionData uint32

const (
	AccessRestrictUTRAN                            AccessRestrictionData = 1 << 0
	AccessRestrictGERAN                            AccessRestrictionData = 1 << 1
	AccessRestrictGAN                              AccessRestrictionData = 1 << 2
	AccessRestrictIHSPAEvolution                   AccessRestrictionData = 1 << 3
	AccessRestrictWBEUTRAN                         AccessRestrictionData = 1 << 4
	AccessRestrictHOToNon3GPP                      AccessRestrictionData = 1 << 5
	AccessRestrictNBIoT                            AccessRestrictionData = 1 << 6
	AccessRestrictEnhancedCoverage                 AccessRestrictionData = 1 << 7
	AccessRestrictNRAsSecondaryRATInEUTRAN         AccessRestrictionData = 1 << 8
	AccessRestrictUnlicensedSpectrumAsSecondaryRAT AccessRestrictionData = 1 << 9
)

// UTRANNotAllowed reports bit 0.
func (a AccessRestrictionData) UTRANNotAllowed() bool { return a&AccessRestrictUTRAN != 0 }

// GERANNotAllowed reports bit 1.
func (a AccessRestrictionData) GERANNotAllowed() bool { return a&AccessRestrictGERAN != 0 }

// GANNotAllowed reports bit 2.
func (a AccessRestrictionData) GANNotAllowed() bool { return a&AccessRestrictGAN != 0 }

// IHSPAEvolutionNotAllowed reports bit 3.
func (a AccessRestrictionData) IHSPAEvolutionNotAllowed() bool {
	return a&AccessRestrictIHSPAEvolution != 0
}

// WBEUTRANNotAllowed reports bit 4 — the subscriber may not use (wideband)
// E-UTRAN, i.e. regular LTE, at all.
func (a AccessRestrictionData) WBEUTRANNotAllowed() bool { return a&AccessRestrictWBEUTRAN != 0 }

// HOToNon3GPPNotAllowed reports bit 5.
func (a AccessRestrictionData) HOToNon3GPPNotAllowed() bool {
	return a&AccessRestrictHOToNon3GPP != 0
}

// NBIoTNotAllowed reports bit 6.
func (a AccessRestrictionData) NBIoTNotAllowed() bool { return a&AccessRestrictNBIoT != 0 }

// EnhancedCoverageNotAllowed reports bit 7.
func (a AccessRestrictionData) EnhancedCoverageNotAllowed() bool {
	return a&AccessRestrictEnhancedCoverage != 0
}

// NRAsSecondaryRATInEUTRANNotAllowed reports bit 8 — the subscriber may not
// use EN-DC (E-UTRA-NR Dual Connectivity) with this LTE cell as anchor.
func (a AccessRestrictionData) NRAsSecondaryRATInEUTRANNotAllowed() bool {
	return a&AccessRestrictNRAsSecondaryRATInEUTRAN != 0
}

// UnlicensedSpectrumAsSecondaryRATNotAllowed reports bit 9.
func (a AccessRestrictionData) UnlicensedSpectrumAsSecondaryRATNotAllowed() bool {
	return a&AccessRestrictUnlicensedSpectrumAsSecondaryRAT != 0
}
