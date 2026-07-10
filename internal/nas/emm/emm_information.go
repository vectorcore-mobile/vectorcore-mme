package emm

import "time"

// EncodeEMMInformation builds a plain EMM Information NAS PDU (TS 24.301 §8.2.35).
// Returns nil if no IE would be appended (nothing to send).
func EncodeEMMInformation(
	fullName string, showFull bool,
	shortName string, showShort bool,
	nameEncoding string,
	addCountryInitials bool,
	nitzEnabled bool, tzOffsetMinutes int, dst uint8,
) []byte {
	var ies []byte

	if showFull {
		if b := EncodeFullNetworkNameWithEncoding(fullName, nameEncoding, addCountryInitials); b != nil {
			ies = append(ies, b...)
		}
	}
	if showShort {
		if b := EncodeShortNetworkNameWithEncoding(shortName, nameEncoding, addCountryInitials); b != nil {
			ies = append(ies, b...)
		}
	}
	if nitzEnabled {
		ies = append(ies, EncodeLocalTimeZone(tzOffsetMinutes)...)
		ies = append(ies, EncodeUniversalTimeAndLocalTimeZone(time.Now().UTC(), tzOffsetMinutes)...)
		if dst > 0 {
			ies = append(ies, EncodeDaylightSavingTime(dst)...)
		}
	}

	if len(ies) == 0 {
		return nil
	}

	hdr := []byte{
		PDEPSMobilityMgmt | (SecurityHeaderPlain << 4),
		0x00, // skip indicator
		MsgEMMInformation,
	}
	return append(hdr, ies...)
}
