package emm

import "time"

type EMMInformationOptions struct {
	FullName             string
	ShowFullName         bool
	ShortName            string
	ShowShortName        bool
	NameEncoding         string
	AddCountryInitials   bool
	IncludeLocalTimeZone bool
	IncludeUniversalTime bool
	IncludeDST           bool
	UniversalTime        time.Time
	TimezoneOffsetMin    int
	DaylightSaving       uint8
}

// EncodeEMMInformation builds a plain EMM Information NAS PDU (TS 24.301 §8.2.35).
// Returns nil if no IE would be appended (nothing to send).
func EncodeEMMInformation(
	fullName string, showFull bool,
	shortName string, showShort bool,
	nameEncoding string,
	addCountryInitials bool,
	nitzEnabled bool, tzOffsetMinutes int, dst uint8,
) []byte {
	return EncodeEMMInformationWithOptions(EMMInformationOptions{
		FullName:             fullName,
		ShowFullName:         showFull,
		ShortName:            shortName,
		ShowShortName:        showShort,
		NameEncoding:         nameEncoding,
		AddCountryInitials:   addCountryInitials,
		IncludeLocalTimeZone: nitzEnabled,
		IncludeUniversalTime: nitzEnabled,
		IncludeDST:           nitzEnabled && dst > 0,
		UniversalTime:        time.Now().UTC(),
		TimezoneOffsetMin:    tzOffsetMinutes,
		DaylightSaving:       dst,
	})
}

func EncodeEMMInformationWithOptions(opts EMMInformationOptions) []byte {
	var ies []byte

	if opts.ShowFullName {
		if b := EncodeFullNetworkNameWithEncoding(opts.FullName, opts.NameEncoding, opts.AddCountryInitials); b != nil {
			ies = append(ies, b...)
		}
	}
	if opts.ShowShortName {
		if b := EncodeShortNetworkNameWithEncoding(opts.ShortName, opts.NameEncoding, opts.AddCountryInitials); b != nil {
			ies = append(ies, b...)
		}
	}
	if opts.IncludeLocalTimeZone {
		ies = append(ies, EncodeLocalTimeZone(opts.TimezoneOffsetMin)...)
	}
	if opts.IncludeUniversalTime {
		t := opts.UniversalTime
		if t.IsZero() {
			t = time.Now().UTC()
		}
		ies = append(ies, EncodeUniversalTimeAndLocalTimeZone(t.UTC(), opts.TimezoneOffsetMin)...)
	}
	if opts.IncludeDST {
		ies = append(ies, EncodeDaylightSavingTime(opts.DaylightSaving)...)
	}

	if len(ies) == 0 {
		return nil
	}

	hdr := []byte{
		PDEPSMobilityMgmt | (SecurityHeaderPlain << 4),
		MsgEMMInformation,
	}
	return append(hdr, ies...)
}
