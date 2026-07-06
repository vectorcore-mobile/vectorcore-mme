package emm

import "fmt"

// EncodeSecurityModeCommand encodes a NAS Security Mode Command.
// intAlgID and encAlgID are the selected EIA/EEA algorithm IDs (0..7).
// ueSecCap is the UE network capability IE echoed back.
func EncodeSecurityModeCommand(intAlgID, encAlgID uint8, ueSecCap []byte) []byte {
	b := make([]byte, 0, 32)
	b = append(b, PDEPSMobilityMgmt|SecurityHeaderPlain<<4)
	b = append(b, MsgSecurityModeCommand)

	// Selected NAS security algorithms: EIA=bits 3:0, EEA=bits 7:4 of byte 0; remaining byte spare
	// byte 0: EEA(bits 6:4) + spare(3) + EIA(bits 2:0)
	b = append(b, (encAlgID&0x07)<<4|(intAlgID&0x07))

	// NAS key set identifier (bits 3:0 = KSI, bits 7:4 = spare)
	b = append(b, 0x00) // KSI=0 (native)

	// Replayed UE security capabilities (mandatory)
	b = append(b, byte(len(ueSecCap)))
	b = append(b, ueSecCap...)

	return b
}

// SecurityModeComplete holds the decoded NAS Security Mode Complete.
type SecurityModeComplete struct {
	IMEISV []byte // optional
}

// DecodeSecurityModeComplete decodes a NAS Security Mode Complete body.
func DecodeSecurityModeComplete(data []byte) (*SecurityModeComplete, error) {
	smc := &SecurityModeComplete{}
	// Optional IMEISV IE (IEI = 0x23)
	for i := 0; i < len(data)-1; {
		iei := data[i]
		i++
		if iei == 0x23 {
			ieLen := int(data[i])
			i++
			if i+ieLen <= len(data) {
				smc.IMEISV = data[i : i+ieLen]
				i += ieLen
			}
		} else {
			// Unknown optional TLV: skip
			if i >= len(data) {
				break
			}
			ieLen := int(data[i])
			i++
			i += ieLen
		}
	}
	return smc, nil
}

// EncodeSecurityModeReject encodes a NAS Security Mode Reject.
func EncodeSecurityModeReject(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgSecurityModeReject,
		cause,
	}
}

// DecodeSecurityModeCommand decodes a received NAS Security Mode Command (for testing).
func DecodeSecurityModeCommand(data []byte) (intAlgID, encAlgID, ksi uint8, ueSecCap []byte, err error) {
	if len(data) < 3 {
		return 0, 0, 0, nil, fmt.Errorf("emm: SecurityModeCommand too short: %d", len(data))
	}
	encAlgID = (data[0] >> 4) & 0x07
	intAlgID = data[0] & 0x07
	ksi = data[1] & 0x07
	if len(data) < 3 {
		return
	}
	capLen := int(data[2])
	if 3+capLen > len(data) {
		return 0, 0, 0, nil, fmt.Errorf("emm: SecurityModeCommand UE cap truncated")
	}
	ueSecCap = data[3 : 3+capLen]
	return
}
