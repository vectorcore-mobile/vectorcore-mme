package s1ap

import (
	"fmt"

	"github.com/vectorcore/mme/internal/nas/emm"
)

func nasIntegrityAlgorithmName(id uint8) string {
	return fmt.Sprintf("EIA%d", id)
}

func nasCipheringAlgorithmName(id uint8) string {
	return fmt.Sprintf("EEA%d", id)
}

func nasSecurityHeaderName(header uint8) string {
	switch header {
	case emm.SecurityHeaderPlain:
		return "Plain NAS message"
	case emm.SecurityHeaderIntegrityProtected:
		return "Integrity protected"
	case emm.SecurityHeaderIntegrityAndCipher:
		return "Integrity protected and ciphered"
	case emm.SecurityHeaderNewEPSSecurityCtx:
		return "Integrity protected with new EPS security context"
	case emm.SecurityHeaderCipherNewEPSSecCtx:
		return "Integrity protected and ciphered with new EPS security context"
	default:
		return "Unknown"
	}
}
