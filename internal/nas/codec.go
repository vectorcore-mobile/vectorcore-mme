// Package nas provides the top-level NAS (Non-Access Stratum) codec.
// It reads the security header, dispatches to security processing,
// then routes the inner message to the emm or esm subpackage.
package nas

import (
	"fmt"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

// DecodeResult holds the outcome of NAS decoding.
type DecodeResult struct {
	SecHeaderType uint8
	PD            uint8
	MsgType       uint8
	Inner         []byte // plaintext payload after header (and decryption if applicable)
}

// Decode decodes a raw NAS PDU. If the message is integrity-protected, it verifies
// the MAC before returning. If ciphered, it decrypts. On error, the MAC failure
// is returned and the caller must reject the message.
func Decode(
	raw []byte,
	intAlgID, encAlgID uint8,
	knasInt, knasEnc []byte,
	ulCount uint32,
) (*DecodeResult, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("nas: empty PDU")
	}

	secHdrType, pd, err := emm.DecodeSecurityHeader(raw)
	if err != nil {
		return nil, err
	}

	switch secHdrType {
	case emm.SecurityHeaderPlain:
		// Plain NAS — no security context yet (e.g., Attach Request before keys)
		if len(raw) < 2 {
			return nil, fmt.Errorf("nas: plain message too short")
		}
		return &DecodeResult{
			SecHeaderType: secHdrType,
			PD:            pd,
			MsgType:       raw[1],
			Inner:         raw[2:],
		}, nil

	case emm.SecurityHeaderIntegrityProtected:
		// Integrity protected, not ciphered
		if len(raw) < 6 {
			return nil, fmt.Errorf("nas: integrity-protected message too short")
		}
		mac := raw[1:5]
		seq := raw[5]
		inner := raw[6:]

		// Verify MAC over the message (including security header byte)
		// The NAS COUNT is reconstructed from the sequence number and overflow counter
		count := (ulCount & 0xFFFFFF00) | uint32(seq)
		msgForMAC := append([]byte{raw[0]}, raw[1:]...)
		if err := security.VerifyNASMAC(intAlgID, knasInt, count, 0, 0, msgForMAC[5:], mac); err != nil {
			return nil, fmt.Errorf("nas: MAC verification failed: %w", err)
		}

		if len(inner) < 2 {
			return nil, fmt.Errorf("nas: inner message too short")
		}
		return &DecodeResult{
			SecHeaderType: secHdrType,
			PD:            pd,
			MsgType:       inner[1],
			Inner:         inner[2:],
		}, nil

	case emm.SecurityHeaderIntegrityAndCipher:
		// Integrity protected and ciphered
		if len(raw) < 6 {
			return nil, fmt.Errorf("nas: encrypted message too short")
		}
		mac := raw[1:5]
		seq := raw[5]
		encrypted := raw[6:]

		count := (ulCount & 0xFFFFFF00) | uint32(seq)

		// Verify integrity first (over the unencrypted security header + MAC + SEQ + ciphertext)
		msgForMAC := append([]byte{raw[0]}, raw[1:]...)
		if err := security.VerifyNASMAC(intAlgID, knasInt, count, 0, 0, msgForMAC[5:], mac); err != nil {
			return nil, fmt.Errorf("nas: MAC verification failed: %w", err)
		}

		// Decrypt
		plaintext, err := security.CipherNAS(encAlgID, knasEnc, count, 0, 0, encrypted)
		if err != nil {
			return nil, fmt.Errorf("nas: decryption failed: %w", err)
		}
		if len(plaintext) < 2 {
			return nil, fmt.Errorf("nas: decrypted message too short")
		}
		return &DecodeResult{
			SecHeaderType: secHdrType,
			PD:            pd,
			MsgType:       plaintext[1],
			Inner:         plaintext[2:],
		}, nil

	case emm.SecurityHeaderNewEPSSecurityCtx:
		// Integrity-protected with new EPS security context.
		// TS 33.401 §5.7.3: verify MAC with new KNASint at UL COUNT=0.
		if len(raw) < 6 {
			return nil, fmt.Errorf("nas: new-context message too short")
		}
		mac := raw[1:5]
		seq := raw[5]
		inner := raw[6:]
		// Reconstruct COUNT from SQN byte (caller passes ulCount with correct base for SQN=0)
		count := (ulCount & 0xFFFFFF00) | uint32(seq)
		// MAC input is [SN byte || inner NAS] per TS 33.401 §B.2
		msgForMAC := make([]byte, 1+len(inner))
		msgForMAC[0] = seq
		copy(msgForMAC[1:], inner)
		if err := security.VerifyNASMAC(intAlgID, knasInt, count, 0, 0, msgForMAC, mac); err != nil {
			return nil, fmt.Errorf("nas: SMC Complete MAC verification failed: %w", err)
		}
		if len(inner) < 2 {
			return nil, fmt.Errorf("nas: inner too short")
		}
		return &DecodeResult{
			SecHeaderType: secHdrType,
			PD:            pd,
			MsgType:       inner[1],
			Inner:         inner[2:],
		}, nil

	case emm.SecurityHeaderCipherNewEPSSecCtx:
		// Integrity-protected and ciphered with new EPS security context
		// (Security Mode Complete).
		if len(raw) < 6 {
			return nil, fmt.Errorf("nas: ciphered new-context message too short")
		}
		mac := raw[1:5]
		seq := raw[5]
		encrypted := raw[6:]
		count := (ulCount & 0xFFFFFF00) | uint32(seq)
		msgForMAC := make([]byte, 1+len(encrypted))
		msgForMAC[0] = seq
		copy(msgForMAC[1:], encrypted)
		if err := security.VerifyNASMAC(intAlgID, knasInt, count, 0, 0, msgForMAC, mac); err != nil {
			return nil, fmt.Errorf("nas: SMC Complete MAC verification failed: %w", err)
		}
		plaintext, err := security.CipherNAS(encAlgID, knasEnc, count, 0, 0, encrypted)
		if err != nil {
			return nil, fmt.Errorf("nas: SMC Complete decryption failed: %w", err)
		}
		if len(plaintext) < 2 {
			return nil, fmt.Errorf("nas: inner too short")
		}
		return &DecodeResult{
			SecHeaderType: secHdrType,
			PD:            pd,
			MsgType:       plaintext[1],
			Inner:         plaintext[2:],
		}, nil

	default:
		return nil, fmt.Errorf("nas: unsupported security header type %d", secHdrType)
	}
}

// EncodeIntegrityProtected wraps a plain NAS PDU with integrity protection.
func EncodeIntegrityProtected(
	plain []byte,
	intAlgID uint8,
	knasInt []byte,
	dlCount uint32,
) ([]byte, error) {
	return encodeIntegrityProtectedWithHeader(plain, intAlgID, knasInt, dlCount, emm.SecurityHeaderIntegrityProtected)
}

// EncodeIntegrityProtectedNewEPSSecurityContext wraps a plain NAS PDU with
// integrity protection using the new EPS security context header. This is used
// for Security Mode Command before the new security context is fully active.
func EncodeIntegrityProtectedNewEPSSecurityContext(
	plain []byte,
	intAlgID uint8,
	knasInt []byte,
	dlCount uint32,
) ([]byte, error) {
	return encodeIntegrityProtectedWithHeader(plain, intAlgID, knasInt, dlCount, emm.SecurityHeaderNewEPSSecurityCtx)
}

func encodeIntegrityProtectedWithHeader(
	plain []byte,
	intAlgID uint8,
	knasInt []byte,
	dlCount uint32,
	securityHeaderType uint8,
) ([]byte, error) {
	seq := uint8(dlCount & 0xFF)
	// Compute MAC over: [SN byte || plain NAS message] per TS 33.401 §B.2
	msgForMAC := make([]byte, 1+len(plain))
	msgForMAC[0] = seq
	copy(msgForMAC[1:], plain)
	mac, err := security.ComputeNASMAC(intAlgID, knasInt, dlCount, 0, 1, msgForMAC)
	if err != nil {
		return nil, err
	}
	// Build security-protected message:
	// Byte 0: PD (EMM) | security header.
	b := make([]byte, 0, 6+len(plain))
	b = append(b, emm.PDEPSMobilityMgmt|(securityHeaderType<<4))
	b = append(b, mac...)
	b = append(b, seq)
	b = append(b, plain...)
	return b, nil
}

// EncodeIntegrityAndCiphered wraps a plain NAS PDU with integrity + ciphering.
func EncodeIntegrityAndCiphered(
	plain []byte,
	intAlgID, encAlgID uint8,
	knasInt, knasEnc []byte,
	dlCount uint32,
) ([]byte, error) {
	seq := uint8(dlCount & 0xFF)

	// Encrypt the inner message
	ciphertext, err := security.CipherNAS(encAlgID, knasEnc, dlCount, 0, 1, plain)
	if err != nil {
		return nil, err
	}

	// Compute MAC over: [SN byte || ciphertext] per TS 33.401 §B.2
	msgForMAC := make([]byte, 1+len(ciphertext))
	msgForMAC[0] = seq
	copy(msgForMAC[1:], ciphertext)
	mac, err := security.ComputeNASMAC(intAlgID, knasInt, dlCount, 0, 1, msgForMAC)
	if err != nil {
		return nil, err
	}

	b := make([]byte, 0, 6+len(ciphertext))
	b = append(b, emm.PDEPSMobilityMgmt|(emm.SecurityHeaderIntegrityAndCipher<<4))
	b = append(b, mac...)
	b = append(b, seq)
	b = append(b, ciphertext...)
	return b, nil
}
