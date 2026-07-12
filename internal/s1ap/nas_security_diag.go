package s1ap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

func (s *Server) logProtectedNASFailure(log *zap.Logger, raw []byte, intAlg, encAlg uint8, knasInt, knasEnc []byte, storedCount uint32, err error) {
	if len(raw) < 1 {
		log.Warn("s1ap: protected NAS decode failed", zap.Error(err), zap.Int("nas_len", len(raw)))
		return
	}
	secHdr, pd, hdrErr := emm.DecodeSecurityHeader(raw)
	fields := []zap.Field{
		zap.Error(err),
		zap.String("nas_hex_full", hex.EncodeToString(raw)),
		zap.Uint8("security_header_type", secHdr),
		zap.Uint8("protocol_discriminator", pd),
		zap.Uint8("integrity_algorithm", intAlg),
		zap.Uint8("ciphering_algorithm", encAlg),
		zap.Uint32("stored_count_before", storedCount),
		zap.String("knasint_sha256_prefix", keyFingerprint(knasInt)),
		zap.String("knasenc_sha256_prefix", keyFingerprint(knasEnc)),
	}
	if hdrErr != nil {
		fields = append(fields, zap.Error(hdrErr))
		log.Warn("s1ap: protected NAS decode failed", fields...)
		return
	}
	if len(raw) < 6 {
		log.Warn("s1ap: protected NAS decode failed", fields...)
		return
	}

	receivedMAC := raw[1:5]
	seq := raw[5]
	payload := raw[6:]
	baseCount := (storedCount & 0xffffff00) | uint32(seq)
	nextCount := baseCount
	if nextCount < storedCount {
		nextCount += 0x100
	}
	messageForMAC := append([]byte{seq}, payload...)
	candidates := []struct {
		name  string
		count uint32
	}{
		{name: "base", count: baseCount},
		{name: "next", count: nextCount},
		{name: "zero", count: uint32(seq)},
	}
	var candidateLogs []string
	for _, c := range candidates {
		mac, macErr := security.ComputeNASMAC(intAlg, knasInt, c.count, 0, 0, messageForMAC)
		if macErr != nil {
			candidateLogs = append(candidateLogs, fmt.Sprintf("%s:count=%d err=%v", c.name, c.count, macErr))
			continue
		}
		candidateLogs = append(candidateLogs, fmt.Sprintf("%s:count=%d mac=%s", c.name, c.count, hex.EncodeToString(mac)))
	}

	fields = append(fields,
		zap.Uint8("received_sequence_number", seq),
		zap.Uint32("candidate_count_base", baseCount),
		zap.Uint32("candidate_count_next", nextCount),
		zap.Uint8("bearer", 0),
		zap.Uint8("direction_bit", 0),
		zap.String("received_mac", hex.EncodeToString(receivedMAC)),
		zap.String("nas_mac_message_hex", hex.EncodeToString(messageForMAC)),
		zap.String("eia2_input_base_hex", eia2InputHex(intAlg, baseCount, messageForMAC)),
		zap.String("eia2_input_next_hex", eia2InputHex(intAlg, nextCount, messageForMAC)),
		zap.Strings("computed_mac_candidates", candidateLogs),
		zap.String("ciphertext_or_inner_hex", hex.EncodeToString(payload)),
	)
	if len(payload) >= 2 && payload[0]&0x0f == emm.PDEPSMobilityMgmt {
		fields = append(fields,
			zap.Uint8("unverified_inner_msg_type", payload[1]))
		if payload[1] == emm.MsgSecurityModeReject && len(payload) > 2 {
			fields = append(fields,
				zap.Uint8("unverified_emm_cause", payload[2]),
				zap.String("unverified_emm_cause_name", emm.CauseName(payload[2])))
		}
	}

	if secHdr == emm.SecurityHeaderIntegrityAndCipher || secHdr == emm.SecurityHeaderCipherNewEPSSecCtx {
		if plain, decErr := security.CipherNAS(encAlg, knasEnc, baseCount, 0, 0, payload); decErr == nil {
			fields = append(fields, zap.String("deciphered_plain_candidate_base_hex", hex.EncodeToString(plain)))
		}
		if nextCount != baseCount {
			if plain, decErr := security.CipherNAS(encAlg, knasEnc, nextCount, 0, 0, payload); decErr == nil {
				fields = append(fields, zap.String("deciphered_plain_candidate_next_hex", hex.EncodeToString(plain)))
			}
		}
	}

	log.Warn("s1ap: protected NAS decode failed", fields...)
}

func keyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:6])
}

func eia2InputHex(intAlg uint8, count uint32, msg []byte) string {
	if intAlg != security.AlgIDEIA2 {
		return ""
	}
	return hex.EncodeToString(security.EIA2CMACInput(count, 0, 0, msg))
}
