// Package lcsnotify implements the TS 24.171/24.080 LCS location-notification
// procedure: the network-to-UE consent/verification exchange TS 23.271
// §9.1.15 step 4/5 requires before positioning a value-added-services LCS
// client. It rides the same Downlink/Uplink Generic NAS Transport messages
// already used for LPP relay (internal/nas/emm/generic_transport.go), with
// Generic-message-container-type 0x02 (emm.GenericMessageContainerTypeLCS)
// instead of 0x01.
//
// The wire format is TS 24.080's BER-based Facility/component syntax
// (ITU-T X.690) — a different encoding from the aligned-PER used everywhere
// else in this codebase (S1AP, LCS-AP). Only the subset this package
// actually emits/parses is implemented: short-form BER lengths and the
// handful of tags TS 24.080 §3.6 defines for Invoke/Return
// Result/Return Error/Reject. The operation code, tagging convention
// (IMPLICIT TAGS), and enumerated values below come from the 3GPP
// SS-Operations/SS-DataTypes/MAP-LCS-DataTypes/MAP-MS-DataTypes ASN.1
// modules (TS 24.080 Annex A) — the modules TS 24.080's own prose text
// references but does not reproduce.
package lcsnotify

import "fmt"

const (
	pdSupplementaryServices byte = 0x0B // TS 24.080 §3.2

	msgTypeRegister        byte = 0x3B // TS 24.080 Table 3.1
	msgTypeReleaseComplete byte = 0x2A

	ieiFacility byte = 0x1C // TS 24.080 §3.5

	tagInvoke       byte = 0xA1 // TS 24.080 Table 3.7
	tagReturnResult byte = 0xA2
	tagReturnError  byte = 0xA3
	tagReject       byte = 0xA4

	tagInvokeID byte = 0x02 // TS 24.080 Table 3.8 (coded as Universal INTEGER)
	tagOpCode   byte = 0x02 // TS 24.080 Table 3.10 (coded as Universal INTEGER)
	tagSequence byte = 0x30 // TS 24.080 Table 3.11

	opLocationNotification byte = 116 // SS-Operations.asn: lcs-LocationNotification CODE local:116

	// This package supports one active notification per UE at a time,
	// mirroring the "one active positioning transaction per UE" invariant
	// already enforced by internal/sls.Provider and the LPP relay — so a
	// single fixed Invoke ID / Transaction Identifier pair is sufficient
	// and no allocator is needed.
	fixedInvokeID      byte = 1
	fixedTransactionID byte = 0

	// LocationType.locationEstimateType (MAP-LCS-DataTypes.asn), value used
	// for a pure consent/verification notification sent before positioning
	// has produced any estimate. TS 24.080's own LocationNotificationArg
	// comment restricts this field to currentLocation,
	// currentOrLastKnownLocation, notificationVerificationOnly, or
	// activateDeferredLocation for this operation; this package only ever
	// sends the pre-positioning verification case.
	locationEstimateTypeNotificationVerificationOnly byte = 5

	// LocationNotificationRes.verificationResponse (SS-DataTypes.asn).
	verificationResponsePermissionGranted byte = 1
)

// NotificationType mirrors TS 24.080's NotificationToMSUser (imported from
// MAP-MS-DataTypes), restricted to the three values valid on a network-sent
// LocationNotificationArg (TS 24.080 §4.4.3.37 comment; the fourth defined
// value, locationNotAllowed, is a receive-only extension member).
type NotificationType uint8

const (
	NotifyLocationAllowed                         NotificationType = 0
	NotifyAndVerifyLocationAllowedIfNoResponse    NotificationType = 1
	NotifyAndVerifyLocationNotAllowedIfNoResponse NotificationType = 2
)

// EncodeRegister builds a complete TS 24.080 REGISTER message carrying an
// lcs-LocationNotification Invoke. The result is the payload argument to
// emm.EncodeDownlinkGenericNASTransport(emm.GenericMessageContainerTypeLCS, ...).
func EncodeRegister(notificationType NotificationType) ([]byte, error) {
	if notificationType > NotifyAndVerifyLocationNotAllowedIfNoResponse {
		return nil, fmt.Errorf("lcsnotify: invalid notification type %d", notificationType)
	}
	// LocationType ::= SEQUENCE { locationEstimateType [0] IMPLICIT LocationEstimateType, ... }
	locationType := tlv(0x80, []byte{locationEstimateTypeNotificationVerificationOnly})
	// LocationNotificationArg ::= SEQUENCE {
	//   notificationType [0] IMPLICIT NotificationToMSUser,
	//   locationType      [1] IMPLICIT LocationType, ... }
	// (IMPLICIT TAGS module: context tags replace the field's universal tag directly.)
	argFields := tlv(0x80, []byte{byte(notificationType)})
	argFields = append(argFields, tlv(0xA1, locationType)...)
	argument := tlv(tagSequence, argFields)

	// Invoke component (TS 24.080 Table 3.3): Invoke ID, Operation Code,
	// Parameters (= the argument type's own tag+encoding) as direct
	// sibling fields — no additional wrapping Sequence.
	invoke := tlv(tagInvokeID, []byte{fixedInvokeID})
	invoke = append(invoke, tlv(tagOpCode, []byte{opLocationNotification})...)
	invoke = append(invoke, argument...)
	component := tlv(tagInvoke, invoke)

	facility := tlv(ieiFacility, component)
	msg := []byte{tiOctet(false), msgTypeRegister}
	return append(msg, facility...), nil
}

// DecodeReleaseComplete parses a TS 24.080 RELEASE COMPLETE message (the
// container payload of an Uplink Generic NAS Transport with container type
// emm.GenericMessageContainerTypeLCS) and extracts the UE's response to a
// pending lcs-LocationNotification Invoke.
//
// granted is true only for an explicit Return Result with no
// verificationResponse field (implicit consent — TS 24.080 Table 3.4's note
// that Sequence/Operation Code/Parameters are all omitted together when the
// component carries no parameters) or verificationResponse =
// permissionGranted(1). A Return Error, Reject, RELEASE COMPLETE with no
// Facility IE at all, or a Return Result carrying permissionDenied(0) all
// yield granted = false: this handler fails closed on anything but
// affirmative consent, matching TS 23.271 step 5's RESTRICTED_IF_NO_RESPONSE
// intent.
func DecodeReleaseComplete(msg []byte) (granted bool, err error) {
	if len(msg) < 2 || msg[0]&0x0F != pdSupplementaryServices || msg[1] != msgTypeReleaseComplete {
		return false, fmt.Errorf("lcsnotify: not a RELEASE COMPLETE message")
	}
	body := msg[2:]
	var facility []byte
	for len(body) >= 2 {
		iei, length := body[0], int(body[1])
		if len(body) < 2+length {
			return false, fmt.Errorf("lcsnotify: truncated IE in RELEASE COMPLETE")
		}
		if iei == ieiFacility {
			facility = body[2 : 2+length]
		}
		body = body[2+length:]
	}
	if facility == nil {
		return false, nil
	}
	return decodeComponent(facility)
}

func decodeComponent(b []byte) (bool, error) {
	tag, content, _, err := readTLV(b)
	if err != nil {
		return false, err
	}
	switch tag {
	case tagReturnResult:
		return decodeReturnResult(content)
	case tagReturnError, tagReject:
		return false, nil
	default:
		return false, fmt.Errorf("lcsnotify: unexpected component tag 0x%02x", tag)
	}
}

func decodeReturnResult(b []byte) (bool, error) {
	tag, _, rest, err := readTLV(b) // Invoke ID
	if err != nil || tag != tagInvokeID {
		return false, fmt.Errorf("lcsnotify: malformed Return Result Invoke ID")
	}
	if len(rest) == 0 {
		return true, nil // no parameters at all: implicit grant (Table 3.4 note)
	}
	seqTag, seqContent, _, err := readTLV(rest)
	if err != nil || seqTag != tagSequence {
		return false, fmt.Errorf("lcsnotify: malformed Return Result parameters")
	}
	opTag, _, opRest, err := readTLV(seqContent) // Operation Code
	if err != nil || opTag != tagOpCode {
		return false, fmt.Errorf("lcsnotify: malformed Return Result operation code")
	}
	if len(opRest) == 0 {
		return true, nil // no result argument: implicit grant
	}
	resTag, resContent, _, err := readTLV(opRest) // LocationNotificationRes SEQUENCE
	if err != nil || resTag != tagSequence {
		return false, fmt.Errorf("lcsnotify: malformed LocationNotificationRes")
	}
	if len(resContent) == 0 {
		return true, nil // all fields optional and absent: implicit grant
	}
	fieldTag, fieldValue, _, err := readTLV(resContent) // verificationResponse [0]
	if err != nil {
		return false, err
	}
	if fieldTag != 0x80 {
		return true, nil // a different optional field is present instead: implicit grant
	}
	if len(fieldValue) != 1 {
		return false, fmt.Errorf("lcsnotify: malformed verificationResponse")
	}
	return fieldValue[0] == verificationResponsePermissionGranted, nil
}

// tiOctet builds the combined Transaction-Identifier/Protocol-Discriminator
// octet (TS 24.007 §11.2.3.1.1: bits 8-5 = TI, bits 4-1 = PD). reflected
// selects the TI flag: false for a message the MME originates (flag 0),
// true for the UE's reflected response (flag 1).
func tiOctet(reflected bool) byte {
	flag := byte(0)
	if reflected {
		flag = 1
	}
	return (flag<<3|fixedTransactionID)<<4 | pdSupplementaryServices
}

// tlv encodes a BER tag-length-value using the short-form length encoding
// (values are always a handful of bytes in this package).
func tlv(tag byte, value []byte) []byte {
	out := make([]byte, 0, 2+len(value))
	out = append(out, tag, byte(len(value)))
	return append(out, value...)
}

// readTLV parses one BER TLV using the short-form length encoding this
// package always emits. It returns the tag, the value, and any bytes
// following the value.
func readTLV(b []byte) (tag byte, value, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, fmt.Errorf("lcsnotify: truncated TLV")
	}
	length := int(b[1])
	if length&0x80 != 0 {
		return 0, nil, nil, fmt.Errorf("lcsnotify: unsupported long-form BER length")
	}
	if len(b) < 2+length {
		return 0, nil, nil, fmt.Errorf("lcsnotify: truncated TLV value")
	}
	return b[0], b[2 : 2+length], b[2+length:], nil
}
