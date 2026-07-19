package gtpv2

import "fmt"

type DownlinkDataNotification struct {
	TEID               uint32
	SeqNum             uint32
	Cause              *uint8
	EBI                *uint8
	ARP                *uint8
	IMSI               string
	SenderFTEID        *FTEID
	DelayValue         *uint8
	PagingServiceInfo  []byte
	LowPriorityRawIEs  []IE
	AdditionalEBIRawIE []IE
}

type DownlinkDataNotificationAck struct {
	Cause      uint8
	DelayValue *uint8
}

type DownlinkDataNotificationFailureIndication struct {
	Cause uint8
	IMSI  string
}

func DecodeDownlinkDataNotification(m *Message) (*DownlinkDataNotification, error) {
	if m.Type != MsgDownlinkDataNotification {
		return nil, fmt.Errorf("gtpv2: expected Downlink Data Notification (176), got %d", m.Type)
	}
	req := &DownlinkDataNotification{TEID: m.TEID, SeqNum: m.SeqNum}
	for _, ie := range m.IEs {
		switch ie.Type {
		case IETypeCause:
			cause, err := DecodeCause(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid DDN Cause IE: %v", ErrMandatoryIEIncorrect, err)
			}
			req.Cause = &cause
		case IETypeEBI:
			ebi, err := DecodeEBI(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid DDN EBI IE: %v", ErrMandatoryIEIncorrect, err)
			}
			if req.EBI == nil {
				req.EBI = &ebi
			} else {
				req.AdditionalEBIRawIE = append(req.AdditionalEBIRawIE, ie)
			}
		case IETypeARP:
			arp, err := DecodeARP(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid DDN ARP IE: %v", ErrMandatoryIEIncorrect, err)
			}
			req.ARP = &arp
		case IETypeIMSI:
			imsi, err := DecodeIMSI(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid DDN IMSI IE: %v", ErrMandatoryIEIncorrect, err)
			}
			req.IMSI = imsi
		case IETypeFTEID:
			fteid, err := DecodeFTEID(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid DDN Sender F-TEID IE: %v", ErrMandatoryIEIncorrect, err)
			}
			req.SenderFTEID = fteid
		case IETypeDelayValue:
			delay, err := DecodeDelayValue(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid DDN Delay Value IE: %v", ErrMandatoryIEIncorrect, err)
			}
			req.DelayValue = &delay
		case IETypePagingSvcInfo:
			req.PagingServiceInfo = append([]byte(nil), ie.Value...)
		default:
			req.LowPriorityRawIEs = append(req.LowPriorityRawIEs, ie)
		}
	}
	return req, nil
}

func EncodeDownlinkDataNotificationAck(teid uint32, seq uint32, cause uint8, delayValue *uint8) []byte {
	ies := []IE{EncodeCause(cause)}
	if delayValue != nil {
		ies = append(ies, EncodeDelayValue(*delayValue))
	}
	return Encode(&Message{
		Type:   MsgDownlinkDataNotificationAck,
		TEID:   teid,
		SeqNum: seq,
		IEs:    ies,
	})
}

func DecodeDownlinkDataNotificationAck(m *Message) (*DownlinkDataNotificationAck, error) {
	if m.Type != MsgDownlinkDataNotificationAck {
		return nil, fmt.Errorf("gtpv2: expected Downlink Data Notification Ack (177), got %d", m.Type)
	}
	causeIE := FindIE(m.IEs, IETypeCause, 0)
	if causeIE == nil {
		return nil, fmt.Errorf("%w: DDN Ack missing Cause", ErrMandatoryIEMissing)
	}
	cause, err := DecodeCause(causeIE)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DDN Ack Cause IE: %v", ErrMandatoryIEIncorrect, err)
	}
	resp := &DownlinkDataNotificationAck{Cause: cause}
	if delayIE := FindIE(m.IEs, IETypeDelayValue, 0); delayIE != nil {
		delay, err := DecodeDelayValue(delayIE)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid DDN Ack Delay Value IE: %v", ErrMandatoryIEIncorrect, err)
		}
		resp.DelayValue = &delay
	}
	return resp, nil
}

func EncodeDownlinkDataNotificationFailureIndication(teid uint32, seq uint32, cause uint8, imsi string) []byte {
	ies := []IE{EncodeCause(cause)}
	if imsi != "" {
		ies = append(ies, EncodeIMSI(imsi))
	}
	return Encode(&Message{
		Type:   MsgDownlinkDataNotificationFail,
		TEID:   teid,
		SeqNum: seq,
		IEs:    ies,
	})
}

func DecodeDownlinkDataNotificationFailureIndication(m *Message) (*DownlinkDataNotificationFailureIndication, error) {
	if m.Type != MsgDownlinkDataNotificationFail {
		return nil, fmt.Errorf("gtpv2: expected Downlink Data Notification Failure Indication (178), got %d", m.Type)
	}
	causeIE := FindIE(m.IEs, IETypeCause, 0)
	if causeIE == nil {
		return nil, fmt.Errorf("%w: DDN Failure Indication missing Cause", ErrMandatoryIEMissing)
	}
	cause, err := DecodeCause(causeIE)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DDN Failure Indication Cause IE: %v", ErrMandatoryIEIncorrect, err)
	}
	resp := &DownlinkDataNotificationFailureIndication{Cause: cause}
	if imsiIE := FindIE(m.IEs, IETypeIMSI, 0); imsiIE != nil {
		imsi, err := DecodeIMSI(imsiIE)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid DDN Failure Indication IMSI IE: %v", ErrMandatoryIEIncorrect, err)
		}
		resp.IMSI = imsi
	}
	return resp, nil
}
