package sgsap

import (
	"fmt"

	"github.com/vectorcore/mme/internal/nas/emm"
)

// --- SGsAP-RESET-INDICATION / SGsAP-RESET-ACK (§8.15, §8.16) ---
//
// Both messages carry the sender's own identity: MMEName when the MME is
// the sender, VLRName when the VLR is the sender. Exactly one is present.
type Reset struct {
	MMEName string
	VLRName string
}

func buildReset(msgType uint8, r Reset) []byte {
	e := newEncoder(msgType)
	if r.MMEName != "" {
		e.put(ieMMEName, EncodeMMEName(r.MMEName))
	}
	if r.VLRName != "" {
		e.put(ieVLRName, EncodeVLRName(r.VLRName))
	}
	return e.bytes()
}

func decodeReset(data []byte, want uint8) (*Reset, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != want {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want %#x", p.msgType, want)
	}
	r := &Reset{}
	if v, ok := p.find(ieMMEName); ok {
		if r.MMEName, err = DecodeMMEName(v); err != nil {
			return nil, err
		}
	}
	if v, ok := p.find(ieVLRName); ok {
		if r.VLRName, err = DecodeVLRName(v); err != nil {
			return nil, err
		}
	}
	if r.MMEName == "" && r.VLRName == "" {
		return nil, fmt.Errorf("sgsap: reset message has neither MME name nor VLR name")
	}
	return r, nil
}

func BuildResetIndication(r Reset) []byte               { return buildReset(MsgResetIndication, r) }
func DecodeResetIndication(data []byte) (*Reset, error) { return decodeReset(data, MsgResetIndication) }
func BuildResetAck(r Reset) []byte                      { return buildReset(MsgResetAck, r) }
func DecodeResetAck(data []byte) (*Reset, error)        { return decodeReset(data, MsgResetAck) }

// --- SGsAP-LOCATION-UPDATE-REQUEST (§8.11, MME -> VLR) ---

type LocationUpdateRequest struct {
	IMSI       string
	MMEName    string
	UpdateType EPSLocationUpdateType
	NewLAI     LAI
	OldLAI     *LAI
	// TMSIStatusValid is set only when the UE's TMSI status must be signalled
	// (the MME received TMSI status "no valid TMSI" from the UE).
	TMSIStatusValid *bool
	IMEISV          string // optional; 16 digits when present
	TAI             *TAI
	ECGI            *ECGI
}

func BuildLocationUpdateRequest(r LocationUpdateRequest) ([]byte, error) {
	if r.IMSI == "" || r.MMEName == "" {
		return nil, fmt.Errorf("sgsap: location update request requires IMSI and MME name")
	}
	e := newEncoder(MsgLocationUpdateRequest)
	e.put(ieIMSI, EncodeIMSI(r.IMSI))
	e.put(ieMMEName, EncodeMMEName(r.MMEName))
	e.put(ieEPSLocationUpdateType, EncodeEPSLocationUpdateType(r.UpdateType))
	newLAI := r.NewLAI
	e.put(ieLAI, newLAI.Encode())
	if r.OldLAI != nil {
		oldLAI := *r.OldLAI
		e.put(ieLAI, oldLAI.Encode())
	}
	if r.TMSIStatusValid != nil {
		e.put(ieTMSIStatus, EncodeTMSIStatus(*r.TMSIStatusValid))
	}
	if r.IMEISV != "" {
		v, err := EncodeIMEISV(r.IMEISV)
		if err != nil {
			return nil, err
		}
		e.put(ieIMEISV, v)
	}
	if r.TAI != nil {
		tai := *r.TAI
		e.put(ieTAI, tai.Encode())
	}
	if r.ECGI != nil {
		e.put(ieECGI, EncodeECGI(*r.ECGI))
	}
	return e.bytes(), nil
}

// DecodeLocationUpdateRequest decodes a SGsAP-LOCATION-UPDATE-REQUEST. When
// both an old and new location area identifier are present, the wire order
// (new first, then old) from BuildLocationUpdateRequest is assumed, matching
// how this MME sends the message; a peer implementation is not required to
// preserve that order, so this decoder is primarily for tests/loopback.
func DecodeLocationUpdateRequest(data []byte) (*LocationUpdateRequest, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgLocationUpdateRequest {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want LOCATION-UPDATE-REQUEST", p.msgType)
	}
	r := &LocationUpdateRequest{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if r.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	nameV, err := p.require(ieMMEName, "MME name")
	if err != nil {
		return nil, err
	}
	if r.MMEName, err = DecodeMMEName(nameV); err != nil {
		return nil, err
	}
	typeV, err := p.require(ieEPSLocationUpdateType, "EPS location update type")
	if err != nil {
		return nil, err
	}
	if r.UpdateType, err = DecodeEPSLocationUpdateType(typeV); err != nil {
		return nil, err
	}
	var lais [][]byte
	for _, ie := range p.ies {
		if ie.iei == ieLAI {
			lais = append(lais, ie.value)
		}
	}
	if len(lais) == 0 {
		return nil, fmt.Errorf("sgsap: location update request missing new location area identifier")
	}
	newLAI, err := emm.DecodeLAI(lais[0])
	if err != nil {
		return nil, err
	}
	r.NewLAI = newLAI
	if len(lais) > 1 {
		oldLAI, err := emm.DecodeLAI(lais[1])
		if err != nil {
			return nil, err
		}
		r.OldLAI = &oldLAI
	}
	if v, ok := p.find(ieTMSIStatus); ok {
		valid, err := DecodeTMSIStatus(v)
		if err != nil {
			return nil, err
		}
		r.TMSIStatusValid = &valid
	}
	if v, ok := p.find(ieIMEISV); ok {
		if r.IMEISV, err = DecodeIMEISV(v); err != nil {
			return nil, err
		}
	}
	if v, ok := p.find(ieTAI); ok {
		tai, err := emm.DecodeTAI(v)
		if err != nil {
			return nil, err
		}
		r.TAI = &tai
	}
	if v, ok := p.find(ieECGI); ok {
		ecgi, err := DecodeECGI(v)
		if err != nil {
			return nil, err
		}
		r.ECGI = &ecgi
	}
	return r, nil
}

// --- SGsAP-LOCATION-UPDATE-ACCEPT (§8.9, VLR -> MME) ---

type LocationUpdateAccept struct {
	IMSI        string
	LAI         LAI
	NewIdentity *MobileIdentity // optional "New TMSI, or IMSI"
}

func BuildLocationUpdateAccept(a LocationUpdateAccept) ([]byte, error) {
	if a.IMSI == "" {
		return nil, fmt.Errorf("sgsap: location update accept requires IMSI")
	}
	e := newEncoder(MsgLocationUpdateAccept)
	e.put(ieIMSI, EncodeIMSI(a.IMSI))
	lai := a.LAI
	e.put(ieLAI, lai.Encode())
	if a.NewIdentity != nil {
		e.put(ieMobileIdentity, EncodeMobileIdentity(*a.NewIdentity))
	}
	return e.bytes(), nil
}

func DecodeLocationUpdateAccept(data []byte) (*LocationUpdateAccept, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgLocationUpdateAccept {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want LOCATION-UPDATE-ACCEPT", p.msgType)
	}
	a := &LocationUpdateAccept{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if a.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	laiV, err := p.require(ieLAI, "location area identifier")
	if err != nil {
		return nil, err
	}
	if a.LAI, err = emm.DecodeLAI(laiV); err != nil {
		return nil, err
	}
	if v, ok := p.find(ieMobileIdentity); ok {
		id, err := DecodeMobileIdentity(v)
		if err != nil {
			return nil, err
		}
		a.NewIdentity = &id
	}
	return a, nil
}

// --- SGsAP-LOCATION-UPDATE-REJECT (§8.10, VLR -> MME) ---

type LocationUpdateReject struct {
	IMSI  string
	Cause uint8 // TS 24.008 reject cause value
	LAI   *LAI
}

func BuildLocationUpdateReject(r LocationUpdateReject) ([]byte, error) {
	if r.IMSI == "" {
		return nil, fmt.Errorf("sgsap: location update reject requires IMSI")
	}
	e := newEncoder(MsgLocationUpdateReject)
	e.put(ieIMSI, EncodeIMSI(r.IMSI))
	e.put(ieRejectCause, EncodeRejectCause(r.Cause))
	if r.LAI != nil {
		lai := *r.LAI
		e.put(ieLAI, lai.Encode())
	}
	return e.bytes(), nil
}

func DecodeLocationUpdateReject(data []byte) (*LocationUpdateReject, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgLocationUpdateReject {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want LOCATION-UPDATE-REJECT", p.msgType)
	}
	r := &LocationUpdateReject{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if r.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	causeV, err := p.require(ieRejectCause, "reject cause")
	if err != nil {
		return nil, err
	}
	if r.Cause, err = DecodeRejectCause(causeV); err != nil {
		return nil, err
	}
	if v, ok := p.find(ieLAI); ok {
		lai, err := emm.DecodeLAI(v)
		if err != nil {
			return nil, err
		}
		r.LAI = &lai
	}
	return r, nil
}

// --- messages that carry only an IMSI ---

func buildIMSIOnly(msgType uint8, imsi string) ([]byte, error) {
	if imsi == "" {
		return nil, fmt.Errorf("sgsap: message requires IMSI")
	}
	e := newEncoder(msgType)
	e.put(ieIMSI, EncodeIMSI(imsi))
	return e.bytes(), nil
}

func decodeIMSIOnly(data []byte, want uint8) (string, error) {
	p, err := decodePDU(data)
	if err != nil {
		return "", err
	}
	if p.msgType != want {
		return "", fmt.Errorf("sgsap: unexpected message type %#x, want %#x", p.msgType, want)
	}
	v, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return "", err
	}
	return DecodeIMSI(v)
}

func BuildTMSIReallocationComplete(imsi string) ([]byte, error) {
	return buildIMSIOnly(MsgTMSIReallocComplete, imsi)
}
func DecodeTMSIReallocationComplete(data []byte) (string, error) {
	return decodeIMSIOnly(data, MsgTMSIReallocComplete)
}

func BuildAlertRequest(imsi string) ([]byte, error)  { return buildIMSIOnly(MsgAlertRequest, imsi) }
func DecodeAlertRequest(data []byte) (string, error) { return decodeIMSIOnly(data, MsgAlertRequest) }

func BuildAlertAck(imsi string) ([]byte, error)  { return buildIMSIOnly(MsgAlertAck, imsi) }
func DecodeAlertAck(data []byte) (string, error) { return decodeIMSIOnly(data, MsgAlertAck) }

func BuildServiceAbortRequest(imsi string) ([]byte, error) {
	return buildIMSIOnly(MsgServiceAbortRequest, imsi)
}
func DecodeServiceAbortRequest(data []byte) (string, error) {
	return decodeIMSIOnly(data, MsgServiceAbortRequest)
}

func BuildEPSDetachAck(imsi string) ([]byte, error)  { return buildIMSIOnly(MsgEPSDetachAck, imsi) }
func DecodeEPSDetachAck(data []byte) (string, error) { return decodeIMSIOnly(data, MsgEPSDetachAck) }

func BuildIMSIDetachAck(imsi string) ([]byte, error) { return buildIMSIOnly(MsgIMSIDetachAck, imsi) }
func DecodeIMSIDetachAck(data []byte) (string, error) {
	return decodeIMSIOnly(data, MsgIMSIDetachAck)
}

// --- messages that carry IMSI + SGs cause ---

func buildIMSICause(msgType uint8, imsi string, cause Cause) ([]byte, error) {
	if imsi == "" {
		return nil, fmt.Errorf("sgsap: message requires IMSI")
	}
	e := newEncoder(msgType)
	e.put(ieIMSI, EncodeIMSI(imsi))
	e.put(ieSGsCause, EncodeSGsCause(cause))
	return e.bytes(), nil
}

func decodeIMSICause(data []byte, want uint8) (imsi string, cause Cause, err error) {
	p, err := decodePDU(data)
	if err != nil {
		return "", 0, err
	}
	if p.msgType != want {
		return "", 0, fmt.Errorf("sgsap: unexpected message type %#x, want %#x", p.msgType, want)
	}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return "", 0, err
	}
	if imsi, err = DecodeIMSI(imsiV); err != nil {
		return "", 0, err
	}
	causeV, err := p.require(ieSGsCause, "SGs cause")
	if err != nil {
		return "", 0, err
	}
	cause, err = DecodeSGsCause(causeV)
	return imsi, cause, err
}

func BuildAlertReject(imsi string, cause Cause) ([]byte, error) {
	return buildIMSICause(MsgAlertReject, imsi, cause)
}
func DecodeAlertReject(data []byte) (string, Cause, error) {
	return decodeIMSICause(data, MsgAlertReject)
}

func BuildPagingReject(imsi string, cause Cause) ([]byte, error) {
	return buildIMSICause(MsgPagingReject, imsi, cause)
}
func DecodePagingReject(data []byte) (string, Cause, error) {
	return decodeIMSICause(data, MsgPagingReject)
}

// --- SGsAP-RELEASE-REQUEST (§8.23, VLR -> MME): IMSI + optional cause ---

func BuildReleaseRequest(imsi string, cause *Cause) ([]byte, error) {
	if imsi == "" {
		return nil, fmt.Errorf("sgsap: release request requires IMSI")
	}
	e := newEncoder(MsgReleaseRequest)
	e.put(ieIMSI, EncodeIMSI(imsi))
	if cause != nil {
		e.put(ieSGsCause, EncodeSGsCause(*cause))
	}
	return e.bytes(), nil
}

func DecodeReleaseRequest(data []byte) (imsi string, cause *Cause, err error) {
	p, err := decodePDU(data)
	if err != nil {
		return "", nil, err
	}
	if p.msgType != MsgReleaseRequest {
		return "", nil, fmt.Errorf("sgsap: unexpected message type %#x, want RELEASE-REQUEST", p.msgType)
	}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return "", nil, err
	}
	if imsi, err = DecodeIMSI(imsiV); err != nil {
		return "", nil, err
	}
	if v, ok := p.find(ieSGsCause); ok {
		c, err := DecodeSGsCause(v)
		if err != nil {
			return "", nil, err
		}
		cause = &c
	}
	return imsi, cause, nil
}

// --- SGsAP-UE-UNREACHABLE (§8.21, MME -> VLR) ---

type UEUnreachable struct {
	IMSI  string
	Cause Cause
	// Requested Retransmission Time and Additional UE Unreachable indicators
	// (Deployment Option 2, TS 23.272 §8.2.4a.1) are intentionally not
	// modeled: this MME does not implement Deployment Option 2.
}

func BuildUEUnreachable(u UEUnreachable) ([]byte, error) {
	return buildIMSICause(MsgUEUnreachable, u.IMSI, u.Cause)
}

func DecodeUEUnreachable(data []byte) (*UEUnreachable, error) {
	imsi, cause, err := decodeIMSICause(data, MsgUEUnreachable)
	if err != nil {
		return nil, err
	}
	return &UEUnreachable{IMSI: imsi, Cause: cause}, nil
}

// --- SGsAP-EPS-DETACH-INDICATION / SGsAP-IMSI-DETACH-INDICATION (MME -> VLR) ---

type EPSDetachIndication struct {
	IMSI       string
	MMEName    string
	DetachType EPSDetachType
}

func BuildEPSDetachIndication(d EPSDetachIndication) ([]byte, error) {
	if d.IMSI == "" || d.MMEName == "" {
		return nil, fmt.Errorf("sgsap: EPS detach indication requires IMSI and MME name")
	}
	e := newEncoder(MsgEPSDetachIndication)
	e.put(ieIMSI, EncodeIMSI(d.IMSI))
	e.put(ieMMEName, EncodeMMEName(d.MMEName))
	e.put(ieIMSIDetachFromEPSType, EncodeEPSDetachType(d.DetachType))
	return e.bytes(), nil
}

func DecodeEPSDetachIndication(data []byte) (*EPSDetachIndication, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgEPSDetachIndication {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want EPS-DETACH-INDICATION", p.msgType)
	}
	d := &EPSDetachIndication{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if d.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	nameV, err := p.require(ieMMEName, "MME name")
	if err != nil {
		return nil, err
	}
	if d.MMEName, err = DecodeMMEName(nameV); err != nil {
		return nil, err
	}
	typeV, err := p.require(ieIMSIDetachFromEPSType, "IMSI detach from EPS service type")
	if err != nil {
		return nil, err
	}
	if len(typeV) != 1 {
		return nil, fmt.Errorf("sgsap: IMSI detach from EPS service type must be 1 octet")
	}
	d.DetachType = EPSDetachType(typeV[0])
	return d, nil
}

type IMSIDetachIndication struct {
	IMSI       string
	MMEName    string
	DetachType NonEPSDetachType
}

func BuildIMSIDetachIndication(d IMSIDetachIndication) ([]byte, error) {
	if d.IMSI == "" || d.MMEName == "" {
		return nil, fmt.Errorf("sgsap: IMSI detach indication requires IMSI and MME name")
	}
	e := newEncoder(MsgIMSIDetachIndication)
	e.put(ieIMSI, EncodeIMSI(d.IMSI))
	e.put(ieMMEName, EncodeMMEName(d.MMEName))
	e.put(ieIMSIDetachFromNonEPSType, EncodeNonEPSDetachType(d.DetachType))
	return e.bytes(), nil
}

func DecodeIMSIDetachIndication(data []byte) (*IMSIDetachIndication, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgIMSIDetachIndication {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want IMSI-DETACH-INDICATION", p.msgType)
	}
	d := &IMSIDetachIndication{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if d.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	nameV, err := p.require(ieMMEName, "MME name")
	if err != nil {
		return nil, err
	}
	if d.MMEName, err = DecodeMMEName(nameV); err != nil {
		return nil, err
	}
	typeV, err := p.require(ieIMSIDetachFromNonEPSType, "IMSI detach from non-EPS service type")
	if err != nil {
		return nil, err
	}
	if len(typeV) != 1 {
		return nil, fmt.Errorf("sgsap: IMSI detach from non-EPS service type must be 1 octet")
	}
	d.DetachType = NonEPSDetachType(typeV[0])
	return d, nil
}

// --- SGsAP-DOWNLINK-UNITDATA / SGsAP-UPLINK-UNITDATA (§8.4, §8.22) ---

type DownlinkUnitdata struct {
	IMSI                string
	NASMessageContainer []byte
}

func BuildDownlinkUnitdata(d DownlinkUnitdata) ([]byte, error) {
	if d.IMSI == "" || len(d.NASMessageContainer) == 0 {
		return nil, fmt.Errorf("sgsap: downlink unitdata requires IMSI and NAS message container")
	}
	e := newEncoder(MsgDownlinkUnitdata)
	e.put(ieIMSI, EncodeIMSI(d.IMSI))
	e.put(ieNASMessageContainer, EncodeNASMessageContainer(d.NASMessageContainer))
	return e.bytes(), nil
}

func DecodeDownlinkUnitdata(data []byte) (*DownlinkUnitdata, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgDownlinkUnitdata {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want DOWNLINK-UNITDATA", p.msgType)
	}
	d := &DownlinkUnitdata{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if d.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	nasV, err := p.require(ieNASMessageContainer, "NAS message container")
	if err != nil {
		return nil, err
	}
	d.NASMessageContainer = DecodeNASMessageContainer(nasV)
	return d, nil
}

type UplinkUnitdata struct {
	IMSI                string
	NASMessageContainer []byte
	IMEISV              string
	UETimeZone          *byte
	TAI                 *TAI
	ECGI                *ECGI
}

func BuildUplinkUnitdata(u UplinkUnitdata) ([]byte, error) {
	if u.IMSI == "" || len(u.NASMessageContainer) == 0 {
		return nil, fmt.Errorf("sgsap: uplink unitdata requires IMSI and NAS message container")
	}
	e := newEncoder(MsgUplinkUnitdata)
	e.put(ieIMSI, EncodeIMSI(u.IMSI))
	e.put(ieNASMessageContainer, EncodeNASMessageContainer(u.NASMessageContainer))
	if u.IMEISV != "" {
		v, err := EncodeIMEISV(u.IMEISV)
		if err != nil {
			return nil, err
		}
		e.put(ieIMEISV, v)
	}
	if u.UETimeZone != nil {
		e.put(ieUETimeZone, EncodeUETimeZone(*u.UETimeZone))
	}
	if u.TAI != nil {
		tai := *u.TAI
		e.put(ieTAI, tai.Encode())
	}
	if u.ECGI != nil {
		e.put(ieECGI, EncodeECGI(*u.ECGI))
	}
	return e.bytes(), nil
}

func DecodeUplinkUnitdata(data []byte) (*UplinkUnitdata, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgUplinkUnitdata {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want UPLINK-UNITDATA", p.msgType)
	}
	u := &UplinkUnitdata{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if u.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	nasV, err := p.require(ieNASMessageContainer, "NAS message container")
	if err != nil {
		return nil, err
	}
	u.NASMessageContainer = DecodeNASMessageContainer(nasV)
	if v, ok := p.find(ieIMEISV); ok {
		if u.IMEISV, err = DecodeIMEISV(v); err != nil {
			return nil, err
		}
	}
	if v, ok := p.find(ieUETimeZone); ok {
		tz, err := DecodeUETimeZone(v)
		if err != nil {
			return nil, err
		}
		u.UETimeZone = &tz
	}
	if v, ok := p.find(ieTAI); ok {
		tai, err := emm.DecodeTAI(v)
		if err != nil {
			return nil, err
		}
		u.TAI = &tai
	}
	if v, ok := p.find(ieECGI); ok {
		ecgi, err := DecodeECGI(v)
		if err != nil {
			return nil, err
		}
		u.ECGI = &ecgi
	}
	return u, nil
}

// --- SGsAP-SERVICE-REQUEST (§8.17, MME -> VLR) ---

type ServiceRequest struct {
	IMSI             string
	ServiceIndicator ServiceIndicator
	IMEISV           string
	UETimeZone       *byte
	TAI              *TAI
	ECGI             *ECGI
	UEEMMMode        UEEMMMode
}

func BuildServiceRequest(r ServiceRequest) ([]byte, error) {
	if r.IMSI == "" {
		return nil, fmt.Errorf("sgsap: service request requires IMSI")
	}
	e := newEncoder(MsgServiceRequest)
	e.put(ieIMSI, EncodeIMSI(r.IMSI))
	e.put(ieServiceIndicator, EncodeServiceIndicator(r.ServiceIndicator))
	if r.IMEISV != "" {
		v, err := EncodeIMEISV(r.IMEISV)
		if err != nil {
			return nil, err
		}
		e.put(ieIMEISV, v)
	}
	if r.UETimeZone != nil {
		e.put(ieUETimeZone, EncodeUETimeZone(*r.UETimeZone))
	}
	if r.TAI != nil {
		tai := *r.TAI
		e.put(ieTAI, tai.Encode())
	}
	if r.ECGI != nil {
		e.put(ieECGI, EncodeECGI(*r.ECGI))
	}
	e.put(ieUEEMMMode, EncodeUEEMMMode(r.UEEMMMode))
	return e.bytes(), nil
}

func DecodeServiceRequest(data []byte) (*ServiceRequest, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgServiceRequest {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want SERVICE-REQUEST", p.msgType)
	}
	r := &ServiceRequest{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if r.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	siV, err := p.require(ieServiceIndicator, "service indicator")
	if err != nil {
		return nil, err
	}
	if r.ServiceIndicator, err = DecodeServiceIndicator(siV); err != nil {
		return nil, err
	}
	if v, ok := p.find(ieIMEISV); ok {
		if r.IMEISV, err = DecodeIMEISV(v); err != nil {
			return nil, err
		}
	}
	if v, ok := p.find(ieUETimeZone); ok {
		tz, err := DecodeUETimeZone(v)
		if err != nil {
			return nil, err
		}
		r.UETimeZone = &tz
	}
	if v, ok := p.find(ieTAI); ok {
		tai, err := emm.DecodeTAI(v)
		if err != nil {
			return nil, err
		}
		r.TAI = &tai
	}
	if v, ok := p.find(ieECGI); ok {
		ecgi, err := DecodeECGI(v)
		if err != nil {
			return nil, err
		}
		r.ECGI = &ecgi
	}
	if v, ok := p.find(ieUEEMMMode); ok {
		if r.UEEMMMode, err = DecodeUEEMMMode(v); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// --- SGsAP-PAGING-REQUEST (§8.14, VLR -> MME) ---
//
// Only the fields this MME acts on are modeled: IMSI, VLR name, service
// indicator (mandatory), and TMSI/LAI (used for paging response matching
// and CS-restoration). CLI, Global CN-Id, SS code, LCS*, Channel needed,
// eMLPP priority, additional paging indicators, and the Deployment-Option-2
// SM delivery timer fields are intentionally not modeled: this MME does not
// implement CLI presentation, LCS-triggered paging, eMLPP, or Deployment
// Option 2. A peer that sends them is still decoded successfully - the
// extra IEs are simply not surfaced.
type PagingRequest struct {
	IMSI             string
	VLRName          string
	ServiceIndicator ServiceIndicator
	TMSI             *uint32
	LAI              *LAI
}

func BuildPagingRequest(r PagingRequest) ([]byte, error) {
	if r.IMSI == "" || r.VLRName == "" {
		return nil, fmt.Errorf("sgsap: paging request requires IMSI and VLR name")
	}
	e := newEncoder(MsgPagingRequest)
	e.put(ieIMSI, EncodeIMSI(r.IMSI))
	e.put(ieVLRName, EncodeVLRName(r.VLRName))
	e.put(ieServiceIndicator, EncodeServiceIndicator(r.ServiceIndicator))
	if r.TMSI != nil {
		e.put(ieTMSI, EncodeTMSI(*r.TMSI))
	}
	if r.LAI != nil {
		lai := *r.LAI
		e.put(ieLAI, lai.Encode())
	}
	return e.bytes(), nil
}

func DecodePagingRequest(data []byte) (*PagingRequest, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgPagingRequest {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want PAGING-REQUEST", p.msgType)
	}
	r := &PagingRequest{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if r.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	nameV, err := p.require(ieVLRName, "VLR name")
	if err != nil {
		return nil, err
	}
	if r.VLRName, err = DecodeVLRName(nameV); err != nil {
		return nil, err
	}
	siV, err := p.require(ieServiceIndicator, "service indicator")
	if err != nil {
		return nil, err
	}
	if r.ServiceIndicator, err = DecodeServiceIndicator(siV); err != nil {
		return nil, err
	}
	if v, ok := p.find(ieTMSI); ok {
		tmsi, err := DecodeTMSI(v)
		if err != nil {
			return nil, err
		}
		r.TMSI = &tmsi
	}
	if v, ok := p.find(ieLAI); ok {
		lai, err := emm.DecodeLAI(v)
		if err != nil {
			return nil, err
		}
		r.LAI = &lai
	}
	return r, nil
}

// --- SGsAP-MM-INFORMATION-REQUEST (§8.12, VLR -> MME) ---
//
// MMInformation is carried opaquely: it is a TS 24.008 MM information
// message body (minus PD/skip/message type) that the MME relays to the UE
// unparsed, the same pattern as NAS message container.
type MMInformationRequest struct {
	IMSI          string
	MMInformation []byte
}

func BuildMMInformationRequest(r MMInformationRequest) ([]byte, error) {
	if r.IMSI == "" || len(r.MMInformation) == 0 {
		return nil, fmt.Errorf("sgsap: MM information request requires IMSI and MM information")
	}
	e := newEncoder(MsgMMInformationRequest)
	e.put(ieIMSI, EncodeIMSI(r.IMSI))
	e.put(ieMMInformation, append([]byte(nil), r.MMInformation...))
	return e.bytes(), nil
}

func DecodeMMInformationRequest(data []byte) (*MMInformationRequest, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgMMInformationRequest {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want MM-INFORMATION-REQUEST", p.msgType)
	}
	r := &MMInformationRequest{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if r.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	mmV, err := p.require(ieMMInformation, "MM information")
	if err != nil {
		return nil, err
	}
	r.MMInformation = append([]byte(nil), mmV...)
	return r, nil
}

// --- SGsAP-STATUS (§8.18, both directions) ---

type Status struct {
	IMSI             string // optional
	Cause            Cause
	ErroneousMessage []byte // message type + IEs of the offending message
}

func BuildStatus(s Status) ([]byte, error) {
	if len(s.ErroneousMessage) == 0 {
		return nil, fmt.Errorf("sgsap: status requires the erroneous message")
	}
	e := newEncoder(MsgStatus)
	if s.IMSI != "" {
		e.put(ieIMSI, EncodeIMSI(s.IMSI))
	}
	e.put(ieSGsCause, EncodeSGsCause(s.Cause))
	e.put(ieErroneousMessage, append([]byte(nil), s.ErroneousMessage...))
	return e.bytes(), nil
}

func DecodeStatus(data []byte) (*Status, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgStatus {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want STATUS", p.msgType)
	}
	s := &Status{}
	if v, ok := p.find(ieIMSI); ok {
		if s.IMSI, err = DecodeIMSI(v); err != nil {
			return nil, err
		}
	}
	causeV, err := p.require(ieSGsCause, "SGs cause")
	if err != nil {
		return nil, err
	}
	if s.Cause, err = DecodeSGsCause(causeV); err != nil {
		return nil, err
	}
	errV, err := p.require(ieErroneousMessage, "erroneous message")
	if err != nil {
		return nil, err
	}
	s.ErroneousMessage = append([]byte(nil), errV...)
	return s, nil
}

// --- SGsAP-UE-ACTIVITY-INDICATION (§8.20, MME -> VLR) ---
//
// Maximum UE Availability Time (Deployment Option 2) is not modeled.
func BuildUEActivityIndication(imsi string) ([]byte, error) {
	return buildIMSIOnly(MsgUEActivityIndication, imsi)
}
func DecodeUEActivityIndication(data []byte) (string, error) {
	return decodeIMSIOnly(data, MsgUEActivityIndication)
}

// --- SGsAP-MO-CSFB-INDICATION (§8.25, MME -> VLR) ---

type MOCSFBIndication struct {
	IMSI string
	TAI  *TAI
	ECGI *ECGI
}

func BuildMOCSFBIndication(m MOCSFBIndication) ([]byte, error) {
	if m.IMSI == "" {
		return nil, fmt.Errorf("sgsap: MO-CSFB indication requires IMSI")
	}
	e := newEncoder(MsgMOCSFBIndication)
	e.put(ieIMSI, EncodeIMSI(m.IMSI))
	if m.TAI != nil {
		tai := *m.TAI
		e.put(ieTAI, tai.Encode())
	}
	if m.ECGI != nil {
		e.put(ieECGI, EncodeECGI(*m.ECGI))
	}
	return e.bytes(), nil
}

func DecodeMOCSFBIndication(data []byte) (*MOCSFBIndication, error) {
	p, err := decodePDU(data)
	if err != nil {
		return nil, err
	}
	if p.msgType != MsgMOCSFBIndication {
		return nil, fmt.Errorf("sgsap: unexpected message type %#x, want MO-CSFB-INDICATION", p.msgType)
	}
	m := &MOCSFBIndication{}
	imsiV, err := p.require(ieIMSI, "IMSI")
	if err != nil {
		return nil, err
	}
	if m.IMSI, err = DecodeIMSI(imsiV); err != nil {
		return nil, err
	}
	if v, ok := p.find(ieTAI); ok {
		tai, err := emm.DecodeTAI(v)
		if err != nil {
			return nil, err
		}
		m.TAI = &tai
	}
	if v, ok := p.find(ieECGI); ok {
		ecgi, err := DecodeECGI(v)
		if err != nil {
			return nil, err
		}
		m.ECGI = &ecgi
	}
	return m, nil
}
