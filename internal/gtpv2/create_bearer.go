package gtpv2

import (
	"fmt"
	"net"
)

type CreateBearerRequest struct {
	TEID      uint32
	SeqNum    uint32
	LinkedEBI uint8
	Bearers   []CreateBearerBearer
}

type CreateBearerBearer struct {
	// RequestedEBI is the EBI value carried inside the incoming Bearer Context.
	// Some SGW/PGW implementations send zero and expect the MME to allocate the
	// final dedicated EBI before NAS/S1AP activation.
	RequestedEBI       uint8
	AssignedEBI        uint8
	EBI                uint8
	Cause              uint8
	NeedsEBIAllocation bool
	QCI                uint8
	ARP                uint8
	BearerQoS          []byte
	TFT                []byte
	SGWS1UTEID         uint32
	SGWS1UIP           []byte
	PGWS5S8UTEID       uint32
	PGWS5S8UIP         []byte
	ENBS1UTEID         uint32
	ENBS1UIP           []byte
}

type CreateBearerResponseMeta struct {
	IncludeULI bool
	ULIPLMN    [3]byte
	ULITAC     uint16
	ULIECI     uint32
}

type UpdateBearerResponseMeta struct {
	IncludeULI bool
	ULIPLMN    [3]byte
	ULITAC     uint16
	ULIECI     uint32
}

type DeleteBearerResponseMeta struct {
	IncludeULI          bool
	ULIPLMN             [3]byte
	ULITAC              uint16
	ULIECI              uint32
	IncludeULITimestamp bool
	ULITimestamp        uint32
}

func DecodeCreateBearerRequest(m *Message) (*CreateBearerRequest, error) {
	if m.Type != MsgCreateBearerRequest {
		return nil, fmt.Errorf("gtpv2: expected Create Bearer Request (95), got %d", m.Type)
	}
	req := &CreateBearerRequest{TEID: m.TEID, SeqNum: m.SeqNum}
	linkedIE := FindIE(m.IEs, IETypeEBI, 0)
	if linkedIE == nil {
		return nil, fmt.Errorf("%w: Create Bearer Request missing Linked EPS Bearer ID", ErrMandatoryIEMissing)
	}
	linked, err := DecodeEBI(linkedIE)
	if err != nil {
		return nil, fmt.Errorf("%w: Create Bearer Request invalid Linked EPS Bearer ID: %v", ErrMandatoryIEIncorrect, err)
	}
	req.LinkedEBI = linked
	for _, ie := range m.IEs {
		if ie.Type != IETypeBearerContext {
			continue
		}
		children, err := FindGroupedIEs(&ie)
		if err != nil {
			return nil, err
		}
		var b CreateBearerBearer
		ebiIE := FindIE(children, IETypeEBI, 0)
		if ebiIE == nil {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context missing EPS Bearer ID", ErrMandatoryIEMissing)
		}
		ebi, err := DecodeEBI(ebiIE)
		if err != nil {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context invalid EPS Bearer ID: %v", ErrMandatoryIEIncorrect, err)
		}
		b.RequestedEBI = ebi
		b.EBI = ebi
		b.AssignedEBI = ebi
		b.NeedsEBIAllocation = ebi == 0
		if qosIE := FindIE(children, IETypeBearerQoS, 0); qosIE != nil {
			if len(qosIE.Value) < 2 {
				return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context invalid Bearer QoS", ErrMandatoryIEIncorrect)
			}
			b.BearerQoS = append([]byte(nil), qosIE.Value...)
			b.ARP = qosIE.Value[0]
			b.QCI = qosIE.Value[1]
		} else {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context missing Bearer Level QoS", ErrMandatoryIEMissing)
		}
		if tftIE := FindIE(children, IETypeTFT, 0); tftIE != nil {
			if len(tftIE.Value) == 0 {
				return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context invalid TFT", ErrMandatoryIEIncorrect)
			}
			b.TFT = append([]byte(nil), tftIE.Value...)
		} else {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context missing TFT", ErrMandatoryIEMissing)
		}
		sgwFTEIDIE := FindIE(children, IETypeFTEID, 0)
		if sgwFTEIDIE == nil {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context missing S1-U SGW F-TEID", ErrConditionalIEMissing)
		}
		fteid, err := DecodeFTEID(sgwFTEIDIE)
		if err != nil {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context invalid S1-U SGW F-TEID: %v", ErrMandatoryIEIncorrect, err)
		}
		b.SGWS1UTEID = fteid.TEID
		if fteid.IP != nil {
			b.SGWS1UIP = append([]byte(nil), fteid.IP...)
		}
		pgwFTEIDIE := FindIE(children, IETypeFTEID, 1)
		if pgwFTEIDIE == nil {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context missing S5/S8-U PGW F-TEID", ErrConditionalIEMissing)
		}
		if fteid, err := DecodeFTEID(pgwFTEIDIE); err == nil {
			b.PGWS5S8UTEID = fteid.TEID
			if fteid.IP != nil {
				b.PGWS5S8UIP = append([]byte(nil), fteid.IP...)
			}
		} else {
			return nil, fmt.Errorf("%w: Create Bearer Request Bearer Context invalid S5/S8-U PGW F-TEID: %v", ErrMandatoryIEIncorrect, err)
		}
		req.Bearers = append(req.Bearers, b)
	}
	if len(req.Bearers) == 0 {
		return nil, fmt.Errorf("%w: Create Bearer Request missing Bearer Context", ErrMandatoryIEMissing)
	}
	return req, nil
}

func AssignRequestedBearerIDs(bearers []CreateBearerBearer, used map[uint8]bool) error {
	if used == nil {
		used = map[uint8]bool{}
	}
	for i := range bearers {
		if bearers[i].EBI != 0 {
			if bearers[i].EBI < 5 || bearers[i].EBI > 15 {
				return fmt.Errorf("gtpv2: invalid requested EBI %d", bearers[i].EBI)
			}
			if used[bearers[i].EBI] {
				return fmt.Errorf("gtpv2: requested EBI %d already in use", bearers[i].EBI)
			}
			used[bearers[i].EBI] = true
			bearers[i].AssignedEBI = bearers[i].EBI
			continue
		}
		allocated := uint8(0)
		for ebi := uint8(5); ebi <= 15; ebi++ {
			if !used[ebi] {
				allocated = ebi
				break
			}
		}
		if allocated == 0 {
			return fmt.Errorf("gtpv2: no free EPS bearer identity")
		}
		bearers[i].EBI = allocated
		bearers[i].AssignedEBI = allocated
		bearers[i].NeedsEBIAllocation = false
		used[allocated] = true
	}
	return nil
}

func EncodeCreateBearerResponse(teid uint32, seq uint32, cause uint8, bearers []CreateBearerBearer) []byte {
	return EncodeCreateBearerResponseWithMeta(teid, seq, cause, bearers, nil)
}

func EncodeCreateBearerResponseWithMeta(teid uint32, seq uint32, cause uint8, bearers []CreateBearerBearer, meta *CreateBearerResponseMeta) []byte {
	ies := []IE{EncodeCause(cause)}
	if meta != nil && meta.IncludeULI {
		ies = append(ies, EncodeULI(meta.ULIPLMN, meta.ULITAC, meta.ULIECI))
	}
	for _, b := range bearers {
		ebi := b.AssignedEBI
		if ebi == 0 {
			ebi = b.EBI
		}
		bearerCause := b.Cause
		if bearerCause == 0 {
			bearerCause = cause
		}
		children := []IE{
			EncodeEBI(ebi, 0),
			EncodeCause(bearerCause),
		}
		if b.ENBS1UTEID != 0 && len(b.ENBS1UIP) == 4 {
			children = append(children, EncodeFTEID(IFTypeS1UENB, b.ENBS1UTEID, net.IP(b.ENBS1UIP), FTEIDInstanceSender))
		}
		if b.SGWS1UTEID != 0 && len(b.SGWS1UIP) == 4 {
			children = append(children, EncodeFTEID(IFTypeS1USGW, b.SGWS1UTEID, net.IP(b.SGWS1UIP), FTEIDInstanceSGWU))
		}
		ies = append(ies, EncodeGrouped(IETypeBearerContext, 0, children))
	}
	return Encode(&Message{
		Type:   MsgCreateBearerResponse,
		TEID:   teid,
		SeqNum: seq,
		IEs:    ies,
	})
}

type UpdateBearerRequest struct {
	TEID    uint32
	SeqNum  uint32
	Bearers []UpdateBearerBearer
	AMBR    []byte
}

type UpdateBearerBearer struct {
	EBI       uint8
	QCI       uint8
	ARP       uint8
	BearerQoS []byte
	TFT       []byte
	PCO       []byte
	AMBR      []byte
}

func DecodeUpdateBearerRequest(m *Message) (*UpdateBearerRequest, error) {
	if m.Type != MsgUpdateBearerRequest {
		return nil, fmt.Errorf("gtpv2: expected Update Bearer Request (97), got %d", m.Type)
	}
	req := &UpdateBearerRequest{TEID: m.TEID, SeqNum: m.SeqNum}
	if ambrIE := FindIE(m.IEs, IETypeAMBR, 0); ambrIE != nil {
		req.AMBR = append([]byte(nil), ambrIE.Value...)
	}
	for _, ie := range m.IEs {
		if ie.Type != IETypeBearerContext {
			continue
		}
		children, err := FindGroupedIEs(&ie)
		if err != nil {
			return nil, err
		}
		var b UpdateBearerBearer
		ebiIE := FindIE(children, IETypeEBI, 0)
		if ebiIE == nil {
			return nil, fmt.Errorf("%w: Update Bearer Request Bearer Context missing EPS Bearer ID", ErrMandatoryIEMissing)
		}
		ebi, err := DecodeEBI(ebiIE)
		if err != nil {
			return nil, fmt.Errorf("%w: Update Bearer Request Bearer Context invalid EPS Bearer ID: %v", ErrMandatoryIEIncorrect, err)
		}
		b.EBI = ebi
		if qosIE := FindIE(children, IETypeBearerQoS, 0); qosIE != nil {
			if len(qosIE.Value) < 2 {
				return nil, fmt.Errorf("%w: Update Bearer Request Bearer Context invalid Bearer QoS", ErrMandatoryIEIncorrect)
			}
			b.BearerQoS = append([]byte(nil), qosIE.Value...)
			b.ARP = qosIE.Value[0]
			b.QCI = qosIE.Value[1]
		}
		if tftIE := FindIE(children, IETypeTFT, 0); tftIE != nil {
			if len(tftIE.Value) == 0 {
				return nil, fmt.Errorf("%w: Update Bearer Request Bearer Context invalid TFT", ErrMandatoryIEIncorrect)
			}
			b.TFT = append([]byte(nil), tftIE.Value...)
		}
		if pcoIE := FindIE(children, IETypePCO, 0); pcoIE != nil {
			b.PCO = append([]byte(nil), pcoIE.Value...)
		}
		if ambrIE := FindIE(children, IETypeAMBR, 0); ambrIE != nil {
			b.AMBR = append([]byte(nil), ambrIE.Value...)
		}
		req.Bearers = append(req.Bearers, b)
	}
	if len(req.Bearers) == 0 {
		return nil, fmt.Errorf("%w: Update Bearer Request missing Bearer Context", ErrMandatoryIEMissing)
	}
	return req, nil
}

func EncodeUpdateBearerResponse(teid uint32, seq uint32, cause uint8, bearers []UpdateBearerBearer) []byte {
	return EncodeUpdateBearerResponseWithMeta(teid, seq, cause, bearers, nil)
}

func EncodeUpdateBearerResponseWithMeta(teid uint32, seq uint32, cause uint8, bearers []UpdateBearerBearer, meta *UpdateBearerResponseMeta) []byte {
	ies := []IE{EncodeCause(cause)}
	for _, b := range bearers {
		children := []IE{EncodeEBI(b.EBI, 0), EncodeCause(cause)}
		ies = append(ies, EncodeGrouped(IETypeBearerContext, 0, children))
	}
	if meta != nil && meta.IncludeULI {
		ies = append(ies, EncodeULI(meta.ULIPLMN, meta.ULITAC, meta.ULIECI))
	}
	return Encode(&Message{
		Type:   MsgUpdateBearerResponse,
		TEID:   teid,
		SeqNum: seq,
		IEs:    ies,
	})
}

type DeleteBearerRequest struct {
	TEID   uint32
	SeqNum uint32
	EBIs   []uint8
}

func DecodeDeleteBearerRequest(m *Message) (*DeleteBearerRequest, error) {
	if m.Type != MsgDeleteBearerRequest {
		return nil, fmt.Errorf("gtpv2: expected Delete Bearer Request (99), got %d", m.Type)
	}
	req := &DeleteBearerRequest{TEID: m.TEID, SeqNum: m.SeqNum}
	for _, ie := range m.IEs {
		if ie.Type == IETypeEBI {
			ebi, err := DecodeEBI(&ie)
			if err != nil {
				return nil, fmt.Errorf("%w: Delete Bearer Request invalid EPS Bearer ID: %v", ErrMandatoryIEIncorrect, err)
			}
			req.EBIs = append(req.EBIs, ebi)
			continue
		}
		if ie.Type != IETypeBearerContext {
			continue
		}
		children, err := FindGroupedIEs(&ie)
		if err != nil {
			return nil, err
		}
		ebiIE := FindIE(children, IETypeEBI, 0)
		if ebiIE == nil {
			return nil, fmt.Errorf("%w: Delete Bearer Request Bearer Context missing EPS Bearer ID", ErrMandatoryIEMissing)
		}
		ebi, err := DecodeEBI(ebiIE)
		if err != nil {
			return nil, fmt.Errorf("%w: Delete Bearer Request Bearer Context invalid EPS Bearer ID: %v", ErrMandatoryIEIncorrect, err)
		}
		req.EBIs = append(req.EBIs, ebi)
	}
	if len(req.EBIs) == 0 {
		return nil, fmt.Errorf("%w: Delete Bearer Request missing EBI", ErrMandatoryIEMissing)
	}
	return req, nil
}

func EncodeDeleteBearerResponse(teid uint32, seq uint32, cause uint8, ebis []uint8) []byte {
	return EncodeDeleteBearerResponseWithMeta(teid, seq, cause, ebis, nil)
}

func EncodeDeleteBearerResponseWithMeta(teid uint32, seq uint32, cause uint8, ebis []uint8, meta *DeleteBearerResponseMeta) []byte {
	ies := []IE{EncodeCause(cause)}
	if meta != nil && meta.IncludeULI {
		ies = append(ies, EncodeULI(meta.ULIPLMN, meta.ULITAC, meta.ULIECI))
	}
	for _, ebi := range ebis {
		children := []IE{EncodeEBI(ebi, 0), EncodeCause(cause)}
		ies = append(ies, EncodeGrouped(IETypeBearerContext, 0, children))
	}
	if meta != nil && meta.IncludeULITimestamp {
		ies = append(ies, EncodeULITimestamp(meta.ULITimestamp))
	}
	return Encode(&Message{
		Type:   MsgDeleteBearerResponse,
		TEID:   teid,
		SeqNum: seq,
		IEs:    ies,
	})
}
