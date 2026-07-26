package sbcap

// Typed PWS area codecs.  The nested LTE identities are shared by S1AP and
// SBc-AP, but their outer area-list wrappers are deliberately different:
// S1AP Broadcast{Completed,Cancelled}AreaList is a CHOICE, while SBc-AP
// Broadcast-{Scheduled,Cancelled}-Area-List is a SEQUENCE with optional list
// fields.  Callers always pass through AreaList; no S1AP open-type bytes are
// ever bridged into SBc-AP.

import (
	"bytes"
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

const maxPWSList = 65535

// TS 36.413 Release 16 PWS Restart/Failure list constraints.  These are not
// interchangeable with SBc-AP's 65535-entry area lists: APER encodes the
// upper bound into the size determinant.
const (
	maxRestartCells = 256
	maxFailedCells  = 256
	maxRestartTAIs  = 2048
	maxRestartEAIs  = 256
)

type EUTRANCGI struct {
	PLMN [3]byte
	Cell uint32
}
type RestartInfo struct {
	GlobalENBID []byte
	Cells       []EUTRANCGI
	TAIs        []TAI
	EAIs        [][3]byte
}
type FailureInfo struct {
	GlobalENBID []byte
	Cells       []EUTRANCGI
}
type AreaKind uint8

const (
	AreaCells AreaKind = iota
	AreaTAIs
	AreaEAIs
)

type AreaCell struct {
	ECGI       EUTRANCGI
	Broadcasts *uint16
}
type AreaGroup struct {
	TAI   *TAI
	EAI   *[3]byte
	Cells []AreaCell
}
type AreaList struct {
	// Kind and Groups describe one S1AP CHOICE alternative.  TAIGroups and
	// EAIGroups are populated only for an aggregated SBc-AP SEQUENCE that
	// legitimately carries more than one optional alternative.
	Kind      AreaKind
	Cells     []AreaCell
	Groups    []AreaGroup
	TAIGroups []AreaGroup
	EAIGroups []AreaGroup
}

func decodeNoExtensions(r *aper.BitReader, optional bool) error {
	ext, err := r.ReadBit()
	if err != nil {
		return err
	}
	if ext != 0 {
		return fmt.Errorf("extensions not supported")
	}
	if optional {
		p, err := r.ReadBit()
		if err != nil {
			return err
		}
		if p != 0 {
			return fmt.Errorf("protocol extensions not supported")
		}
	}
	return nil
}
func validateGlobalENBID(data []byte) error {
	g, err := ies.DecodeGlobalENBID(data)
	if err != nil {
		return err
	}
	canonical, err := ies.EncodeGlobalENBID(g)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("non-canonical Global eNB ID")
	}
	return nil
}
func validatePLMN(data []byte) error {
	if len(data) != 3 {
		return fmt.Errorf("PLMN length %d", len(data))
	}
	for _, n := range []byte{data[0] & 0x0f, data[0] >> 4, data[1] & 0x0f, data[2] & 0x0f, data[2] >> 4} {
		if n > 9 {
			return fmt.Errorf("invalid PLMN digit")
		}
	}
	if n := data[1] >> 4; n > 9 && n != 0x0f {
		return fmt.Errorf("invalid MNC digit")
	}
	_, _, err := ies.DecodePLMN(data)
	return err
}
func ensureEnd(r *aper.BitReader) error {
	// APER values are carried in octet-aligned open types, so up to seven
	// zero alignment bits may remain after a non-octet-aligned final field.
	if r.Remaining() > 7 {
		return fmt.Errorf("trailing APER bits")
	}
	for r.Remaining() > 0 {
		b, err := r.ReadBit()
		if err != nil || b != 0 {
			return fmt.Errorf("trailing APER bits")
		}
	}
	return nil
}
func decodeCountMax(r *aper.BitReader, max int) (int, error) {
	n, err := aper.DecodeConstrainedWholeNumber(r, 1, int64(max))
	return int(n), err
}
func encodeCountMax(w *aper.BitWriter, n, max int) error {
	return aper.EncodeConstrainedWholeNumber(w, int64(n), 1, int64(max))
}
func decodeCount(r *aper.BitReader) (int, error) { return decodeCountMax(r, maxPWSList) }
func encodeCount(w *aper.BitWriter, n int) error { return encodeCountMax(w, n, maxPWSList) }

func decodeECGIReader(r *aper.BitReader) (EUTRANCGI, error) {
	var out EUTRANCGI
	if err := decodeNoExtensions(r, true); err != nil {
		return out, err
	}
	plmn, err := aper.DecodeOctetString(r, 3, 3)
	if err != nil {
		return out, err
	}
	if err = validatePLMN(plmn); err != nil {
		return out, fmt.Errorf("PLMN: %w", err)
	}
	copy(out.PLMN[:], plmn)
	bs, err := aper.DecodeBitString(r, 28, 28)
	if err != nil {
		return out, err
	}
	if len(bs.Bytes) != 4 || bs.Bytes[3]&0x0f != 0 {
		return out, fmt.Errorf("invalid E-CGI cell identity")
	}
	out.Cell = uint32(bs.Bytes[0])<<20 | uint32(bs.Bytes[1])<<12 | uint32(bs.Bytes[2])<<4 | uint32(bs.Bytes[3]>>4)
	return out, nil
}
func encodeECGIWriter(w *aper.BitWriter, e EUTRANCGI) error {
	if err := validatePLMN(e.PLMN[:]); err != nil {
		return fmt.Errorf("PLMN: %w", err)
	}
	w.WriteBit(0)
	w.WriteBit(0)
	if err := aper.EncodeOctetString(w, e.PLMN[:], 3, 3); err != nil {
		return err
	}
	return aper.EncodeBitString(w, aper.BitString{Bytes: []byte{byte(e.Cell >> 20), byte(e.Cell >> 12), byte(e.Cell >> 4), byte(e.Cell << 4)}, NumBits: 28}, 28, 28)
}
func decodeTAIReader(r *aper.BitReader) (TAI, error) {
	var out TAI
	if err := decodeNoExtensions(r, true); err != nil {
		return out, err
	}
	p, err := aper.DecodeOctetString(r, 3, 3)
	if err != nil {
		return out, err
	}
	if err = validatePLMN(p); err != nil {
		return out, fmt.Errorf("PLMN: %w", err)
	}
	t, err := aper.DecodeOctetString(r, 2, 2)
	if err != nil {
		return out, err
	}
	copy(out.PLMN[:], p)
	out.TAC = uint16(t[0])<<8 | uint16(t[1])
	return out, nil
}
func encodeTAIWriter(w *aper.BitWriter, t TAI) error {
	if err := validatePLMN(t.PLMN[:]); err != nil {
		return err
	}
	w.WriteBit(0)
	w.WriteBit(0)
	if err := aper.EncodeOctetString(w, t.PLMN[:], 3, 3); err != nil {
		return err
	}
	return aper.EncodeOctetString(w, []byte{byte(t.TAC >> 8), byte(t.TAC)}, 2, 2)
}

func decodeECGIList(data []byte) ([]EUTRANCGI, error) {
	return decodeECGIListMax(data, maxPWSList)
}
func decodeECGIListMax(data []byte, max int) ([]EUTRANCGI, error) {
	r := aper.NewBitReader(data)
	n, err := decodeCountMax(r, max)
	if err != nil {
		return nil, err
	}
	out := make([]EUTRANCGI, n)
	for i := range out {
		if out[i], err = decodeECGIReader(r); err != nil {
			return nil, fmt.Errorf("cell[%d]: %w", i, err)
		}
	}
	return out, ensureEnd(r)
}
func encodeECGIList(c []EUTRANCGI) ([]byte, error) {
	return encodeECGIListMax(c, maxPWSList)
}
func encodeECGIListMax(c []EUTRANCGI, max int) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := encodeCountMax(w, len(c), max); err != nil {
		return nil, err
	}
	for _, v := range c {
		if err := encodeECGIWriter(w, v); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}
func decodeTAIListTyped(data []byte) ([]TAI, error) {
	return decodeTAIListTypedMax(data, maxPWSList)
}
func decodeTAIListTypedMax(data []byte, max int) ([]TAI, error) {
	r := aper.NewBitReader(data)
	n, err := decodeCountMax(r, max)
	if err != nil {
		return nil, err
	}
	out := make([]TAI, n)
	for i := range out {
		if out[i], err = decodeTAIReader(r); err != nil {
			return nil, err
		}
	}
	return out, ensureEnd(r)
}
func encodeTAIListTyped(v []TAI) ([]byte, error) {
	return encodeTAIListTypedMax(v, maxPWSList)
}
func encodeTAIListTypedMax(v []TAI, max int) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := encodeCountMax(w, len(v), max); err != nil {
		return nil, err
	}
	for _, x := range v {
		if err := encodeTAIWriter(w, x); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}
func decodeEAIList(data []byte) ([][3]byte, error) {
	return decodeEAIListMax(data, maxPWSList)
}
func decodeEAIListMax(data []byte, max int) ([][3]byte, error) {
	r := aper.NewBitReader(data)
	n, err := decodeCountMax(r, max)
	if err != nil {
		return nil, err
	}
	o := make([][3]byte, n)
	for i := range o {
		b, e := aper.DecodeOctetString(r, 3, 3)
		if e != nil {
			return nil, e
		}
		copy(o[i][:], b)
	}
	return o, ensureEnd(r)
}
func encodeEAIList(v [][3]byte) ([]byte, error) {
	return encodeEAIListMax(v, maxPWSList)
}
func encodeEAIListMax(v [][3]byte, max int) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := encodeCountMax(w, len(v), max); err != nil {
		return nil, err
	}
	for _, x := range v {
		if err := aper.EncodeOctetString(w, x[:], 3, 3); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

// DecodeRestartInfo and DecodeFailureInfo validate all mandatory S1AP IE values.
func DecodeRestartInfo(values map[uint16][]byte) (RestartInfo, error) {
	var x RestartInfo
	g := values[59]
	if len(g) == 0 {
		return x, fmt.Errorf("missing Global eNB ID")
	}
	if err := validateGlobalENBID(g); err != nil {
		return x, err
	}
	x.GlobalENBID = append([]byte(nil), g...)
	var err error
	if x.Cells, err = decodeECGIListMax(values[182], maxRestartCells); err != nil {
		return x, fmt.Errorf("restarted cells: %w", err)
	}
	if x.TAIs, err = decodeTAIListTypedMax(values[188], maxRestartTAIs); err != nil {
		return x, fmt.Errorf("restart TAIs: %w", err)
	}
	if b := values[190]; len(b) > 0 {
		if x.EAIs, err = decodeEAIListMax(b, maxRestartEAIs); err != nil {
			return x, fmt.Errorf("restart EAIs: %w", err)
		}
	}
	return x, nil
}
func DecodeFailureInfo(values map[uint16][]byte) (FailureInfo, error) {
	var x FailureInfo
	g := values[59]
	if len(g) == 0 {
		return x, fmt.Errorf("missing Global eNB ID")
	}
	if err := validateGlobalENBID(g); err != nil {
		return x, err
	}
	x.GlobalENBID = append([]byte(nil), g...)
	var err error
	x.Cells, err = decodeECGIListMax(values[222], maxFailedCells)
	if err != nil {
		return x, fmt.Errorf("failed cells: %w", err)
	}
	return x, nil
}
func EncodeRestartInfo(x RestartInfo) (map[uint16][]byte, error) {
	if err := validateGlobalENBID(x.GlobalENBID); err != nil {
		return nil, err
	}
	c, err := encodeECGIListMax(x.Cells, maxRestartCells)
	if err != nil {
		return nil, err
	}
	t, err := encodeTAIListTypedMax(x.TAIs, maxRestartTAIs)
	if err != nil {
		return nil, err
	}
	o := map[uint16][]byte{IEGlobalENBID: append([]byte(nil), x.GlobalENBID...), IERestartedCellList: c, IEListOfTAIsRestart: t}
	if x.EAIs != nil {
		e, err := encodeEAIListMax(x.EAIs, maxRestartEAIs)
		if err != nil {
			return nil, err
		}
		o[IEListOfEAIsRestart] = e
	}
	return o, nil
}
func EncodeFailureInfo(x FailureInfo) (map[uint16][]byte, error) {
	if err := validateGlobalENBID(x.GlobalENBID); err != nil {
		return nil, err
	}
	c, err := encodeECGIListMax(x.Cells, maxFailedCells)
	if err != nil {
		return nil, err
	}
	return map[uint16][]byte{IEGlobalENBID: append([]byte(nil), x.GlobalENBID...), IEFailedCellList: c}, nil
}

func decodeArea(data []byte, cancelled bool) (AreaList, error) {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return AreaList{}, err
	}
	if ext != 0 {
		return AreaList{}, fmt.Errorf("area-list extension")
	}
	k, err := r.ReadBits(2)
	if err != nil || k > 2 {
		return AreaList{}, fmt.Errorf("area-list choice")
	}
	n, err := decodeCount(r)
	if err != nil {
		return AreaList{}, err
	}
	o := AreaList{Kind: AreaKind(k)}
	for i := 0; i < n; i++ {
		if o.Kind == AreaCells {
			v, e := decodeAreaCell(r, cancelled)
			if e != nil {
				return o, e
			}
			o.Cells = append(o.Cells, v)
			continue
		}
		g := AreaGroup{}
		// SEQUENCE extension and optional-presence bits precede the mandatory
		// components in APER.
		if err := decodeNoExtensions(r, true); err != nil {
			return o, err
		}
		if o.Kind == AreaTAIs {
			v, e := decodeTAIReader(r)
			if e != nil {
				return o, e
			}
			g.TAI = &v
		} else {
			b, e := aper.DecodeOctetString(r, 3, 3)
			if e != nil {
				return o, e
			}
			var a [3]byte
			copy(a[:], b)
			g.EAI = &a
		}
		m, e := decodeCount(r)
		if e != nil {
			return o, e
		}
		for j := 0; j < m; j++ {
			v, e := decodeAreaCell(r, cancelled)
			if e != nil {
				return o, e
			}
			g.Cells = append(g.Cells, v)
		}
		o.Groups = append(o.Groups, g)
	}
	return o, ensureEnd(r)
}
func decodeAreaCell(r *aper.BitReader, cancelled bool) (AreaCell, error) {
	if e := decodeNoExtensions(r, true); e != nil {
		return AreaCell{}, e
	}
	v, e := decodeECGIReader(r)
	if e != nil {
		return AreaCell{}, e
	}
	o := AreaCell{ECGI: v}
	if cancelled {
		n, e := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if e != nil {
			return o, e
		}
		x := uint16(n)
		o.Broadcasts = &x
	}
	return o, nil
}

// DecodeS1CompletedAreaList decodes the LTE S1AP BroadcastCompletedAreaList
// CHOICE to the shared typed model; no S1AP open-type payload is forwarded.
func DecodeS1CompletedAreaList(data []byte) (AreaList, error) {
	return decodeArea(data, false)
}

// DecodeS1CancelledAreaList decodes the LTE S1AP
// BroadcastCancelledAreaList CHOICE to the shared typed model.
func DecodeS1CancelledAreaList(data []byte) (AreaList, error) {
	return decodeArea(data, true)
}

// EncodeS1CompletedAreaList encodes the TS 36.413
// BroadcastCompletedAreaList CHOICE.  It exists separately from the SBc-AP
// encoder to keep protocol wrapper selection explicit at every call site.
func EncodeS1CompletedAreaList(a AreaList) ([]byte, error) { return encodeArea(a, false) }

// EncodeS1CancelledAreaList encodes the TS 36.413
// BroadcastCancelledAreaList CHOICE.
func EncodeS1CancelledAreaList(a AreaList) ([]byte, error) { return encodeArea(a, true) }

// DecodeCompletedAreaList decodes the TS 29.168 Broadcast-Scheduled-Area-List
// SEQUENCE.  It is intentionally not the S1AP CHOICE decoder above.
func DecodeCompletedAreaList(data []byte) (AreaList, error) {
	return decodeSBcAPAreaList(data, false)
}

// DecodeCancelledAreaList decodes the TS 29.168 Broadcast-Cancelled-Area-List
// SEQUENCE.  It is intentionally not the S1AP CHOICE decoder above.
func DecodeCancelledAreaList(data []byte) (AreaList, error) {
	return decodeSBcAPAreaList(data, true)
}

// EncodeCompletedAreaList encodes the TS 29.168
// Broadcast-Scheduled-Area-List SEQUENCE.
func EncodeCompletedAreaList(a AreaList) ([]byte, error) {
	return encodeSBcAPAreaList(a, false)
}

// EncodeCancelledAreaList encodes the TS 29.168
// Broadcast-Cancelled-Area-List SEQUENCE.
func EncodeCancelledAreaList(a AreaList) ([]byte, error) {
	return encodeSBcAPAreaList(a, true)
}

// decodeArea/encodeArea implement the S1AP Broadcast{Completed,Cancelled}
// AreaList CHOICE only.  Keep them private so an S1AP CHOICE cannot
// accidentally be emitted as an SBc-AP SEQUENCE open type.
func encodeArea(a AreaList, cancelled bool) ([]byte, error) {
	w := aper.NewBitWriter()
	if a.Kind > AreaEAIs {
		return nil, fmt.Errorf("invalid area kind")
	}
	w.WriteBit(0)
	w.WriteBits(uint64(a.Kind), 2)
	n := len(a.Cells)
	if a.Kind != AreaCells {
		n = len(a.Groups)
	}
	if err := encodeCount(w, n); err != nil {
		return nil, err
	}
	if a.Kind == AreaCells {
		for _, v := range a.Cells {
			if err := encodeAreaCell(w, v, cancelled); err != nil {
				return nil, err
			}
		}
	} else {
		for _, g := range a.Groups {
			w.WriteBit(0)
			w.WriteBit(0)
			if a.Kind == AreaTAIs {
				if g.TAI == nil {
					return nil, fmt.Errorf("missing TAI")
				}
				if err := encodeTAIWriter(w, *g.TAI); err != nil {
					return nil, err
				}
			} else {
				if g.EAI == nil {
					return nil, fmt.Errorf("missing EAI")
				}
				if err := aper.EncodeOctetString(w, g.EAI[:], 3, 3); err != nil {
					return nil, err
				}
			}
			if err := encodeCount(w, len(g.Cells)); err != nil {
				return nil, err
			}
			for _, v := range g.Cells {
				if err := encodeAreaCell(w, v, cancelled); err != nil {
					return nil, err
				}
			}
		}
	}
	return w.Bytes(), nil
}

// decodeSBcAPAreaList implements the TS 29.168 root SEQUENCE:
//
//	Broadcast-*-Area-List ::= SEQUENCE {
//	    cell... OPTIONAL, tAI... OPTIONAL, emergencyAreaID... OPTIONAL,
//	    iE-Extensions OPTIONAL, ... }
func decodeSBcAPAreaList(data []byte, cancelled bool) (AreaList, error) {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return AreaList{}, err
	}
	if ext != 0 {
		return AreaList{}, fmt.Errorf("SBc-AP area-list extension")
	}
	present := [4]uint8{}
	for i := range present {
		if present[i], err = r.ReadBit(); err != nil {
			return AreaList{}, err
		}
	}
	if present[3] != 0 {
		return AreaList{}, fmt.Errorf("SBc-AP area-list protocol extensions not supported")
	}
	var out AreaList
	count := int(present[0]) + int(present[1]) + int(present[2])
	if count == 0 {
		return out, fmt.Errorf("SBc-AP area-list has no alternatives")
	}
	if present[0] != 0 {
		n, e := decodeCount(r)
		if e != nil {
			return out, e
		}
		out.Cells = make([]AreaCell, 0, n)
		for i := 0; i < n; i++ {
			v, e := decodeAreaCell(r, cancelled)
			if e != nil {
				return out, fmt.Errorf("cell[%d]: %w", i, e)
			}
			out.Cells = append(out.Cells, v)
		}
	}
	if present[1] != 0 {
		groups, e := decodeSBcAPGroups(r, AreaTAIs, cancelled)
		if e != nil {
			return out, e
		}
		out.TAIGroups = groups
	}
	if present[2] != 0 {
		groups, e := decodeSBcAPGroups(r, AreaEAIs, cancelled)
		if e != nil {
			return out, e
		}
		out.EAIGroups = groups
	}
	// Preserve the historical single-alternative shape for callers decoding
	// a direct S1AP-to-SBcAP mapping, while retaining all fields for a valid
	// aggregated SEQUENCE with several alternatives.
	if count == 1 {
		switch {
		case present[0] != 0:
			out.Kind = AreaCells
		case present[1] != 0:
			out.Kind, out.Groups = AreaTAIs, out.TAIGroups
		case present[2] != 0:
			out.Kind, out.Groups = AreaEAIs, out.EAIGroups
		}
	} else {
		out.Kind = AreaCells
	}
	if err := ensureEnd(r); err != nil {
		return out, err
	}
	return out, nil
}

func decodeSBcAPGroups(r *aper.BitReader, kind AreaKind, cancelled bool) ([]AreaGroup, error) {
	n, err := decodeCount(r)
	if err != nil {
		return nil, err
	}
	groups := make([]AreaGroup, 0, n)
	for i := 0; i < n; i++ {
		g := AreaGroup{}
		if err := decodeNoExtensions(r, true); err != nil {
			return nil, fmt.Errorf("group[%d]: %w", i, err)
		}
		if kind == AreaTAIs {
			tai, err := decodeTAIReader(r)
			if err != nil {
				return nil, fmt.Errorf("group[%d] TAI: %w", i, err)
			}
			g.TAI = &tai
		} else {
			b, err := aper.DecodeOctetString(r, 3, 3)
			if err != nil {
				return nil, fmt.Errorf("group[%d] EAI: %w", i, err)
			}
			var eai [3]byte
			copy(eai[:], b)
			g.EAI = &eai
		}
		m, err := decodeCount(r)
		if err != nil {
			return nil, fmt.Errorf("group[%d] cells: %w", i, err)
		}
		g.Cells = make([]AreaCell, 0, m)
		for j := 0; j < m; j++ {
			cell, err := decodeAreaCell(r, cancelled)
			if err != nil {
				return nil, fmt.Errorf("group[%d] cell[%d]: %w", i, j, err)
			}
			g.Cells = append(g.Cells, cell)
		}
		groups = append(groups, g)
	}
	return groups, nil
}

func encodeSBcAPAreaList(a AreaList, cancelled bool) ([]byte, error) {
	if a.Kind > AreaEAIs {
		return nil, fmt.Errorf("invalid area kind")
	}
	cells, taiGroups, eaiGroups := sbcAPAreaComponents(a)
	if len(cells)+len(taiGroups)+len(eaiGroups) == 0 {
		return nil, fmt.Errorf("SBc-AP area-list has no alternatives")
	}
	w := aper.NewBitWriter()
	// Extension marker then presence bits for the three alternatives and the
	// optional extension container.  This is the crucial difference from the
	// S1AP CHOICE discriminator.
	w.WriteBit(0)
	w.WriteBit(boolBit(len(cells) != 0))
	w.WriteBit(boolBit(len(taiGroups) != 0))
	w.WriteBit(boolBit(len(eaiGroups) != 0))
	w.WriteBit(0)
	if len(cells) != 0 {
		if err := encodeCount(w, len(cells)); err != nil {
			return nil, err
		}
		for i, cell := range cells {
			if err := encodeAreaCell(w, cell, cancelled); err != nil {
				return nil, fmt.Errorf("cell[%d]: %w", i, err)
			}
		}
	}
	if len(taiGroups) != 0 {
		if err := encodeCount(w, len(taiGroups)); err != nil {
			return nil, err
		}
		for i, group := range taiGroups {
			if err := encodeSBcAPGroup(w, AreaTAIs, group, cancelled); err != nil {
				return nil, fmt.Errorf("TAI group[%d]: %w", i, err)
			}
		}
	}
	if len(eaiGroups) != 0 {
		if err := encodeCount(w, len(eaiGroups)); err != nil {
			return nil, err
		}
		for i, group := range eaiGroups {
			if err := encodeSBcAPGroup(w, AreaEAIs, group, cancelled); err != nil {
				return nil, fmt.Errorf("EAI group[%d]: %w", i, err)
			}
		}
	}
	return w.Bytes(), nil
}

func sbcAPAreaComponents(a AreaList) (cells []AreaCell, taiGroups, eaiGroups []AreaGroup) {
	cells, taiGroups, eaiGroups = a.Cells, a.TAIGroups, a.EAIGroups
	if a.Kind == AreaTAIs && len(taiGroups) == 0 {
		taiGroups = a.Groups
	}
	if a.Kind == AreaEAIs && len(eaiGroups) == 0 {
		eaiGroups = a.Groups
	}
	return cells, taiGroups, eaiGroups
}

func boolBit(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func encodeSBcAPGroup(w *aper.BitWriter, kind AreaKind, g AreaGroup, cancelled bool) error {
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	if kind == AreaTAIs {
		if g.TAI == nil {
			return fmt.Errorf("missing TAI")
		}
		if err := encodeTAIWriter(w, *g.TAI); err != nil {
			return err
		}
	} else {
		if g.EAI == nil {
			return fmt.Errorf("missing EAI")
		}
		if err := aper.EncodeOctetString(w, g.EAI[:], 3, 3); err != nil {
			return err
		}
	}
	if err := encodeCount(w, len(g.Cells)); err != nil {
		return err
	}
	for j, cell := range g.Cells {
		if err := encodeAreaCell(w, cell, cancelled); err != nil {
			return fmt.Errorf("cell[%d]: %w", j, err)
		}
	}
	return nil
}

// EncodeBroadcastEmptyAreaList encodes the TS 29.168 Broadcast-Empty-Area-List
// (SIZE(1..256)) from canonical Global-ENB-ID values.  Although Global-ENB-ID
// has an intentionally matching S1AP definition, each value is decoded and
// re-encoded here rather than copied from an S1AP open type.
func EncodeBroadcastEmptyAreaList(ids [][]byte) ([]byte, error) {
	w := aper.NewBitWriter()
	if err := encodeCountMax(w, len(ids), 256); err != nil {
		return nil, err
	}
	for i, raw := range ids {
		g, err := ies.DecodeGlobalENBID(raw)
		if err != nil {
			return nil, fmt.Errorf("Global eNB ID[%d]: %w", i, err)
		}
		canonical, err := ies.EncodeGlobalENBID(g)
		if err != nil {
			return nil, fmt.Errorf("Global eNB ID[%d]: %w", i, err)
		}
		if !bytes.Equal(raw, canonical) {
			return nil, fmt.Errorf("Global eNB ID[%d] is non-canonical", i)
		}
		if err := encodeGlobalENBIDWriter(w, g); err != nil {
			return nil, fmt.Errorf("Global eNB ID[%d]: %w", i, err)
		}
	}
	return w.Bytes(), nil
}

// DecodeBroadcastEmptyAreaList is the counterpart to
// EncodeBroadcastEmptyAreaList and returns canonical independent encodings.
func DecodeBroadcastEmptyAreaList(data []byte) ([][]byte, error) {
	r := aper.NewBitReader(data)
	n, err := decodeCountMax(r, 256)
	if err != nil {
		return nil, err
	}
	ids := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		g, err := decodeGlobalENBIDReader(r)
		if err != nil {
			return nil, fmt.Errorf("Global eNB ID[%d]: %w", i, err)
		}
		canonical, err := ies.EncodeGlobalENBID(g)
		if err != nil {
			return nil, fmt.Errorf("Global eNB ID[%d]: %w", i, err)
		}
		ids = append(ids, canonical)
	}
	return ids, ensureEnd(r)
}

func encodeGlobalENBIDWriter(w *aper.BitWriter, g ies.GlobalENBID) error {
	plmn, err := ies.EncodePLMN(g.MCC, g.MNC)
	if err != nil {
		return err
	}
	w.WriteBit(0) // Global-ENB-ID extension marker
	w.WriteBit(0) // iE-Extensions absent
	if err := aper.EncodeOctetString(w, plmn, 3, 3); err != nil {
		return err
	}
	w.WriteBit(0) // ENB-ID CHOICE extension marker
	if g.ENB.Type == ies.ENBIDTypeMacro {
		w.WriteBit(0)
		return aper.EncodeBitString(w, aper.BitString{Bytes: []byte{byte(g.ENB.Value >> 12), byte(g.ENB.Value >> 4), byte(g.ENB.Value << 4)}, NumBits: 20}, 20, 20)
	}
	if g.ENB.Type != ies.ENBIDTypeHome {
		return fmt.Errorf("unsupported eNB ID type")
	}
	w.WriteBit(1)
	return aper.EncodeBitString(w, aper.BitString{Bytes: []byte{byte(g.ENB.Value >> 20), byte(g.ENB.Value >> 12), byte(g.ENB.Value >> 4), byte(g.ENB.Value << 4)}, NumBits: 28}, 28, 28)
}

func decodeGlobalENBIDReader(r *aper.BitReader) (ies.GlobalENBID, error) {
	var out ies.GlobalENBID
	if err := decodeNoExtensions(r, true); err != nil {
		return out, err
	}
	plmn, err := aper.DecodeOctetString(r, 3, 3)
	if err != nil {
		return out, err
	}
	if err := validatePLMN(plmn); err != nil {
		return out, err
	}
	mcc, mnc, err := ies.DecodePLMN(plmn)
	if err != nil {
		return out, err
	}
	ext, err := r.ReadBit()
	if err != nil {
		return out, err
	}
	if ext != 0 {
		return out, fmt.Errorf("eNB ID extension")
	}
	kind, err := r.ReadBit()
	if err != nil {
		return out, err
	}
	bits := 20
	typ := ies.ENBIDTypeMacro
	if kind != 0 {
		bits = 28
		typ = ies.ENBIDTypeHome
	}
	value, err := aper.DecodeBitString(r, bits, bits)
	if err != nil {
		return out, err
	}
	var enb uint32
	for i := 0; i < bits; i++ {
		enb = (enb << 1) | uint32((value.Bytes[i/8]>>(7-uint(i%8)))&1)
	}
	var rawPLMN [3]byte
	copy(rawPLMN[:], plmn)
	return ies.GlobalENBID{MCC: mcc, MNC: mnc, PLMNRaw: rawPLMN, ENB: ies.ENBID{Type: typ, Value: enb}}, nil
}
func encodeAreaCell(w *aper.BitWriter, v AreaCell, cancelled bool) error {
	w.WriteBit(0)
	w.WriteBit(0)
	if err := encodeECGIWriter(w, v.ECGI); err != nil {
		return err
	}
	if cancelled {
		if v.Broadcasts == nil {
			return fmt.Errorf("missing number of broadcasts")
		}
		if err := aper.EncodeConstrainedWholeNumber(w, int64(*v.Broadcasts), 0, 65535); err != nil {
			return err
		}
	}
	return nil
}

// MergeAreaLists keeps valid partial results and removes repeated cell reports.
func MergeAreaLists(lists []AreaList, cancelled bool) AreaList {
	o := AreaList{Kind: AreaCells}
	cellSeen := map[string]bool{}
	taiGroups := map[string]*AreaGroup{}
	eaiGroups := map[string]*AreaGroup{}
	addCell := func(dst *[]AreaCell, cell AreaCell, scope string) {
		key := scope + fmt.Sprintf(":%x:%x", cell.ECGI.PLMN, cell.ECGI.Cell)
		if !cellSeen[key] {
			cellSeen[key] = true
			*dst = append(*dst, cell)
		}
	}
	for _, l := range lists {
		for _, cell := range l.Cells {
			addCell(&o.Cells, cell, "cell")
		}
		taiSource := l.TAIGroups
		if l.Kind == AreaTAIs && len(taiSource) == 0 {
			taiSource = l.Groups
		}
		for _, group := range taiSource {
			if group.TAI == nil {
				continue
			}
			key := fmt.Sprintf("%x:%04x", group.TAI.PLMN, group.TAI.TAC)
			dst := taiGroups[key]
			if dst == nil {
				copy := AreaGroup{TAI: group.TAI}
				o.TAIGroups = append(o.TAIGroups, copy)
				dst = &o.TAIGroups[len(o.TAIGroups)-1]
				taiGroups[key] = dst
			}
			for _, cell := range group.Cells {
				addCell(&dst.Cells, cell, "tai:"+key)
			}
		}
		eaiSource := l.EAIGroups
		if l.Kind == AreaEAIs && len(eaiSource) == 0 {
			eaiSource = l.Groups
		}
		for _, group := range eaiSource {
			if group.EAI == nil {
				continue
			}
			key := fmt.Sprintf("%x", *group.EAI)
			dst := eaiGroups[key]
			if dst == nil {
				copy := AreaGroup{EAI: group.EAI}
				o.EAIGroups = append(o.EAIGroups, copy)
				dst = &o.EAIGroups[len(o.EAIGroups)-1]
				eaiGroups[key] = dst
			}
			for _, cell := range group.Cells {
				addCell(&dst.Cells, cell, "eai:"+key)
			}
		}
	}
	// Keep the compact historical form for a single alternative.
	if len(o.Cells) == 0 && len(o.TAIGroups) != 0 && len(o.EAIGroups) == 0 {
		o.Kind, o.Groups = AreaTAIs, o.TAIGroups
	}
	if len(o.Cells) == 0 && len(o.EAIGroups) != 0 && len(o.TAIGroups) == 0 {
		o.Kind, o.Groups = AreaEAIs, o.EAIGroups
	}
	return o
}
