package s1ap

// Narrow APER codec for TS 36.413 ResetType and the two logical-S1 reset
// lists.  The ASN.1 used is TS 36.413 v16.7.0, section 9.2: the list is
// SIZE(1..256), the contained ProtocolIE has ID 91, and MME/eNB IDs are
// INTEGER (0..4294967295)/(0..16777215), respectively.

import (
	"fmt"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

const (
	resetConnectionItemIEID uint16 = 91
	resetListMin                   = 1
	resetListMax                   = 256
)

type resetTypeKind uint8

const (
	resetTypeS1Interface resetTypeKind = iota
	resetTypePartOfS1Interface
)

func (k resetTypeKind) String() string {
	if k == resetTypeS1Interface {
		return "s1_interface"
	}
	if k == resetTypePartOfS1Interface {
		return "part_of_s1_interface"
	}
	return "unknown"
}

// resetConnectionItem is the value carried in the ProtocolIE single
// container. ExtensionBytes contains the encoded ProtocolExtensionContainer
// body when iE-Extensions is present. No Rel-16 extension fields are defined
// for this item, but retaining the body lets the decoder distinguish presence
// from absence without treating it as a reset-all.
type resetConnectionItem struct {
	MMEUEID           uint32
	HasMMEUEID        bool
	ENBUEID           uint32
	HasENBUEID        bool
	ExtensionsPresent bool
	ExtensionBytes    []byte
	IEID              uint16
	Criticality       aper.Criticality
}

type resetType struct {
	Kind          resetTypeKind
	Items         []resetConnectionItem
	BytesConsumed int
	BitsConsumed  int
}

func decodeResetType(data []byte) (resetType, error) {
	r := aper.NewBitReader(data)
	var out resetType
	ext, err := r.ReadBit()
	if err != nil {
		return out, fmt.Errorf("reset type extension: %w", err)
	}
	if ext != 0 {
		return out, fmt.Errorf("reset type: unsupported extension choice")
	}
	choice, err := r.ReadBit()
	if err != nil {
		return out, fmt.Errorf("reset type choice: %w", err)
	}
	if choice == 0 {
		innerExt, err := r.ReadBit()
		if err != nil {
			return out, fmt.Errorf("reset-all extension: %w", err)
		}
		if innerExt != 0 {
			return out, fmt.Errorf("reset-all: unsupported extension")
		}
		if _, err = aper.DecodeConstrainedWholeNumber(r, 0, 0); err != nil {
			return out, fmt.Errorf("reset-all: %w", err)
		}
		if err = resetTrailingZeroes(r); err != nil {
			return out, err
		}
		out.Kind = resetTypeS1Interface
		out.BitsConsumed, out.BytesConsumed = r.BitsRead(), len(data)
		return out, nil
	}
	out.Kind = resetTypePartOfS1Interface
	count, err := aper.DecodeConstrainedWholeNumber(r, resetListMin, resetListMax)
	if err != nil {
		return out, fmt.Errorf("partial reset list length: %w", err)
	}
	if count < resetListMin || count > resetListMax {
		return out, fmt.Errorf("partial reset list length %d out of range", count)
	}
	out.Items = make([]resetConnectionItem, 0, count)
	for i := 0; i < int(count); i++ {
		id, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return out, fmt.Errorf("partial reset item[%d] id: %w", i, err)
		}
		if uint16(id) != resetConnectionItemIEID {
			return out, fmt.Errorf("partial reset item[%d]: IE ID %d, want %d", i, id, resetConnectionItemIEID)
		}
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			return out, fmt.Errorf("partial reset item[%d] criticality: %w", i, err)
		}
		if crit != aper.CriticalityReject {
			return out, fmt.Errorf("partial reset item[%d]: criticality %s, want reject", i, crit)
		}
		body, err := aper.ReadOpenType(r)
		if err != nil {
			return out, fmt.Errorf("partial reset item[%d] open type: %w", i, err)
		}
		item, err := decodeResetConnectionItem(body)
		if err != nil {
			return out, fmt.Errorf("partial reset item[%d]: %w", i, err)
		}
		item.IEID, item.Criticality = uint16(id), crit
		out.Items = append(out.Items, item)
	}
	if err := resetTrailingZeroes(r); err != nil {
		return out, err
	}
	out.BitsConsumed, out.BytesConsumed = r.BitsRead(), len(data)
	return out, nil
}

func encodeResetType(v resetType) ([]byte, error) {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	switch v.Kind {
	case resetTypeS1Interface:
		w.WriteBit(0)
		w.WriteBit(0)
	case resetTypePartOfS1Interface:
		if len(v.Items) < resetListMin || len(v.Items) > resetListMax {
			return nil, fmt.Errorf("partial reset list length %d out of range", len(v.Items))
		}
		w.WriteBit(1)
		if err := aper.EncodeConstrainedWholeNumber(w, int64(len(v.Items)), resetListMin, resetListMax); err != nil {
			return nil, err
		}
		for i, item := range v.Items {
			if item.IEID != 0 && item.IEID != resetConnectionItemIEID {
				return nil, fmt.Errorf("partial reset item[%d]: IE ID %d", i, item.IEID)
			}
			if item.Criticality != 0 && item.Criticality != aper.CriticalityReject {
				return nil, fmt.Errorf("partial reset item[%d]: criticality %s", i, item.Criticality)
			}
			body, err := encodeResetConnectionItem(item)
			if err != nil {
				return nil, fmt.Errorf("partial reset item[%d]: %w", i, err)
			}
			if err := aper.EncodeConstrainedWholeNumber(w, int64(resetConnectionItemIEID), 0, 65535); err != nil {
				return nil, err
			}
			aper.EncodeCriticality(w, aper.CriticalityReject)
			aper.WriteOpenType(w, body)
		}
	default:
		return nil, fmt.Errorf("unsupported reset type %d", v.Kind)
	}
	return w.Bytes(), nil
}

func decodeResetConnectionItem(data []byte) (resetConnectionItem, error) {
	r := aper.NewBitReader(data)
	var out resetConnectionItem
	ext, err := r.ReadBit()
	if err != nil {
		return out, err
	}
	if ext != 0 {
		return out, fmt.Errorf("unsupported UE-associated connection item extension additions")
	}
	bits := make([]uint8, 3)
	for i := range bits {
		bits[i], err = r.ReadBit()
		if err != nil {
			return out, fmt.Errorf("optional bitmap: %w", err)
		}
	}
	out.HasMMEUEID, out.HasENBUEID, out.ExtensionsPresent = bits[0] != 0, bits[1] != 0, bits[2] != 0
	if out.HasMMEUEID {
		n, err := aper.DecodeConstrainedWholeNumber(r, 0, 4294967295)
		if err != nil {
			return out, fmt.Errorf("MME UE S1AP ID: %w", err)
		}
		out.MMEUEID = uint32(n)
	}
	if out.HasENBUEID {
		n, err := aper.DecodeConstrainedWholeNumber(r, 0, 16777215)
		if err != nil {
			return out, fmt.Errorf("eNB UE S1AP ID: %w", err)
		}
		out.ENBUEID = uint32(n)
	}
	if out.ExtensionsPresent {
		if err := decodeResetExtensionContainer(r); err != nil {
			return out, fmt.Errorf("IE extensions: %w", err)
		}
	}
	if err := resetTrailingZeroes(r); err != nil {
		return out, err
	}
	return out, nil
}

func encodeResetConnectionItem(v resetConnectionItem) ([]byte, error) {
	if v.HasENBUEID && v.ENBUEID > 16777215 {
		return nil, fmt.Errorf("eNB UE S1AP ID %d out of range", v.ENBUEID)
	}
	if v.ExtensionsPresent && len(v.ExtensionBytes) == 0 {
		return nil, fmt.Errorf("IE extensions present without container")
	}
	w := aper.NewBitWriter()
	w.WriteBit(0)
	if v.HasMMEUEID {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	if v.HasENBUEID {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	w.WriteBit(0)
	if v.HasMMEUEID {
		if err := aper.EncodeConstrainedWholeNumber(w, int64(v.MMEUEID), 0, 4294967295); err != nil {
			return nil, err
		}
	}
	if v.HasENBUEID {
		if err := aper.EncodeConstrainedWholeNumber(w, int64(v.ENBUEID), 0, 16777215); err != nil {
			return nil, err
		}
	}
	if v.ExtensionsPresent {
		// ProtocolExtensionContainer begins at an APER alignment boundary here.
		// Validate the caller-supplied generic container before preserving it.
		if err := decodeResetExtensionContainer(aper.NewBitReader(v.ExtensionBytes)); err != nil {
			return nil, fmt.Errorf("IE extensions: %w", err)
		}
		w.WriteOctets(v.ExtensionBytes)
	}
	return w.Bytes(), nil
}

// decodeResetExtensionContainer validates the generic APER
// ProtocolExtensionContainer boundaries. The Rel-16 extension set for this
// item has no root fields; extension values are intentionally opaque here.
func decodeResetExtensionContainer(r *aper.BitReader) error {
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 65535)
	if err != nil {
		return err
	}
	for i := 0; i < int(count); i++ {
		if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535); err != nil {
			return fmt.Errorf("extension[%d] id: %w", i, err)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return fmt.Errorf("extension[%d] criticality: %w", i, err)
		}
		if _, err := aper.ReadOpenType(r); err != nil {
			return fmt.Errorf("extension[%d] open type: %w", i, err)
		}
	}
	return nil
}

func resetTrailingZeroes(r *aper.BitReader) error {
	for r.Remaining() > 0 {
		b, err := r.ReadBit()
		if err != nil {
			return err
		}
		if b != 0 {
			return fmt.Errorf("trailing non-padding data")
		}
	}
	return nil
}

func encodeResetAcknowledgeList(items []resetConnectionItem) ([]byte, error) {
	// Ack list uses the same item value, but its single-container criticality
	// is ignore rather than reject.
	if len(items) < resetListMin || len(items) > resetListMax {
		return nil, fmt.Errorf("partial reset acknowledge list length %d out of range", len(items))
	}
	w := aper.NewBitWriter()
	if err := aper.EncodeConstrainedWholeNumber(w, int64(len(items)), resetListMin, resetListMax); err != nil {
		return nil, err
	}
	for i, item := range items {
		body, err := encodeResetConnectionItem(item)
		if err != nil {
			return nil, fmt.Errorf("ack item[%d]: %w", i, err)
		}
		_ = aper.EncodeConstrainedWholeNumber(w, int64(resetConnectionItemIEID), 0, 65535)
		aper.EncodeCriticality(w, aper.CriticalityIgnore)
		aper.WriteOpenType(w, body)
	}
	return w.Bytes(), nil
}

func decodeResetAcknowledgeList(data []byte) ([]resetConnectionItem, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, resetListMin, resetListMax)
	if err != nil {
		return nil, fmt.Errorf("partial reset acknowledge list length: %w", err)
	}
	items := make([]resetConnectionItem, 0, count)
	for i := 0; i < int(count); i++ {
		id, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("ack item[%d] id: %w", i, err)
		}
		if uint16(id) != resetConnectionItemIEID {
			return nil, fmt.Errorf("ack item[%d]: IE ID %d", i, id)
		}
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			return nil, fmt.Errorf("ack item[%d] criticality: %w", i, err)
		}
		if crit != aper.CriticalityIgnore {
			return nil, fmt.Errorf("ack item[%d]: criticality %s, want ignore", i, crit)
		}
		body, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("ack item[%d] open type: %w", i, err)
		}
		item, err := decodeResetConnectionItem(body)
		if err != nil {
			return nil, fmt.Errorf("ack item[%d]: %w", i, err)
		}
		item.IEID, item.Criticality = uint16(id), crit
		items = append(items, item)
	}
	if err := resetTrailingZeroes(r); err != nil {
		return nil, err
	}
	return items, nil
}
