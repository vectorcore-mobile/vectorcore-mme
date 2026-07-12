package uecontext

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/vectorcore/mme/internal/nas/emm"
)

// Manager is a concurrent-safe registry of live UE contexts.
// Contexts are indexed by MME UE S1AP ID (primary), IMSI, and GUTI.
type Manager struct {
	byMMEID sync.Map // uint32 → *Context
	byIMSI  sync.Map // string → *Context
	byGUTI  sync.Map // string → *Context

	nextID atomic.Uint32 // MME UE S1AP ID allocator
}

// NewManager creates a new Manager.
func NewManager() *Manager {
	m := &Manager{}
	m.nextID.Store(0) // Add(1) in Allocate returns the first ID as 1
	return m
}

// Allocate creates a new UE context with a fresh MME UE S1AP ID and registers it.
func (m *Manager) Allocate() *Context {
	id := m.nextID.Add(1)
	ctx := NewContext(id)
	m.byMMEID.Store(id, ctx)
	return ctx
}

// Register indexes an existing context by IMSI and GUTI (called after identity/GUTI assignment).
func (m *Manager) Register(ctx *Context) {
	ctx.mu.Lock()
	imsi := ctx.IMSI
	guti := ctx.GUTI
	ctx.mu.Unlock()
	if imsi != "" {
		m.byIMSI.Store(imsi, ctx)
	}
	if guti != nil {
		m.byGUTI.Store(SerialiseGUTI(guti), ctx)
	}
}

// GetByMMEID looks up a context by MME UE S1AP ID.
func (m *Manager) GetByMMEID(id uint32) (*Context, bool) {
	v, ok := m.byMMEID.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Context), true
}

// Range calls fn for each live UE context until fn returns false.
func (m *Manager) Range(fn func(*Context) bool) {
	m.byMMEID.Range(func(_, v any) bool {
		return fn(v.(*Context))
	})
}

// GetByIMSI looks up a context by IMSI.
func (m *Manager) GetByIMSI(imsi string) (*Context, bool) {
	v, ok := m.byIMSI.Load(imsi)
	if !ok {
		return nil, false
	}
	return v.(*Context), true
}

// GetByGUTI looks up a context by serialised GUTI string.
func (m *Manager) GetByGUTI(gutiStr string) (*Context, bool) {
	v, ok := m.byGUTI.Load(gutiStr)
	if !ok {
		return nil, false
	}
	return v.(*Context), true
}

// Remove deletes a context and all its index entries.
func (m *Manager) Remove(ctx *Context) {
	m.byMMEID.Delete(ctx.MMEUES1APID)
	ctx.mu.Lock()
	imsi := ctx.IMSI
	guti := ctx.GUTI
	pendingOldGUTI := ctx.PendingOldGUTI
	pendingGUTI := ctx.PendingGUTI
	ctx.mu.Unlock()
	if imsi != "" {
		m.deleteIMSIIfOwned(imsi, ctx)
	}
	if guti != nil {
		m.deleteGUTIIfOwned(SerialiseGUTI(guti), ctx)
	}
	if pendingOldGUTI != nil {
		m.deleteGUTIIfOwned(SerialiseGUTI(pendingOldGUTI), ctx)
	}
	if pendingGUTI != nil {
		m.deleteGUTIIfOwned(SerialiseGUTI(pendingGUTI), ctx)
	}
	ctx.StopAllTimers()
}

// UpdateIMSI updates the IMSI index for a context.
// Callers MUST NOT hold ctx.mu when calling this method.
func (m *Manager) UpdateIMSI(ctx *Context, imsi string) {
	ctx.mu.Lock()
	old := ctx.IMSI
	ctx.IMSI = imsi
	ctx.mu.Unlock()
	if old != "" {
		m.deleteIMSIIfOwned(old, ctx)
	}
	if imsi != "" {
		m.byIMSI.Store(imsi, ctx)
	}
}

// UpdateGUTI updates the GUTI index for a context and sets ctx.GUTI.
// Callers MUST NOT hold ctx.mu when calling this method.
// guti may be nil to clear the GUTI index entry.
func (m *Manager) UpdateGUTI(ctx *Context, guti *emm.GUTI) {
	ctx.mu.Lock()
	old := ctx.GUTI
	ctx.GUTI = guti
	ctx.mu.Unlock()
	if old != nil {
		m.deleteGUTIIfOwned(SerialiseGUTI(old), ctx)
	}
	if guti != nil {
		m.byGUTI.Store(SerialiseGUTI(guti), ctx)
	}
}

// AddGUTIAlias indexes an additional GUTI for a context without changing ctx.GUTI.
func (m *Manager) AddGUTIAlias(ctx *Context, guti *emm.GUTI) {
	if guti != nil {
		m.byGUTI.Store(SerialiseGUTI(guti), ctx)
	}
}

// RemoveGUTIAlias removes an additional GUTI index if it is still owned by ctx.
func (m *Manager) RemoveGUTIAlias(ctx *Context, guti *emm.GUTI) {
	if guti != nil {
		m.deleteGUTIIfOwned(SerialiseGUTI(guti), ctx)
	}
}

func (m *Manager) GUTIAliasPresent(ctx *Context, guti *emm.GUTI) bool {
	if guti == nil {
		return false
	}
	v, ok := m.byGUTI.Load(SerialiseGUTI(guti))
	return ok && v == ctx
}

func (m *Manager) deleteIMSIIfOwned(imsi string, ctx *Context) {
	if v, ok := m.byIMSI.Load(imsi); ok && v == ctx {
		m.byIMSI.Delete(imsi)
	}
}

func (m *Manager) deleteGUTIIfOwned(guti string, ctx *Context) {
	if v, ok := m.byGUTI.Load(guti); ok && v == ctx {
		m.byGUTI.Delete(guti)
	}
}

// Count returns the number of live UE contexts.
func (m *Manager) Count() int {
	n := 0
	m.byMMEID.Range(func(_, _ interface{}) bool { n++; return true })
	return n
}

// List returns a snapshot of all live UE contexts.
func (m *Manager) List() []*Context {
	var out []*Context
	m.byMMEID.Range(func(_, v interface{}) bool {
		out = append(out, v.(*Context))
		return true
	})
	return out
}

// MustGetByMMEID returns a context or panics — for use in tests.
func (m *Manager) MustGetByMMEID(id uint32) *Context {
	ctx, ok := m.GetByMMEID(id)
	if !ok {
		panic(fmt.Sprintf("uecontext: no context for MME ID %d", id))
	}
	return ctx
}
