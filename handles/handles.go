package handles

import (
	"runtime"
	"sync"
	"unsafe"
)

// For Store/Session/Scan handles - these are size_t values
type SequenceHandle uintptr

// For Arc handles (EntryList, KeyEntryList, LocalKey) - these are pointers
type ArcHandle unsafe.Pointer

type StoreHandle struct {
	handle SequenceHandle
	mu     sync.Mutex
}

type SessionHandle struct {
	handle SequenceHandle
	mu     sync.Mutex
}

type ScanHandle struct {
	handle SequenceHandle
	mu     sync.Mutex
}

type LocalKeyHandle struct {
	handle ArcHandle
	mu     sync.Mutex
}

type EntryListHandle struct {
	handle ArcHandle
	mu     sync.Mutex
}

type KeyEntryListHandle struct {
	handle ArcHandle
	mu     sync.Mutex
}

func NewStoreHandle(handle SequenceHandle) *StoreHandle {
	h := &StoreHandle{handle: handle}
	runtime.SetFinalizer(h, (*StoreHandle).cleanup)
	return h
}

func NewSessionHandle(handle SequenceHandle) *SessionHandle {
	h := &SessionHandle{handle: handle}
	runtime.SetFinalizer(h, (*SessionHandle).cleanup)
	return h
}

func NewScanHandle(handle SequenceHandle) *ScanHandle {
	h := &ScanHandle{handle: handle}
	runtime.SetFinalizer(h, (*ScanHandle).cleanup)
	return h
}

func NewLocalKeyHandle(handle ArcHandle) *LocalKeyHandle {
	h := &LocalKeyHandle{handle: handle}
	runtime.SetFinalizer(h, (*LocalKeyHandle).cleanup)
	return h
}

func NewEntryListHandle(handle ArcHandle) *EntryListHandle {
	h := &EntryListHandle{handle: handle}
	runtime.SetFinalizer(h, (*EntryListHandle).cleanup)
	return h
}

func NewKeyEntryListHandle(handle ArcHandle) *KeyEntryListHandle {
	h := &KeyEntryListHandle{handle: handle}
	runtime.SetFinalizer(h, (*KeyEntryListHandle).cleanup)
	return h
}

func (h *StoreHandle) Handle() SequenceHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

func (h *SessionHandle) Handle() SequenceHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

func (h *ScanHandle) Handle() SequenceHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

func (h *LocalKeyHandle) Ptr() ArcHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

func (h *EntryListHandle) Ptr() ArcHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

func (h *KeyEntryListHandle) Ptr() ArcHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

func (h *StoreHandle) cleanup() {
	// Will be implemented with FFI
}

func (h *SessionHandle) cleanup() {
	// Will be implemented with FFI
}

func (h *LocalKeyHandle) cleanup() {
	// Will be implemented with FFI
}

func (h *EntryListHandle) cleanup() {
	// Will be implemented with FFI
}

func (h *KeyEntryListHandle) cleanup() {
	// Will be implemented with FFI
}

func (h *ScanHandle) cleanup() {
	// Will be implemented with FFI
}