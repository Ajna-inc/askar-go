package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../native
#include <stdint.h>
#include <stdlib.h>
#include "libaries_askar.h"

// Callback types matching the C API
extern void goCallback(int64_t cb_id, int64_t err);
extern void goCallbackStore(int64_t cb_id, int64_t err, size_t handle);
extern void goCallbackSession(int64_t cb_id, int64_t err, size_t handle);
extern void goCallbackCount(int64_t cb_id, int64_t err, int64_t count);
extern void goCallbackEntryList(int64_t cb_id, int64_t err, EntryListHandle handle);
extern void goCallbackKeyEntryList(int64_t cb_id, int64_t err, KeyEntryListHandle handle);
extern void goCallbackLocalKey(int64_t cb_id, int64_t err, LocalKeyHandle handle);
extern void goCallbackScan(int64_t cb_id, int64_t err, size_t handle);

// C wrapper functions to get callback pointers
static void* get_callback() {
    return (void*)goCallback;
}

static void* get_callback_store() {
    return (void*)goCallbackStore;
}

static void* get_callback_session() {
    return (void*)goCallbackSession;
}

static void* get_callback_count() {
    return (void*)goCallbackCount;
}

static void* get_callback_entry_list() {
    return (void*)goCallbackEntryList;
}

static void* get_callback_key_entry_list() {
    return (void*)goCallbackKeyEntryList;
}

static void* get_callback_local_key() {
    return (void*)goCallbackLocalKey;
}

static void* get_callback_scan() {
    return (void*)goCallbackScan;
}
*/
import "C"
import (
	"sync"
	"sync/atomic"
	"unsafe"
)

var (
	callbackCounter int64
	callbacks       sync.Map
)

// CallbackResult holds the result from an async callback
type CallbackResult struct {
	ErrorCode int32          // @param The error code from the operation
	Handle    unsafe.Pointer // @param The returned handle (if any)
	Count     int64          // @param The returned count (for count operations)
}

// CallbackPromise manages async callbacks from C library
type CallbackPromise struct {
	id     int64               // @param Unique callback ID
	result chan CallbackResult // @param Channel to receive result
}

// NewCallbackPromise creates a new callback promise
// @return New CallbackPromise instance
func NewCallbackPromise() *CallbackPromise {
	id := atomic.AddInt64(&callbackCounter, 1)
	p := &CallbackPromise{
		id:     id,
		result: make(chan CallbackResult, 1),
	}
	callbacks.Store(id, p)
	return p
}

// ID returns the callback ID
// @return The unique callback ID
func (p *CallbackPromise) ID() int64 {
	return p.id
}

// CallbackId returns the callback ID as C type
// @return The callback ID as C.CallbackId
func (p *CallbackPromise) CallbackId() C.CallbackId {
	return C.CallbackId(p.id)
}

// Wait blocks until the callback completes
// @return The callback result
func (p *CallbackPromise) Wait() CallbackResult {
	result := <-p.result
	callbacks.Delete(p.id)
	return result
}

// Ptr returns the C callback function pointer
// @return Pointer to the C callback function
func (p *CallbackPromise) Ptr() unsafe.Pointer {
	return C.get_callback()
}

// StorePtr returns the store callback function pointer
// @return Pointer to the store callback function
func (p *CallbackPromise) StorePtr() unsafe.Pointer {
	return C.get_callback_store()
}

// SessionPtr returns the session callback function pointer
// @return Pointer to the session callback function
func (p *CallbackPromise) SessionPtr() unsafe.Pointer {
	return C.get_callback_session()
}

// CountPtr returns the count callback function pointer
// @return Pointer to the count callback function
func (p *CallbackPromise) CountPtr() unsafe.Pointer {
	return C.get_callback_count()
}

// EntryListPtr returns the entry list callback function pointer
// @return Pointer to the entry list callback function
func (p *CallbackPromise) EntryListPtr() unsafe.Pointer {
	return C.get_callback_entry_list()
}

// KeyEntryListPtr returns the key entry list callback function pointer
// @return Pointer to the key entry list callback function
func (p *CallbackPromise) KeyEntryListPtr() unsafe.Pointer {
	return C.get_callback_key_entry_list()
}

// LocalKeyPtr returns the local key callback function pointer
// @return Pointer to the local key callback function
func (p *CallbackPromise) LocalKeyPtr() unsafe.Pointer {
	return C.get_callback_local_key()
}

// ScanPtr returns the scan callback function pointer
// @return Pointer to the scan callback function
func (p *CallbackPromise) ScanPtr() unsafe.Pointer {
	return C.get_callback_scan()
}

// Go callback implementations exported to C

//export goCallback
func goCallback(cbID C.int64_t, errorCode C.int64_t) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
		}
	}
}

//export goCallbackStore
func goCallbackStore(cbID C.int64_t, errorCode C.int64_t, handle C.size_t) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Handle:    unsafe.Pointer(uintptr(handle)),
		}
	}
}

//export goCallbackSession
func goCallbackSession(cbID C.int64_t, errorCode C.int64_t, handle C.size_t) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Handle:    unsafe.Pointer(uintptr(handle)),
		}
	}
}

//export goCallbackCount
func goCallbackCount(cbID C.int64_t, errorCode C.int64_t, count C.int64_t) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Count:     int64(count),
		}
	}
}

//export goCallbackEntryList
func goCallbackEntryList(cbID C.int64_t, errorCode C.int64_t, handle C.EntryListHandle) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Handle:    unsafe.Pointer(handle._0),
		}
	}
}

//export goCallbackKeyEntryList
func goCallbackKeyEntryList(cbID C.int64_t, errorCode C.int64_t, handle C.KeyEntryListHandle) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Handle:    unsafe.Pointer(handle._0),
		}
	}
}

//export goCallbackLocalKey
func goCallbackLocalKey(cbID C.int64_t, errorCode C.int64_t, handle C.LocalKeyHandle) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Handle:    unsafe.Pointer(handle._0),
		}
	}
}

//export goCallbackScan
func goCallbackScan(cbID C.int64_t, errorCode C.int64_t, handle C.size_t) {
	id := int64(cbID)
	if promise, ok := callbacks.Load(id); ok {
		p := promise.(*CallbackPromise)
		p.result <- CallbackResult{
			ErrorCode: int32(errorCode),
			Handle:    unsafe.Pointer(uintptr(handle)),
		}
	}
}