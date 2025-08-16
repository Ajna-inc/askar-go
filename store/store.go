package store

/*
#cgo CFLAGS: -I${SRCDIR}/../native
#cgo darwin LDFLAGS: -L${SRCDIR}/../native -laries_askar -framework Security -framework Foundation
#cgo linux LDFLAGS: -L${SRCDIR}/../native -laries_askar -lm -ldl

#include <stdint.h>
#include <stdlib.h>
#include "libaries_askar.h"
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/handles"
)

type Store struct {
	handle *handles.StoreHandle
	uri    string
}

// GenerateRawKey generates a raw store key
// @param seed Optional seed bytes for deterministic key generation
// @return The generated raw key string and error if any
func GenerateRawKey(seed []byte) (string, error) {
	var seedBuf C.struct_ByteBuffer
	if len(seed) > 0 {
		seedBuf.data = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
		seedBuf.len = C.int64_t(len(seed))
	}
	
	var out *C.char
	code := C.askar_store_generate_raw_key(seedBuf, &out)
	
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if out == nil {
		return "", errors.NewAskarError(errors.ErrorCodeBackend, "failed to generate raw key")
	}
	
	result := C.GoString(out)
	C.free(unsafe.Pointer(out))
	
	return result, nil
}


// Provision creates and opens a new store
// @param uri The store URI (e.g., "sqlite://path/to/db")
// @param keyMethod The key derivation method to use
// @param passKey The passphrase for encryption
// @param profile Optional profile name
// @param recreate Whether to recreate if store exists
// @return The provisioned Store instance and error if any
func Provision(uri string, keyMethod enums.StoreKeyMethod, passKey string, profile string, recreate bool) (*Store, error) {
	callback := ffi.NewCallbackPromise()
	
	uriStr := C.CString(uri)
	defer C.free(unsafe.Pointer(uriStr))
	
	keyMethodStr := C.CString(string(keyMethod))
	defer C.free(unsafe.Pointer(keyMethodStr))
	
	var passKeyStr *C.char
	if passKey != "" {
		passKeyStr = C.CString(passKey)
		defer C.free(unsafe.Pointer(passKeyStr))
	}
	
	var profileStr *C.char
	if profile != "" {
		profileStr = C.CString(profile)
		defer C.free(unsafe.Pointer(profileStr))
	}
	
	var rec C.int8_t
	if recreate {
		rec = 1
	}
	
	code := C.askar_store_provision(
		uriStr,
		keyMethodStr,
		passKeyStr,
		profileStr,
		rec,
		(*[0]byte)(callback.StorePtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	// Store handle is a SequenceHandle (uintptr)
	store := &Store{
		handle: handles.NewStoreHandle(handles.SequenceHandle(uintptr(result.Handle))),
		uri:    uri,
	}
	runtime.SetFinalizer(store, (*Store).cleanup)
	
	return store, nil
}

// Open opens an existing store
// @param uri The store URI (e.g., "sqlite://path/to/db")
// @param keyMethod The key derivation method used
// @param passKey The passphrase for decryption
// @param profile Optional profile name to open
// @return The opened Store instance and error if any
func Open(uri string, keyMethod enums.StoreKeyMethod, passKey string, profile string) (*Store, error) {
	callback := ffi.NewCallbackPromise()
	
	uriStr := C.CString(uri)
	defer C.free(unsafe.Pointer(uriStr))
	
	var keyMethodStr *C.char
	if keyMethod != "" {
		keyMethodStr = C.CString(string(keyMethod))
		defer C.free(unsafe.Pointer(keyMethodStr))
	}
	
	var passKeyStr *C.char
	if passKey != "" {
		passKeyStr = C.CString(passKey)
		defer C.free(unsafe.Pointer(passKeyStr))
	}
	
	var profileStr *C.char
	if profile != "" {
		profileStr = C.CString(profile)
		defer C.free(unsafe.Pointer(profileStr))
	}
	
	code := C.askar_store_open(
		uriStr,
		keyMethodStr,
		passKeyStr,
		profileStr,
		(*[0]byte)(callback.StorePtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	// Store handle is a SequenceHandle (uintptr)
	store := &Store{
		handle: handles.NewStoreHandle(handles.SequenceHandle(uintptr(result.Handle))),
		uri:    uri,
	}
	runtime.SetFinalizer(store, (*Store).cleanup)
	
	return store, nil
}

// Close closes the store
// @return Error if closing fails
func (s *Store) Close() error {
	if s.handle == nil {
		return nil
	}
	
	callback := ffi.NewCallbackPromise()
	
	code := C.askar_store_close(
		C.StoreHandle(s.handle.Handle()),
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	s.handle = nil
	return nil
}

// Remove removes a store at the given URI (static function)
// @param uri The store URI to remove
// @return Error if removal fails
func Remove(uri string) error {
	callback := ffi.NewCallbackPromise()
	
	uriStr := C.CString(uri)
	defer C.free(unsafe.Pointer(uriStr))
	
	code := C.askar_store_remove(
		uriStr,
		(*[0]byte)(callback.CountPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return nil
}

// Rekey changes the store encryption key
// @param keyMethod The new key derivation method
// @param passKey The new passphrase
// @return Error if rekeying fails
func (s *Store) Rekey(keyMethod enums.StoreKeyMethod, passKey string) error {
	callback := ffi.NewCallbackPromise()
	
	keyMethodStr := C.CString(string(keyMethod))
	defer C.free(unsafe.Pointer(keyMethodStr))
	
	var passKeyStr *C.char
	if passKey != "" {
		passKeyStr = C.CString(passKey)
		defer C.free(unsafe.Pointer(passKeyStr))
	}
	
	code := C.askar_store_rekey(
		C.StoreHandle(s.handle.Handle()),
		keyMethodStr,
		passKeyStr,
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return nil
}

// Copy copies the store to a new location
// @param targetURI The destination URI
// @param keyMethod The key derivation method for the copy
// @param passKey The passphrase for the copy
// @param recreate Whether to recreate if target exists
// @return The copied Store instance and error if any
func (s *Store) Copy(targetURI string, keyMethod enums.StoreKeyMethod, passKey string, recreate bool) (*Store, error) {
	callback := ffi.NewCallbackPromise()
	
	targetStr := C.CString(targetURI)
	defer C.free(unsafe.Pointer(targetStr))
	
	keyMethodStr := C.CString(string(keyMethod))
	defer C.free(unsafe.Pointer(keyMethodStr))
	
	var passKeyStr *C.char
	if passKey != "" {
		passKeyStr = C.CString(passKey)
		defer C.free(unsafe.Pointer(passKeyStr))
	}
	
	var rec C.int8_t
	if recreate {
		rec = 1
	}
	
	code := C.askar_store_copy(
		C.StoreHandle(s.handle.Handle()),
		targetStr,
		keyMethodStr,
		passKeyStr,
		rec,
		(*[0]byte)(callback.StorePtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	store := &Store{
		handle: handles.NewStoreHandle(handles.SequenceHandle(uintptr(result.Handle))),
		uri:    targetURI,
	}
	runtime.SetFinalizer(store, (*Store).cleanup)
	
	return store, nil
}

// CreateProfile creates a new profile in the store
// @param profile The profile name to create
// @return Error if profile creation fails
func (s *Store) CreateProfile(profile string) error {
	callback := ffi.NewCallbackPromise()
	
	profileStr := C.CString(profile)
	defer C.free(unsafe.Pointer(profileStr))
	
	code := C.askar_store_create_profile(
		C.StoreHandle(s.handle.Handle()),
		profileStr,
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return nil
}

// GetProfileName returns the current profile name
// @return The current profile name and error if any
func (s *Store) GetProfileName() (string, error) {
	callback := ffi.NewCallbackPromise()
	
	code := C.askar_store_get_profile_name(
		C.StoreHandle(s.handle.Handle()),
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return "", errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	// Extract profile name from callback result
	return "", nil
}

// GetDefaultProfile returns the default profile name for the store
// @return The default profile name and error if any
func (s *Store) GetDefaultProfile() (string, error) {
	callback := ffi.NewCallbackPromise()
	
	code := C.askar_store_get_default_profile(
		C.StoreHandle(s.handle.Handle()),
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return "", errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	// Extract profile name from callback result
	return "", nil
}

// ListProfiles lists all profiles in the store
// @return Array of profile names and error if any
func (s *Store) ListProfiles() ([]string, error) {
	callback := ffi.NewCallbackPromise()
	
	code := C.askar_store_list_profiles(
		C.StoreHandle(s.handle.Handle()),
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	// StringListHandle is an ArcHandle struct
	listHandle := C.StringListHandle{_0: (*C.FfiStringList)(result.Handle)}
	defer C.askar_string_list_free(listHandle)
	
	var count C.int32_t
	code = C.askar_string_list_count(listHandle, &count)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	profiles := make([]string, 0, count)
	for i := C.int32_t(0); i < count; i++ {
		var item *C.char
		code = C.askar_string_list_get_item(listHandle, i, &item)
		if code != 0 {
			return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
		}
		profiles = append(profiles, C.GoString(item))
	}
	
	return profiles, nil
}

// RemoveProfile removes a profile from the store
// @param profile The profile name to remove
// @return Error if removal fails
func (s *Store) RemoveProfile(profile string) error {
	callback := ffi.NewCallbackPromise()
	
	profileStr := C.CString(profile)
	defer C.free(unsafe.Pointer(profileStr))
	
	code := C.askar_store_remove_profile(
		C.StoreHandle(s.handle.Handle()),
		profileStr,
		(*[0]byte)(callback.CountPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return nil
}

// SetDefaultProfile sets the default profile
// @param profile The profile name to set as default
// @return Error if setting fails
func (s *Store) SetDefaultProfile(profile string) error {
	callback := ffi.NewCallbackPromise()
	
	profileStr := C.CString(profile)
	defer C.free(unsafe.Pointer(profileStr))
	
	code := C.askar_store_set_default_profile(
		C.StoreHandle(s.handle.Handle()),
		profileStr,
		(*[0]byte)(callback.Ptr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return nil
}

// Session creates a new session for the store
// @param profile Optional profile name
// @return The new Session instance and error if any
func (s *Store) Session(profile string) (*Session, error) {
	return s.OpenSession(profile, false)
}

// Transaction creates a new transaction session for the store
// @param profile Optional profile name
// @return The new transaction Session and error if any
func (s *Store) Transaction(profile string) (*Session, error) {
	return s.OpenSession(profile, true)
}

// OpenSession opens a new session
// @param profile Optional profile name
// @param asTransaction Whether to open as a transaction
// @return The new Session instance and error if any
func (s *Store) OpenSession(profile string, asTransaction bool) (*Session, error) {
	callback := ffi.NewCallbackPromise()
	
	var profileStr *C.char
	if profile != "" {
		profileStr = C.CString(profile)
		defer C.free(unsafe.Pointer(profileStr))
	}
	
	var asTx C.int8_t
	if asTransaction {
		asTx = 1
	}
	
	code := C.askar_session_start(
		C.StoreHandle(s.handle.Handle()),
		profileStr,
		asTx,
		(*[0]byte)(callback.SessionPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	session := &Session{
		handle:        handles.NewSessionHandle(handles.SequenceHandle(uintptr(result.Handle))),
		isTransaction: asTransaction,
	}
	runtime.SetFinalizer(session, (*Session).cleanup)
	
	return session, nil
}


// GetHandle returns the underlying handle
// @return The internal StoreHandle
func (s *Store) GetHandle() *handles.StoreHandle {
	return s.handle
}

func (s *Store) cleanup() {
	if s.handle != nil {
		s.Close()
	}
}