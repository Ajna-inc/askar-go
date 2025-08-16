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
	"encoding/json"
	"unsafe"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/handles"
)

type Session struct {
	handle        *handles.SessionHandle
	isTransaction bool
}

// Count returns the count of entries matching the filter
// @param category The category to count entries from
// @param tagFilter Optional tag filter as JSON object
// @return The count of matching entries and error if any
func (s *Session) Count(category string, tagFilter map[string]interface{}) (int64, error) {
	callback := ffi.NewCallbackPromise()
	
	var categoryStr *C.char
	if category != "" {
		categoryStr = C.CString(category)
		defer C.free(unsafe.Pointer(categoryStr))
	}
	
	var tagFilterStr *C.char
	if tagFilter != nil {
		tagBytes, err := json.Marshal(tagFilter)
		if err != nil {
			return 0, err
		}
		tagFilterStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagFilterStr))
	}
	
	var count C.int64_t
	
	code := C.askar_session_count(
		C.SessionHandle(s.handle.Handle()),
		categoryStr,
		tagFilterStr,
		(*[0]byte)(callback.CountPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return 0, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return 0, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return int64(count), nil
}

// Fetch retrieves a single entry
// @param category The category of the entry
// @param name The name of the entry
// @param forUpdate Whether to lock the entry for update
// @return The fetched Entry and error if any
func (s *Session) Fetch(category, name string, forUpdate bool) (*Entry, error) {
	callback := ffi.NewCallbackPromise()
	
	categoryStr := C.CString(category)
	defer C.free(unsafe.Pointer(categoryStr))
	
	nameStr := C.CString(name)
	defer C.free(unsafe.Pointer(nameStr))
	
	var update C.int8_t
	if forUpdate {
		update = 1
	}
	
	code := C.askar_session_fetch(
		C.SessionHandle(s.handle.Handle()),
		categoryStr,
		nameStr,
		update,
		(*[0]byte)(callback.EntryListPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	if result.Handle == nil {
		return nil, nil
	}
	
	entryListHandle := handles.NewEntryListHandle(handles.ArcHandle(result.Handle))
	handleStruct := C.EntryListHandle{_0: (*C.FfiEntryList)(entryListHandle.Ptr())}
	defer C.askar_entry_list_free(handleStruct)
	
	// Get the entry from the list (should have exactly one)
	entry, err := getEntryFromList(entryListHandle, 0)
	if err != nil {
		return nil, err
	}
	
	return entry, nil
}

// FetchAll retrieves all matching entries
// @param category The category to fetch from
// @param tagFilter Optional tag filter as JSON object
// @param limit Maximum number of entries to return
// @param forUpdate Whether to lock entries for update
// @param orderBy Field to order results by
// @param descending Whether to order in descending order
// @return Array of matching Entry objects and error if any
func (s *Session) FetchAll(category string, tagFilter map[string]interface{}, limit int64, forUpdate bool, orderBy string, descending bool) ([]*Entry, error) {
	callback := ffi.NewCallbackPromise()
	
	var categoryStr *C.char
	if category != "" {
		categoryStr = C.CString(category)
		defer C.free(unsafe.Pointer(categoryStr))
	}
	
	var tagFilterStr *C.char
	if tagFilter != nil {
		tagBytes, err := json.Marshal(tagFilter)
		if err != nil {
			return nil, err
		}
		tagFilterStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagFilterStr))
	}
	
	var orderByStr *C.char
	if orderBy != "" {
		orderByStr = C.CString(orderBy)
		defer C.free(unsafe.Pointer(orderByStr))
	}
	
	var desc C.int8_t
	if descending {
		desc = 1
	}
	
	var update C.int8_t
	if forUpdate {
		update = 1
	}
	
	code := C.askar_session_fetch_all(
		C.SessionHandle(s.handle.Handle()),
		categoryStr,
		tagFilterStr,
		C.int64_t(limit),
		orderByStr,
		desc,
		update,
		(*[0]byte)(callback.EntryListPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	if result.Handle == nil {
		return []*Entry{}, nil
	}
	
	entryListHandle := handles.NewEntryListHandle(handles.ArcHandle(result.Handle))
	handleStruct := C.EntryListHandle{_0: (*C.FfiEntryList)(entryListHandle.Ptr())}
	defer C.askar_entry_list_free(handleStruct)
	
	return getAllEntriesFromList(entryListHandle)
}

// Insert inserts a new entry
// @param category The category for the entry
// @param name The name of the entry
// @param value The entry value bytes
// @param tags Optional tags as JSON object
// @param expiryMs Optional expiry time in milliseconds
// @return Error if insertion fails
func (s *Session) Insert(category, name string, value []byte, tags map[string]interface{}, expiryMs ...int64) error {
	return s.update(enums.EntryOperationInsert, category, name, value, tags, expiryMs...)
}

// Replace replaces an existing entry
// @param category The category of the entry
// @param name The name of the entry
// @param value The new value bytes
// @param tags Optional new tags as JSON object
// @param expiryMs Optional expiry time in milliseconds
// @return Error if replacement fails
func (s *Session) Replace(category, name string, value []byte, tags map[string]interface{}, expiryMs ...int64) error {
	return s.update(enums.EntryOperationReplace, category, name, value, tags, expiryMs...)
}

// Remove removes an entry
// @param category The category of the entry
// @param name The name of the entry
// @return Error if removal fails
func (s *Session) Remove(category, name string) error {
	return s.update(enums.EntryOperationRemove, category, name, nil, nil)
}

// RemoveAll removes all matching entries
// @param category The category to remove from
// @param tagFilter Optional tag filter as JSON object
// @return The count of removed entries and error if any
func (s *Session) RemoveAll(category string, tagFilter map[string]interface{}) (int64, error) {
	callback := ffi.NewCallbackPromise()
	
	var categoryStr *C.char
	if category != "" {
		categoryStr = C.CString(category)
		defer C.free(unsafe.Pointer(categoryStr))
	}
	
	var tagFilterStr *C.char
	if tagFilter != nil {
		tagBytes, err := json.Marshal(tagFilter)
		if err != nil {
			return 0, err
		}
		tagFilterStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagFilterStr))
	}
	
	code := C.askar_session_remove_all(
		C.SessionHandle(s.handle.Handle()),
		categoryStr,
		tagFilterStr,
		(*[0]byte)(callback.CountPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return 0, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return 0, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	// The count is returned in result.Count field
	return result.Count, nil
}

// FetchKey retrieves a key by name
// @param name The name of the key
// @param forUpdate Whether to lock the key for update
// @return The fetched KeyEntry and error if any
func (s *Session) FetchKey(name string, forUpdate bool) (*KeyEntry, error) {
	callback := ffi.NewCallbackPromise()
	
	nameStr := C.CString(name)
	defer C.free(unsafe.Pointer(nameStr))
	
	var update C.int8_t
	if forUpdate {
		update = 1
	}
	
	code := C.askar_session_fetch_key(
		C.SessionHandle(s.handle.Handle()),
		nameStr,
		update,
		(*[0]byte)(callback.KeyEntryListPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	if result.Handle == nil {
		return nil, nil
	}
	
	keyListHandle := handles.NewKeyEntryListHandle(handles.ArcHandle(result.Handle))
	// KeyEntryListHandle is a struct with a pointer field
	handleStruct := C.KeyEntryListHandle{_0: (*C.FfiKeyEntryList)(keyListHandle.Ptr())}
	defer C.askar_key_entry_list_free(handleStruct)
	
	return getKeyEntryFromList(keyListHandle, 0)
}

// FetchAllKeys retrieves all matching keys
// @param alg Optional algorithm filter
// @param thumbprint Optional thumbprint filter
// @param tagFilter Optional tag filter as JSON object
// @param limit Maximum number of keys to return
// @param forUpdate Whether to lock keys for update
// @return Array of matching KeyEntry objects and error if any
func (s *Session) FetchAllKeys(alg enums.KeyAlgorithm, thumbprint string, tagFilter map[string]interface{}, limit int64, forUpdate bool) ([]*KeyEntry, error) {
	callback := ffi.NewCallbackPromise()
	
	var algStr *C.char
	if alg != "" {
		algStr = C.CString(string(alg))
		defer C.free(unsafe.Pointer(algStr))
	}
	
	var thumbprintStr *C.char
	if thumbprint != "" {
		thumbprintStr = C.CString(thumbprint)
		defer C.free(unsafe.Pointer(thumbprintStr))
	}
	
	var tagFilterStr *C.char
	if tagFilter != nil {
		tagBytes, err := json.Marshal(tagFilter)
		if err != nil {
			return nil, err
		}
		tagFilterStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagFilterStr))
	}
	
	var update C.int8_t
	if forUpdate {
		update = 1
	}
	
	code := C.askar_session_fetch_all_keys(
		C.SessionHandle(s.handle.Handle()),
		algStr,
		thumbprintStr,
		tagFilterStr,
		C.int64_t(limit),
		update,
		(*[0]byte)(callback.KeyEntryListPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	if result.Handle == nil {
		return []*KeyEntry{}, nil
	}
	
	keyListHandle := handles.NewKeyEntryListHandle(handles.ArcHandle(result.Handle))
	// KeyEntryListHandle is a struct with a pointer field
	handleStruct := C.KeyEntryListHandle{_0: (*C.FfiKeyEntryList)(keyListHandle.Ptr())}
	defer C.askar_key_entry_list_free(handleStruct)
	
	return getAllKeyEntriesFromList(keyListHandle)
}

// InsertKey inserts a new key
// @param key The cryptographic key to insert
// @param name The name for the key
// @param metadata Optional metadata string
// @param tags Optional tags as JSON object
// @param expiryMs Optional expiry time in milliseconds
// @return Error if insertion fails
func (s *Session) InsertKey(key *crypto.Key, name string, metadata string, tags map[string]interface{}, expiryMs ...int64) error {
	callback := ffi.NewCallbackPromise()
	
	nameStr := C.CString(name)
	defer C.free(unsafe.Pointer(nameStr))
	
	var metadataStr *C.char
	if metadata != "" {
		metadataStr = C.CString(metadata)
		defer C.free(unsafe.Pointer(metadataStr))
	}
	
	var tagsStr *C.char
	if tags != nil {
		tagBytes, err := json.Marshal(tags)
		if err != nil {
			return err
		}
		tagsStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagsStr))
	}
	
	var expiry C.int64_t = -1
	if len(expiryMs) > 0 {
		expiry = C.int64_t(expiryMs[0])
	}
	
	// LocalKeyHandle is an ArcHandle (struct with pointer)
	keyHandleStruct := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(key.GetHandle().Ptr())}
	code := C.askar_session_insert_key(
		C.SessionHandle(s.handle.Handle()),
		keyHandleStruct,
		nameStr,
		metadataStr,
		tagsStr,
		expiry,
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

// UpdateKey updates key metadata and tags
// @param name The name of the key to update
// @param metadata New metadata string
// @param tags New tags as JSON object
// @param expiryMs Optional expiry time in milliseconds
// @return Error if update fails
func (s *Session) UpdateKey(name string, metadata string, tags map[string]interface{}, expiryMs ...int64) error {
	callback := ffi.NewCallbackPromise()
	
	nameStr := C.CString(name)
	defer C.free(unsafe.Pointer(nameStr))
	
	var metadataStr *C.char
	if metadata != "" {
		metadataStr = C.CString(metadata)
		defer C.free(unsafe.Pointer(metadataStr))
	}
	
	var tagsStr *C.char
	if tags != nil {
		tagBytes, err := json.Marshal(tags)
		if err != nil {
			return err
		}
		tagsStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagsStr))
	}
	
	var expiry C.int64_t = -1
	if len(expiryMs) > 0 {
		expiry = C.int64_t(expiryMs[0])
	}
	
	code := C.askar_session_update_key(
		C.SessionHandle(s.handle.Handle()),
		nameStr,
		metadataStr,
		tagsStr,
		expiry,
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

// RemoveKey removes a key
// @param name The name of the key to remove
// @return Error if removal fails
func (s *Session) RemoveKey(name string) error {
	callback := ffi.NewCallbackPromise()
	
	nameStr := C.CString(name)
	defer C.free(unsafe.Pointer(nameStr))
	
	code := C.askar_session_remove_key(
		C.SessionHandle(s.handle.Handle()),
		nameStr,
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

// Commit commits a transaction
// @return Error if commit fails
// @dev Only valid for transaction sessions
func (s *Session) Commit() error {
	if !s.isTransaction {
		return errors.NewAskarError(errors.ErrorCodeInput, "Cannot commit non-transaction session")
	}
	return s.close(true)
}

// Rollback rolls back a transaction
// @return Error if rollback fails
// @dev Only valid for transaction sessions
func (s *Session) Rollback() error {
	if !s.isTransaction {
		return errors.NewAskarError(errors.ErrorCodeInput, "Cannot rollback non-transaction session")
	}
	return s.close(false)
}

// Close closes the session
// @return Error if closing fails
// @dev Automatically commits or rolls back transactions
func (s *Session) Close() error {
	return s.close(s.isTransaction)
}

func (s *Session) close(commit bool) error {
	if s.handle == nil {
		return nil
	}
	
	callback := ffi.NewCallbackPromise()
	
	var com C.int8_t
	if commit {
		com = 1
	}
	
	code := C.askar_session_close(
		C.SessionHandle(s.handle.Handle()),
		com,
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

func (s *Session) update(operation enums.EntryOperation, category, name string, value []byte, tags map[string]interface{}, expiryMs ...int64) error {
	callback := ffi.NewCallbackPromise()
	
	categoryStr := C.CString(category)
	defer C.free(unsafe.Pointer(categoryStr))
	
	nameStr := C.CString(name)
	defer C.free(unsafe.Pointer(nameStr))
	
	// Create ByteBuffer from value
	var valueBuffer C.ByteBuffer
	if len(value) > 0 {
		valueBuffer.data = (*C.uint8_t)(unsafe.Pointer(&value[0]))
		valueBuffer.len = C.int64_t(len(value))
	}
	
	var tagsStr *C.char
	if tags != nil {
		tagBytes, err := json.Marshal(tags)
		if err != nil {
			return err
		}
		tagsStr = C.CString(string(tagBytes))
		defer C.free(unsafe.Pointer(tagsStr))
	}
	
	var expiry C.int64_t = -1
	if len(expiryMs) > 0 {
		expiry = C.int64_t(expiryMs[0])
	}
	
	code := C.askar_session_update(
		C.SessionHandle(s.handle.Handle()),
		C.int8_t(operation),
		categoryStr,
		nameStr,
		valueBuffer,
		tagsStr,
		expiry,
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

func (s *Session) cleanup() {
	if s.handle != nil {
		s.Close()
	}
}