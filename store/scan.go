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
	"runtime"
	"unsafe"

	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/handles"
)

// Scan represents a database scan operation
// @dev Allows iterating over large result sets efficiently
type Scan struct {
	handle   *handles.ScanHandle
	store    *Store
	category string
}

// StartScan starts a new scan operation
// @param profile Optional profile name to scan
// @param category The category to scan
// @param tagFilter Optional tag filter as JSON object
// @param offset Number of entries to skip
// @param limit Maximum number of entries to return
// @param orderBy Field to order results by
// @param descending Whether to order in descending order
// @return New Scan instance and error if any
func (s *Store) StartScan(profile, category string, tagFilter map[string]interface{}, offset, limit int64, orderBy string, descending bool) (*Scan, error) {
	callback := ffi.NewCallbackPromise()
	
	var profileStr *C.char
	if profile != "" {
		profileStr = C.CString(profile)
		defer C.free(unsafe.Pointer(profileStr))
	}
	
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
	
	// StoreHandle is a SequenceHandle (size_t/uintptr)
	code := C.askar_scan_start(
		C.StoreHandle(s.handle.Handle()),
		profileStr,
		categoryStr,
		tagFilterStr,
		C.int64_t(offset),
		C.int64_t(limit),
		orderByStr,
		desc,
		(*[0]byte)(callback.ScanPtr()),
		C.CallbackId(callback.ID()),
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return nil, errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	scan := &Scan{
		handle:   handles.NewScanHandle(handles.SequenceHandle(uintptr(result.Handle))),
		store:    s,
		category: category,
	}
	runtime.SetFinalizer(scan, (*Scan).cleanup)
	
	return scan, nil
}

// Next retrieves the next batch of entries from the scan
// @return Array of Entry objects and error if any
func (s *Scan) Next() ([]*Entry, error) {
	callback := ffi.NewCallbackPromise()
	
	code := C.askar_scan_next(
		C.ScanHandle(s.handle.Handle()),
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
		// No more entries
		return nil, nil
	}
	
	entryListHandle := handles.NewEntryListHandle(handles.ArcHandle(result.Handle))
	handleStruct := C.EntryListHandle{_0: (*C.FfiEntryList)(entryListHandle.Ptr())}
	defer C.askar_entry_list_free(handleStruct)
	
	return getAllEntriesFromList(entryListHandle)
}

// Close closes the scan and releases resources
// @return Error if closing fails
func (s *Scan) Close() error {
	if s.handle == nil {
		return nil
	}
	
	code := C.askar_scan_free(C.ScanHandle(s.handle.Handle()))
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	s.handle = nil
	return nil
}

// Iterate provides a convenient way to iterate over all entries
// @param fn Function to call for each entry
// @return Error if iteration or callback fails
func (s *Scan) Iterate(fn func(*Entry) error) error {
	for {
		entries, err := s.Next()
		if err != nil {
			return err
		}
		
		if entries == nil {
			// No more entries
			break
		}
		
		for _, entry := range entries {
			if err := fn(entry); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// CollectAll retrieves all entries from the scan
// @return Array of all Entry objects and error if any
// @dev Loads all remaining entries into memory at once
func (s *Scan) CollectAll() ([]*Entry, error) {
	var allEntries []*Entry
	
	for {
		entries, err := s.Next()
		if err != nil {
			return nil, err
		}
		
		if entries == nil {
			// No more entries
			break
		}
		
		allEntries = append(allEntries, entries...)
	}
	
	return allEntries, nil
}

func (s *Scan) cleanup() {
	if s.handle != nil {
		s.Close()
	}
}