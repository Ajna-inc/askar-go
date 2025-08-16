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

	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/handles"
)

// Entry represents a stored entry
type Entry struct {
	Category string
	Name     string
	Value    []byte
	Tags     map[string]interface{}
}

// getEntryFromList retrieves an entry from an entry list handle at the given index
func getEntryFromList(handle *handles.EntryListHandle, index int32) (*Entry, error) {
	var category, name, tags *C.char
	
	// EntryListHandle is a struct with a pointer field
	handleStruct := C.EntryListHandle{_0: (*C.FfiEntryList)(handle.Ptr())}
	code := C.askar_entry_list_get_category(handleStruct, C.int32_t(index), &category)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	code = C.askar_entry_list_get_name(handleStruct, C.int32_t(index), &name)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	code = C.askar_entry_list_get_tags(handleStruct, C.int32_t(index), &tags)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	// Get value
	var buffer C.struct_SecretBuffer
	
	code = C.askar_entry_list_get_value(
		handleStruct,
		C.int32_t(index),
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	var value []byte
	if buffer.data != nil {
		value = C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
		C.askar_buffer_free(buffer)
	}
	
	entry := &Entry{
		Category: C.GoString(category),
		Name:     C.GoString(name),
		Value:    value,
	}
	
	if tags != nil {
		tagsStr := C.GoString(tags)
		if tagsStr != "" {
			if err := json.Unmarshal([]byte(tagsStr), &entry.Tags); err != nil {
				return nil, err
			}
		}
	}
	
	return entry, nil
}

// getAllEntriesFromList retrieves all entries from an entry list handle
func getAllEntriesFromList(handle *handles.EntryListHandle) ([]*Entry, error) {
	var count C.int32_t
	handleStruct := C.EntryListHandle{_0: (*C.FfiEntryList)(handle.Ptr())}
	code := C.askar_entry_list_count(handleStruct, &count)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	entries := make([]*Entry, 0, count)
	for i := C.int32_t(0); i < count; i++ {
		entry, err := getEntryFromList(handle, int32(i))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	
	return entries, nil
}