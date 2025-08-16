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
	"github.com/Ajna-inc/askar-go/handles"
)

// KeyEntry represents a stored key entry
type KeyEntry struct {
	Algorithm enums.KeyAlgorithm
	Name      string
	Metadata  string
	Tags      map[string]interface{}
	key       *crypto.Key
	listHandle *handles.KeyEntryListHandle
	index     int32
}

// LoadLocal loads the actual key from the entry
func (k *KeyEntry) LoadLocal() (*crypto.Key, error) {
	if k.key != nil {
		return k.key, nil
	}
	
	if k.listHandle == nil {
		return nil, errors.NewAskarError(errors.ErrorCodeInput, "KeyEntry not associated with a list")
	}
	
	// KeyEntryListHandle is a struct with a pointer field
	handleStruct := C.KeyEntryListHandle{_0: (*C.FfiKeyEntryList)(k.listHandle.Ptr())}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_entry_list_load_local(
		handleStruct,
		C.int32_t(k.index),
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := crypto.NewKeyFromHandle(handle)
	
	// Store in internal field to reuse
	k.key = key
	
	return key, nil
}

// getKeyEntryFromList retrieves a key entry from a key entry list handle at the given index
func getKeyEntryFromList(handle *handles.KeyEntryListHandle, index int32) (*KeyEntry, error) {
	var algorithm, name, metadata, tags *C.char
	
	// KeyEntryListHandle is a struct with a pointer field
	handleStruct := C.KeyEntryListHandle{_0: (*C.FfiKeyEntryList)(handle.Ptr())}
	
	code := C.askar_key_entry_list_get_algorithm(handleStruct, C.int32_t(index), &algorithm)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	code = C.askar_key_entry_list_get_name(handleStruct, C.int32_t(index), &name)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	code = C.askar_key_entry_list_get_metadata(handleStruct, C.int32_t(index), &metadata)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	code = C.askar_key_entry_list_get_tags(handleStruct, C.int32_t(index), &tags)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	entry := &KeyEntry{
		Algorithm: enums.KeyAlgorithm(C.GoString(algorithm)),
		Name:      C.GoString(name),
		Metadata:  C.GoString(metadata),
		listHandle: handle,
		index:     index,
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

// getAllKeyEntriesFromList retrieves all key entries from a key entry list handle
func getAllKeyEntriesFromList(handle *handles.KeyEntryListHandle) ([]*KeyEntry, error) {
	var count C.int32_t
	// KeyEntryListHandle is a struct with a pointer field
	handleStruct := C.KeyEntryListHandle{_0: (*C.FfiKeyEntryList)(handle.Ptr())}
	code := C.askar_key_entry_list_count(handleStruct, &count)
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	entries := make([]*KeyEntry, 0, count)
	for i := C.int32_t(0); i < count; i++ {
		entry, err := getKeyEntryFromList(handle, int32(i))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	
	return entries, nil
}