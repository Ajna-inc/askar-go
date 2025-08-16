package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../native
#cgo darwin LDFLAGS: -L${SRCDIR}/../native -laries_askar -framework Security -framework Foundation
#cgo linux LDFLAGS: -L${SRCDIR}/../native -laries_askar -lm -ldl
#cgo windows LDFLAGS: -L${SRCDIR}/../native -laries_askar -lws2_32 -ladvapi32 -luserenv -lbcrypt

#include <stdint.h>
#include <stdlib.h>
#include "libaries_askar.h"
*/
import "C"
import "unsafe"

// Version returns the version of the Askar library
// @return The library version string and error if any
func Version() (string, error) {
	version := C.askar_version()
	if version == nil {
		return "", &AskarError{Code: -1, Message: "Failed to get version"}
	}
	return C.GoString(version), nil
}

// GetCurrentError returns the current error message
// @return The last error message from the C library
func GetCurrentError() string {
	var errorJSON *C.char
	code := C.askar_get_current_error(&errorJSON)
	if code != 0 || errorJSON == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(errorJSON))
	return C.GoString(errorJSON)
}

// SetMaxLogLevel sets the maximum log level
// @param level The log level to set
// @return Always returns nil
func SetMaxLogLevel(level int32) error {
	C.askar_set_max_log_level(C.int32_t(level))
	return nil
}

// handleError converts a C error code to a Go error
// @param code The error code from C library
// @return AskarError or nil if success
func handleError(code int32) error {
	if code == 0 {
		return nil
	}
	errorMsg := GetCurrentError()
	return &AskarError{
		Code:    code,
		Message: errorMsg,
	}
}

// AskarError represents an FFI error
type AskarError struct {
	Code    int32  // @param The error code
	Message string // @param The error message
}

// Error implements the error interface
// @return The error message
func (e *AskarError) Error() string {
	return e.Message
}