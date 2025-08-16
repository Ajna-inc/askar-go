package errors

import (
	"fmt"
)

// ErrorCode represents Askar library error codes
type ErrorCode int32

const (
	ErrorCodeSuccess       ErrorCode = 0
	ErrorCodeBackend       ErrorCode = 1
	ErrorCodeBusy          ErrorCode = 2
	ErrorCodeDuplicate     ErrorCode = 3
	ErrorCodeEncryption    ErrorCode = 4
	ErrorCodeInput         ErrorCode = 5
	ErrorCodeNotFound      ErrorCode = 6
	ErrorCodeUnexpected    ErrorCode = 7
	ErrorCodeUnsupported   ErrorCode = 8
	ErrorCodeCustom        ErrorCode = 100
)

// AskarError represents an error from the Askar library
type AskarError struct {
	Code    ErrorCode // @param The error code
	Message string    // @param The error message
	Extra   string    // @param Additional error information
}

// Error implements the error interface
// @return Formatted error string
func (e *AskarError) Error() string {
	if e.Extra != "" {
		return fmt.Sprintf("Askar error %d: %s (%s)", e.Code, e.Message, e.Extra)
	}
	return fmt.Sprintf("Askar error %d: %s", e.Code, e.Message)
}

// NewAskarError creates a new AskarError
// @param code The error code
// @param message The error message
// @return New AskarError instance
func NewAskarError(code ErrorCode, message string) *AskarError {
	return &AskarError{
		Code:    code,
		Message: message,
	}
}

// errorCodeToString converts an error code to a human-readable string
// @param code The error code to convert
// @return Human-readable error description
func errorCodeToString(code ErrorCode) string {
	switch code {
	case ErrorCodeSuccess:
		return "Success"
	case ErrorCodeBackend:
		return "Backend error"
	case ErrorCodeBusy:
		return "Busy"
	case ErrorCodeDuplicate:
		return "Duplicate"
	case ErrorCodeEncryption:
		return "Encryption error"
	case ErrorCodeInput:
		return "Input error"
	case ErrorCodeNotFound:
		return "Not found"
	case ErrorCodeUnexpected:
		return "Unexpected error"
	case ErrorCodeUnsupported:
		return "Unsupported"
	case ErrorCodeCustom:
		return "Custom error"
	default:
		return "Unknown error"
	}
}

// HandleError creates an error from an error code
// @param code The error code returned from C library
// @param getLastError Function to retrieve detailed error message
// @return AskarError or nil if code is success
func HandleError(code ErrorCode, getLastError func() string) error {
	if code == ErrorCodeSuccess {
		return nil
	}
	
	message := getLastError()
	if message == "" {
		message = errorCodeToString(code)
	}
	
	return &AskarError{
		Code:    code,
		Message: message,
	}
}