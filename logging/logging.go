package logging

/*
#cgo CFLAGS: -I${SRCDIR}/../native
#cgo darwin LDFLAGS: -L${SRCDIR}/../native -laries_askar -framework Security -framework Foundation
#cgo linux LDFLAGS: -L${SRCDIR}/../native -laries_askar -lm -ldl

#include <stdint.h>
#include <stdlib.h>

extern int32_t askar_set_custom_logger(void* context, void* enabled, void* callback, void* max_level);
extern int32_t askar_set_max_log_level(int32_t max_level);
extern void askar_set_default_logger(void);
extern void askar_clear_custom_logger(void);

// Callback function for custom logger
typedef void (*LogCallback)(void* context, int32_t level, const char* target, const char* message, const char* module_path, const char* file, int32_t line);

// External C function that will call our Go callback
extern void cLogCallback(void* context, int32_t level, const char* target, const char* message, const char* module_path, const char* file, int32_t line);

static LogCallback getLogCallbackPtr() {
    return cLogCallback;
}
*/
import "C"
import (
	"log"
	"sync"
	"unsafe"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
)

var (
	customLoggerMu sync.Mutex
	customLogger   LoggerFunc
)

// LoggerFunc is the function signature for custom loggers
// @param level The log level of the message
// @param target The target module or component
// @param message The log message
// @param modulePath The module path
// @param file The source file name
// @param line The line number in the source file
type LoggerFunc func(level enums.LogLevel, target, message, modulePath, file string, line int32)

// SetMaxLogLevel sets the maximum log level
// @param level The maximum log level to output
// @return Error if setting fails
func SetMaxLogLevel(level enums.LogLevel) error {
	code := C.askar_set_max_log_level(C.int32_t(level))
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), nil)
	}
	return nil
}

// SetDefaultLogger sets the default logger
// @dev Activates the built-in default logger implementation
func SetDefaultLogger() {
	C.askar_set_default_logger()
}

// SetCustomLogger sets a custom logger function
// @param logger The custom logger function to use
// @param maxLevel The maximum log level to output
// @return Error if setting fails
func SetCustomLogger(logger LoggerFunc, maxLevel enums.LogLevel) error {
	customLoggerMu.Lock()
	defer customLoggerMu.Unlock()
	
	customLogger = logger
	
	// Pass 1 for enabled
	enabled := unsafe.Pointer(uintptr(1))
	maxLevelPtr := unsafe.Pointer(uintptr(maxLevel))
	
	code := C.askar_set_custom_logger(
		nil, // context
		enabled,
		unsafe.Pointer(C.getLogCallbackPtr()),
		maxLevelPtr,
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), nil)
	}
	
	return nil
}

// ClearCustomLogger removes the custom logger
// @dev Disables custom logging and reverts to default behavior
func ClearCustomLogger() {
	customLoggerMu.Lock()
	defer customLoggerMu.Unlock()
	
	customLogger = nil
	C.askar_clear_custom_logger()
}

//export goLogCallback
func goLogCallback(context unsafe.Pointer, level C.int32_t, target, message, modulePath, file *C.char, line C.int32_t) {
	customLoggerMu.Lock()
	logger := customLogger
	customLoggerMu.Unlock()
	
	if logger == nil {
		return
	}
	
	logger(
		enums.LogLevel(level),
		C.GoString(target),
		C.GoString(message),
		C.GoString(modulePath),
		C.GoString(file),
		int32(line),
	)
}

// DefaultLogger provides a simple default logger implementation
// @param level The log level of the message
// @param target The target module or component
// @param message The log message
// @param modulePath The module path
// @param file The source file name
// @param line The line number in the source file
// @dev Formats and prints log messages using standard Go log package
func DefaultLogger(level enums.LogLevel, target, message, modulePath, file string, line int32) {
	levelStr := "INFO"
	switch level {
	case enums.LogLevelError:
		levelStr = "ERROR"
	case enums.LogLevelWarn:
		levelStr = "WARN"
	case enums.LogLevelDebug:
		levelStr = "DEBUG"
	case enums.LogLevelTrace:
		levelStr = "TRACE"
	}
	
	log.Printf("[%s] %s:%d - %s: %s", levelStr, file, line, target, message)
}