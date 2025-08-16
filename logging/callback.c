// This file contains C code that references the Go callback

#include <stdint.h>

// Forward declaration - this will be provided by CGO's generated code
extern void goLogCallback(void* context, int32_t level, const char* target, const char* message, const char* module_path, const char* file, int32_t line);

// C wrapper that calls the Go callback
void cLogCallback(void* context, int32_t level, const char* target, const char* message, const char* module_path, const char* file, int32_t line) {
    goLogCallback(context, level, target, message, module_path, file, line);
}