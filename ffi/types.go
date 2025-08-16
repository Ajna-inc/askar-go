package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../native
#include <stdint.h>
#include <stdlib.h>
#include "libaries_askar.h"

// Types are already defined in libaries_askar.h
*/
import "C"
import (
	"unsafe"
)

type ByteBuffer struct {
	Data []byte
}

func (b *ByteBuffer) toCByteBuffer() C.ByteBuffer {
	if len(b.Data) == 0 {
		return C.ByteBuffer{len: 0, data: nil}
	}
	return C.ByteBuffer{
		len:  C.int64_t(len(b.Data)),
		data: (*C.uint8_t)(unsafe.Pointer(&b.Data[0])),
	}
}

func fromCByteBuffer(cb C.ByteBuffer) *ByteBuffer {
	if cb.data == nil || cb.len == 0 {
		return &ByteBuffer{Data: []byte{}}
	}
	data := C.GoBytes(unsafe.Pointer(cb.data), C.int(cb.len))
	return &ByteBuffer{Data: data}
}

func (b *ByteBuffer) toCSecretBuffer() C.struct_SecretBuffer {
	if len(b.Data) == 0 {
		return C.struct_SecretBuffer{len: 0, data: nil}
	}
	return C.struct_SecretBuffer{
		len:  C.int64_t(len(b.Data)),
		data: (*C.uint8_t)(unsafe.Pointer(&b.Data[0])),
	}
}

func fromCSecretBuffer(cb C.struct_SecretBuffer) *ByteBuffer {
	if cb.data == nil || cb.len == 0 {
		return &ByteBuffer{Data: []byte{}}
	}
	data := C.GoBytes(unsafe.Pointer(cb.data), C.int(cb.len))
	return &ByteBuffer{Data: data}
}

type EncryptedBuffer struct {
	Data     []byte
	TagPos   int64
	NoncePos int64
}

func (e *EncryptedBuffer) toCEncryptedBuffer() C.EncryptedBuffer {
	bb := ByteBuffer{Data: e.Data}
	return C.EncryptedBuffer{
		buffer:    bb.toCSecretBuffer(),
		tag_pos:   C.int64_t(e.TagPos),
		nonce_pos: C.int64_t(e.NoncePos),
	}
}

func fromCEncryptedBuffer(ce C.EncryptedBuffer) *EncryptedBuffer {
	bb := fromCSecretBuffer(ce.buffer)
	return &EncryptedBuffer{
		Data:     bb.Data,
		TagPos:   int64(ce.tag_pos),
		NoncePos: int64(ce.nonce_pos),
	}
}

type AeadParams struct {
	NonceLength int32
	TagLength   int32
}

func (a *AeadParams) toCAeadParams() C.AeadParams {
	return C.AeadParams{
		nonce_length: C.int32_t(a.NonceLength),
		tag_length:   C.int32_t(a.TagLength),
	}
}

func fromCAeadParams(ca C.AeadParams) *AeadParams {
	return &AeadParams{
		NonceLength: int32(ca.nonce_length),
		TagLength:   int32(ca.tag_length),
	}
}

func cStringOrNil(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func freeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func goString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}