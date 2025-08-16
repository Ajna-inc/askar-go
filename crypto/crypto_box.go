package crypto

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
	"unsafe"

	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
)

// CryptoBox encrypts a message using crypto_box (NaCl box)
// @param recipientKey The recipient's public key
// @param senderKey The sender's secret key
// @param message The plaintext message to encrypt
// @param nonce The nonce for encryption
// @return The encrypted ciphertext and error if any
func CryptoBox(recipientKey, senderKey *Key, message, nonce []byte) ([]byte, error) {
	recipKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(recipientKey.handle.Ptr())}
	senderKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(senderKey.handle.Ptr())}
	
	var msgBuffer, nonceBuffer C.ByteBuffer
	if len(message) > 0 {
		msgBuffer.data = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		msgBuffer.len = C.int64_t(len(message))
	}
	if len(nonce) > 0 {
		nonceBuffer.data = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
		nonceBuffer.len = C.int64_t(len(nonce))
	}
	
	var buffer C.SecretBuffer
	code := C.askar_key_crypto_box(
		recipKeyHandle,
		senderKeyHandle,
		msgBuffer,
		nonceBuffer,
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if buffer.data == nil {
		return []byte{}, nil
	}
	
	data := C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
	C.askar_buffer_free(buffer)
	
	return data, nil
}

// CryptoBoxOpen decrypts a message using crypto_box_open (NaCl box)
// @param recipientKey The recipient's secret key
// @param senderKey The sender's public key
// @param ciphertext The encrypted message
// @param nonce The nonce used for encryption
// @return The decrypted plaintext and error if any
func CryptoBoxOpen(recipientKey, senderKey *Key, ciphertext, nonce []byte) ([]byte, error) {
	recipKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(recipientKey.handle.Ptr())}
	senderKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(senderKey.handle.Ptr())}
	
	var cipherBuffer, nonceBuffer C.ByteBuffer
	if len(ciphertext) > 0 {
		cipherBuffer.data = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
		cipherBuffer.len = C.int64_t(len(ciphertext))
	}
	if len(nonce) > 0 {
		nonceBuffer.data = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
		nonceBuffer.len = C.int64_t(len(nonce))
	}
	
	var buffer C.SecretBuffer
	code := C.askar_key_crypto_box_open(
		recipKeyHandle,
		senderKeyHandle,
		cipherBuffer,
		nonceBuffer,
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if buffer.data == nil {
		return []byte{}, nil
	}
	
	data := C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
	C.askar_buffer_free(buffer)
	
	return data, nil
}

// CryptoBoxRandomNonce generates a random nonce for CryptoBox
// @return The generated nonce bytes and error if any
func CryptoBoxRandomNonce() ([]byte, error) {
	var buffer C.SecretBuffer
	code := C.askar_key_crypto_box_random_nonce(&buffer)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if buffer.data == nil {
		return []byte{}, nil
	}
	
	data := C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
	C.askar_buffer_free(buffer)
	
	return data, nil
}

// CryptoBoxSeal encrypts a message using crypto_box_seal (anonymous encryption)
// @param recipientKey The recipient's public key
// @param message The plaintext message to encrypt
// @return The sealed ciphertext and error if any
func CryptoBoxSeal(recipientKey *Key, message []byte) ([]byte, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(recipientKey.handle.Ptr())}
	
	var msgBuffer C.ByteBuffer
	if len(message) > 0 {
		msgBuffer.data = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		msgBuffer.len = C.int64_t(len(message))
	}
	
	var buffer C.SecretBuffer
	code := C.askar_key_crypto_box_seal(
		keyHandle,
		msgBuffer,
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if buffer.data == nil {
		return []byte{}, nil
	}
	
	data := C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
	C.askar_buffer_free(buffer)
	
	return data, nil
}

// CryptoBoxSealOpen decrypts a message using crypto_box_seal_open (anonymous decryption)
// @param recipientKey The recipient's keypair (public and secret)
// @param ciphertext The sealed encrypted message
// @return The decrypted plaintext and error if any
func CryptoBoxSealOpen(recipientKey *Key, ciphertext []byte) ([]byte, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(recipientKey.handle.Ptr())}
	
	var cipherBuffer C.ByteBuffer
	if len(ciphertext) > 0 {
		cipherBuffer.data = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
		cipherBuffer.len = C.int64_t(len(ciphertext))
	}
	
	var buffer C.SecretBuffer
	code := C.askar_key_crypto_box_seal_open(
		keyHandle,
		cipherBuffer,
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if buffer.data == nil {
		return []byte{}, nil
	}
	
	data := C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
	C.askar_buffer_free(buffer)
	
	return data, nil
}