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
	"encoding/json"
	"runtime"
	"unsafe"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/handles"
)

type Key struct {
	handle *handles.LocalKeyHandle
}

// NewKeyFromHandle creates a new Key from an existing handle
// @param handle The LocalKeyHandle to wrap
// @return A new Key instance with the provided handle
func NewKeyFromHandle(handle *handles.LocalKeyHandle) *Key {
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	return key
}

// Generate creates a new random key
// @param alg The key algorithm to use
// @param ephemeral Whether the key is ephemeral (not persisted)
// @return The generated Key and error if any
func Generate(alg enums.KeyAlgorithm, ephemeral bool) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	var eph C.int8_t
	if ephemeral {
		eph = 1
	}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_generate(
		algStr,
		nil, // Key backend parameter (reserved for future use)
		eph,
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	// Create handle from the C pointer
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// FromSeed creates a key from a seed
// @param alg The key algorithm to use
// @param seed The seed bytes for key generation
// @param method Optional key derivation method
// @return The derived Key and error if any
func FromSeed(alg enums.KeyAlgorithm, seed []byte, method ...enums.KeyMethod) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	var methodStr *C.char
	if len(method) > 0 {
		methodStr = C.CString(string(method[0]))
		defer C.free(unsafe.Pointer(methodStr))
	}
	
	// Create ByteBuffer from seed
	var seedBuffer C.ByteBuffer
	if len(seed) > 0 {
		seedBuffer.data = (*C.uint8_t)(unsafe.Pointer(&seed[0]))
		seedBuffer.len = C.int64_t(len(seed))
	}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_from_seed(
		algStr,
		seedBuffer,
		methodStr,
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// FromSecretBytes creates a key from secret bytes
// @param alg The key algorithm to use
// @param secret The secret key bytes
// @return The created Key and error if any
func FromSecretBytes(alg enums.KeyAlgorithm, secret []byte) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	// Create ByteBuffer from secret
	var secretBuffer C.ByteBuffer
	if len(secret) > 0 {
		secretBuffer.data = (*C.uint8_t)(unsafe.Pointer(&secret[0]))
		secretBuffer.len = C.int64_t(len(secret))
	}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_from_secret_bytes(
		algStr,
		secretBuffer,
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// FromPublicBytes creates a key from public bytes
// @param alg The key algorithm to use
// @param public The public key bytes
// @return The created Key and error if any
func FromPublicBytes(alg enums.KeyAlgorithm, public []byte) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	// Create ByteBuffer from public
	var publicBuffer C.ByteBuffer
	if len(public) > 0 {
		publicBuffer.data = (*C.uint8_t)(unsafe.Pointer(&public[0]))
		publicBuffer.len = C.int64_t(len(public))
	}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_from_public_bytes(
		algStr,
		publicBuffer,
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// FromJWK creates a key from a JWK
// @param jwk The JWK object (map or struct)
// @return The created Key and error if any
func FromJWK(jwk interface{}) (*Key, error) {
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	
	// Create ByteBuffer from JWK
	var jwkBuffer C.ByteBuffer
	jwkBuffer.data = (*C.uint8_t)(unsafe.Pointer(&jwkBytes[0]))
	jwkBuffer.len = C.int64_t(len(jwkBytes))
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_from_jwk(
		jwkBuffer,
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// GetAlgorithm returns the algorithm of the key
// @return The key algorithm and error if any
func (k *Key) GetAlgorithm() (enums.KeyAlgorithm, error) {
	// Create the LocalKeyHandle struct for C
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var algStr *C.char
	code := C.askar_key_get_algorithm(keyHandle, &algStr)
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	return enums.KeyAlgorithm(C.GoString(algStr)), nil
}

// Convert converts a key to a different algorithm
// @param alg The target algorithm to convert to
// @return The converted Key and error if any
func (k *Key) Convert(alg enums.KeyAlgorithm) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var convertedHandle C.LocalKeyHandle
	code := C.askar_key_convert(keyHandle, algStr, &convertedHandle)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(convertedHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// GetJwkPublic returns the public JWK representation of the key
// @param alg Optional algorithm hint for JWK generation
// @return The public JWK as JSON string and error if any
func (k *Key) GetJwkPublic(alg ...string) (string, error) {
	var algStr *C.char
	if len(alg) > 0 {
		algStr = C.CString(alg[0])
		defer C.free(unsafe.Pointer(algStr))
	}
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var jwk *C.char
	code := C.askar_key_get_jwk_public(keyHandle, algStr, &jwk)
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	return C.GoString(jwk), nil
}

// GetJwkSecret returns the secret JWK representation of the key
// @return The secret JWK as JSON string and error if any
func (k *Key) GetJwkSecret() (string, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.SecretBuffer
	code := C.askar_key_get_jwk_secret(keyHandle, &buffer)
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	if buffer.data == nil {
		return "", nil
	}
	
	jwk := C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
	C.askar_buffer_free(buffer)
	
	return string(jwk), nil
}

// GetJwkThumbprint returns the JWK thumbprint of the key
// @param alg Optional hash algorithm for thumbprint
// @return The JWK thumbprint string and error if any
func (k *Key) GetJwkThumbprint(alg ...string) (string, error) {
	var algStr *C.char
	if len(alg) > 0 {
		algStr = C.CString(alg[0])
		defer C.free(unsafe.Pointer(algStr))
	}
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var thumbprint *C.char
	code := C.askar_key_get_jwk_thumbprint(keyHandle, algStr, &thumbprint)
	if code != 0 {
		return "", errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	return C.GoString(thumbprint), nil
}

// GetPublicBytes returns the public bytes of the key
// @return The public key bytes and error if any
func (k *Key) GetPublicBytes() ([]byte, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.SecretBuffer
	code := C.askar_key_get_public_bytes(keyHandle, &buffer)
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

// GetSecretBytes returns the secret bytes of the key
// @return The secret key bytes and error if any
func (k *Key) GetSecretBytes() ([]byte, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.SecretBuffer
	code := C.askar_key_get_secret_bytes(keyHandle, &buffer)
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

// SignMessage signs a message with the key
// @param message The message bytes to sign
// @param sigType Optional signature algorithm to use
// @return The signature bytes and error if any
func (k *Key) SignMessage(message []byte, sigType ...enums.SignatureAlgorithm) ([]byte, error) {
	var sigTypeStr *C.char
	if len(sigType) > 0 {
		sigTypeStr = C.CString(string(sigType[0]))
		defer C.free(unsafe.Pointer(sigTypeStr))
	}
	
	// Create ByteBuffer from message
	var msgBuffer C.ByteBuffer
	if len(message) > 0 {
		msgBuffer.data = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		msgBuffer.len = C.int64_t(len(message))
	}
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.SecretBuffer
	code := C.askar_key_sign_message(
		keyHandle,
		msgBuffer,
		sigTypeStr,
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

// VerifySignature verifies a signature with the key
// @param message The original message bytes
// @param signature The signature bytes to verify
// @param sigType Optional signature algorithm to use
// @return True if signature is valid, false otherwise, and error if any
func (k *Key) VerifySignature(message, signature []byte, sigType ...enums.SignatureAlgorithm) (bool, error) {
	var sigTypeStr *C.char
	if len(sigType) > 0 {
		sigTypeStr = C.CString(string(sigType[0]))
		defer C.free(unsafe.Pointer(sigTypeStr))
	}
	
	// Create ByteBuffers
	var msgBuffer, sigBuffer C.ByteBuffer
	if len(message) > 0 {
		msgBuffer.data = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		msgBuffer.len = C.int64_t(len(message))
	}
	if len(signature) > 0 {
		sigBuffer.data = (*C.uint8_t)(unsafe.Pointer(&signature[0]))
		sigBuffer.len = C.int64_t(len(signature))
	}
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var verified C.int8_t
	code := C.askar_key_verify_signature(
		keyHandle,
		msgBuffer,
		sigBuffer,
		sigTypeStr,
		&verified,
	)
	
	if code != 0 {
		return false, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	return verified != 0, nil
}

// GetHandle returns the underlying handle
// @return The internal LocalKeyHandle
func (k *Key) GetHandle() *handles.LocalKeyHandle {
	return k.handle
}

func (k *Key) cleanup() {
	if k.handle != nil && k.handle.Ptr() != nil {
		keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
		C.askar_key_free(keyHandle)
	}
}

// AeadParams represents AEAD encryption parameters
type AeadParams struct {
	NonceLength int32
	TagLength   int32
}

// EncryptedBuffer represents an encrypted buffer with tag and nonce positions
type EncryptedBuffer struct {
	Data     []byte
	TagPos   int
	NoncePos int
}

// GetCiphertext returns the ciphertext portion
// @return The ciphertext bytes without tag or nonce
func (e *EncryptedBuffer) GetCiphertext() []byte {
	if e.TagPos > 0 {
		return e.Data[:e.TagPos]
	}
	return e.Data
}

// GetTag returns the authentication tag
// @return The authentication tag bytes
func (e *EncryptedBuffer) GetTag() []byte {
	if e.TagPos > 0 && e.NoncePos > e.TagPos {
		return e.Data[e.TagPos:e.NoncePos]
	}
	return nil
}

// GetNonce returns the nonce
// @return The nonce bytes
func (e *EncryptedBuffer) GetNonce() []byte {
	if e.NoncePos > 0 && e.NoncePos < len(e.Data) {
		return e.Data[e.NoncePos:]
	}
	return nil
}

// AEADEncrypt encrypts a message using AEAD
// @param message The plaintext message to encrypt
// @param nonce The nonce for encryption (optional, generated if nil)
// @param aad Additional authenticated data
// @return The encrypted buffer containing ciphertext, tag, and nonce
func (k *Key) AEADEncrypt(message, nonce, aad []byte) (*EncryptedBuffer, error) {
	// Create ByteBuffers
	var msgBuffer, nonceBuffer, aadBuffer C.ByteBuffer
	if len(message) > 0 {
		msgBuffer.data = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		msgBuffer.len = C.int64_t(len(message))
	}
	if len(nonce) > 0 {
		nonceBuffer.data = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
		nonceBuffer.len = C.int64_t(len(nonce))
	}
	if len(aad) > 0 {
		aadBuffer.data = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadBuffer.len = C.int64_t(len(aad))
	}
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.EncryptedBuffer
	code := C.askar_key_aead_encrypt(
		keyHandle,
		msgBuffer,
		nonceBuffer,
		aadBuffer,
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	// Convert C buffer to Go EncryptedBuffer
	result := &EncryptedBuffer{}
	if buffer.buffer.data != nil {
		data := C.GoBytes(unsafe.Pointer(buffer.buffer.data), C.int(buffer.buffer.len))
		result.Data = data
		result.TagPos = int(buffer.tag_pos)
		result.NoncePos = int(buffer.nonce_pos)
		C.askar_buffer_free(buffer.buffer)
	}
	
	return result, nil
}

// AEADDecrypt decrypts a message using AEAD
// @param ciphertext The encrypted message bytes
// @param nonce The nonce used for encryption
// @param tag The authentication tag
// @param aad Additional authenticated data
// @return The decrypted plaintext and error if any
func (k *Key) AEADDecrypt(ciphertext, nonce, tag, aad []byte) ([]byte, error) {
	// Create ByteBuffers
	var cipherBuffer, nonceBuffer, tagBuffer, aadBuffer C.ByteBuffer
	if len(ciphertext) > 0 {
		cipherBuffer.data = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
		cipherBuffer.len = C.int64_t(len(ciphertext))
	}
	if len(nonce) > 0 {
		nonceBuffer.data = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
		nonceBuffer.len = C.int64_t(len(nonce))
	}
	if len(tag) > 0 {
		tagBuffer.data = (*C.uint8_t)(unsafe.Pointer(&tag[0]))
		tagBuffer.len = C.int64_t(len(tag))
	}
	if len(aad) > 0 {
		aadBuffer.data = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadBuffer.len = C.int64_t(len(aad))
	}
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.SecretBuffer
	code := C.askar_key_aead_decrypt(
		keyHandle,
		cipherBuffer,
		nonceBuffer,
		tagBuffer,
		aadBuffer,
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

// AEADParams represents AEAD parameters
type AEADParams struct {
	NonceLength int32
	TagLength   int32
}

// AEADGetParams gets the AEAD parameters for the key
// @return The AEAD parameters (nonce and tag lengths) and error if any
func (k *Key) AEADGetParams() (*AEADParams, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var params C.AeadParams
	code := C.askar_key_aead_get_params(keyHandle, &params)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	return &AEADParams{
		NonceLength: int32(params.nonce_length),
		TagLength:   int32(params.tag_length),
	}, nil
}

// AEADRandomNonce generates a random nonce for AEAD encryption
// @return The generated nonce bytes and error if any
func (k *Key) AEADRandomNonce() ([]byte, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var buffer C.SecretBuffer
	code := C.askar_key_aead_random_nonce(keyHandle, &buffer)
	
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

// FromKeyExchange derives a key from ECDH key exchange
// @param alg The algorithm for the derived key
// @param skHandle The secret key for key exchange
// @param pkHandle The public key for key exchange
// @return The derived Key and error if any
func FromKeyExchange(alg enums.KeyAlgorithm, skHandle, pkHandle *Key) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	skKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(skHandle.handle.Ptr())}
	pkKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(pkHandle.handle.Ptr())}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_from_key_exchange(
		algStr,
		skKeyHandle,
		pkKeyHandle,
		&keyHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(keyHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// WrapKey wraps another key using this key
// @param other The key to wrap
// @param nonce Optional nonce for wrapping
// @return The encrypted buffer containing wrapped key and error if any
func (k *Key) WrapKey(other *Key, nonce []byte) (*EncryptedBuffer, error) {
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	otherHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(other.handle.Ptr())}
	
	var nonceBuffer C.ByteBuffer
	if len(nonce) > 0 {
		nonceBuffer.data = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
		nonceBuffer.len = C.int64_t(len(nonce))
	}
	
	var buffer C.EncryptedBuffer
	code := C.askar_key_wrap_key(
		keyHandle,
		otherHandle,
		nonceBuffer,
		&buffer,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	// Convert C buffer to Go EncryptedBuffer
	result := &EncryptedBuffer{}
	if buffer.buffer.data != nil {
		data := C.GoBytes(unsafe.Pointer(buffer.buffer.data), C.int(buffer.buffer.len))
		result.Data = data
		result.TagPos = int(buffer.tag_pos)
		result.NoncePos = int(buffer.nonce_pos)
		C.askar_buffer_free(buffer.buffer)
	}
	
	return result, nil
}

// UnwrapKey unwraps a key using this key
// @param alg The algorithm of the wrapped key
// @param ciphertext The wrapped key ciphertext
// @param tag The authentication tag
// @param nonce The nonce used for wrapping
// @return The unwrapped Key and error if any
func (k *Key) UnwrapKey(alg enums.KeyAlgorithm, ciphertext, tag, nonce []byte) (*Key, error) {
	algStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(algStr))
	
	keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
	
	var cipherBuffer, tagBuffer, nonceBuffer C.ByteBuffer
	if len(ciphertext) > 0 {
		cipherBuffer.data = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
		cipherBuffer.len = C.int64_t(len(ciphertext))
	}
	if len(tag) > 0 {
		tagBuffer.data = (*C.uint8_t)(unsafe.Pointer(&tag[0]))
		tagBuffer.len = C.int64_t(len(tag))
	}
	if len(nonce) > 0 {
		nonceBuffer.data = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
		nonceBuffer.len = C.int64_t(len(nonce))
	}
	
	var unwrappedHandle C.LocalKeyHandle
	code := C.askar_key_unwrap_key(
		keyHandle,
		algStr,
		cipherBuffer,
		nonceBuffer,
		tagBuffer,
		&unwrappedHandle,
	)
	
	if code != 0 {
		return nil, errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	handle := handles.NewLocalKeyHandle(handles.ArcHandle(unsafe.Pointer(unwrappedHandle._0)))
	key := &Key{handle: handle}
	runtime.SetFinalizer(key, (*Key).cleanup)
	
	return key, nil
}

// Free releases the key resources
// @dev Manually frees the key handle, preventing memory leaks
func (k *Key) Free() {
	if k.handle != nil && k.handle.Ptr() != nil {
		keyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(k.handle.Ptr())}
		C.askar_key_free(keyHandle)
		k.handle = nil
	}
}