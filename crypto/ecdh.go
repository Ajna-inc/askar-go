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
	"runtime"
	"unsafe"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/handles"
)

// EcdhEs provides ECDH-ES key agreement operations
type EcdhEs struct{}

// DeriveKey derives a key using ECDH-ES
// @param alg The algorithm for the derived key
// @param ephemeralKey The ephemeral key
// @param recipientKey The recipient's key
// @param apu Agreement PartyUInfo (optional)
// @param apv Agreement PartyVInfo (optional)
// @param receive Whether deriving for receiving (true) or sending (false)
// @return The derived Key and error if any
func (e *EcdhEs) DeriveKey(alg enums.KeyAlgorithm, ephemeralKey, recipientKey *Key, apu, apv []byte, receive bool) (*Key, error) {
	var skHandle, pkHandle *Key
	if receive {
		skHandle = recipientKey
		pkHandle = ephemeralKey
	} else {
		skHandle = ephemeralKey
		pkHandle = recipientKey
	}
	
	return FromKeyExchange(alg, skHandle, pkHandle)
}

// EncryptDirect performs direct ECDH-ES encryption
// @param recipientKey The recipient's public key
// @param message The plaintext message to encrypt
// @param apu Agreement PartyUInfo (optional)
// @param apv Agreement PartyVInfo (optional)
// @param nonce The encryption nonce
// @return The encrypted result and error if any
func (e *EcdhEs) EncryptDirect(recipientKey *Key, message, apu, apv, nonce []byte) (*EcdhEsEncrypted, error) {
	// Generate ephemeral key
	ephemeralKey, err := Generate(enums.KeyAlgX25519, true)
	if err != nil {
		return nil, err
	}
	
	// Derive encryption key
	encKey, err := e.DeriveKey(enums.KeyAlgChacha20Poly1305, ephemeralKey, recipientKey, apu, apv, false)
	if err != nil {
		return nil, err
	}
	
	// Encrypt message
	encrypted, err := encKey.AEADEncrypt(message, nonce, nil)
	if err != nil {
		return nil, err
	}
	
	// Get ephemeral public key
	ephPubKey, err := ephemeralKey.GetPublicBytes()
	if err != nil {
		return nil, err
	}
	
	return &EcdhEsEncrypted{
		EphemeralPublicKey: ephPubKey,
		Ciphertext:         encrypted.GetCiphertext(),
		Tag:                encrypted.GetTag(),
		Nonce:              nonce,
	}, nil
}

// DecryptDirect performs direct ECDH-ES decryption
// @param recipientKey The recipient's private key
// @param ephemeralPubKeyBytes The ephemeral public key bytes
// @param ciphertext The encrypted message
// @param tag The authentication tag
// @param apu Agreement PartyUInfo (optional)
// @param apv Agreement PartyVInfo (optional)
// @param nonce The encryption nonce
// @return The decrypted plaintext and error if any
func (e *EcdhEs) DecryptDirect(recipientKey *Key, ephemeralPubKeyBytes, ciphertext, tag, apu, apv, nonce []byte) ([]byte, error) {
	// Recreate ephemeral public key
	ephemeralKey, err := FromPublicBytes(enums.KeyAlgX25519, ephemeralPubKeyBytes)
	if err != nil {
		return nil, err
	}
	
	// Derive decryption key
	decKey, err := e.DeriveKey(enums.KeyAlgChacha20Poly1305, ephemeralKey, recipientKey, apu, apv, true)
	if err != nil {
		return nil, err
	}
	
	// Decrypt message
	return decKey.AEADDecrypt(ciphertext, nonce, tag, nil)
}

// EcdhEsEncrypted represents the result of ECDH-ES encryption
type EcdhEsEncrypted struct {
	EphemeralPublicKey []byte
	Ciphertext         []byte
	Tag                []byte
	Nonce              []byte
}

// Ecdh1PU provides ECDH-1PU key agreement operations
type Ecdh1PU struct {
	AlgId []byte
	Apu   []byte
	Apv   []byte
}

// NewEcdh1PU creates a new ECDH-1PU instance
// @param algId Algorithm identifier
// @param apu Agreement PartyUInfo
// @param apv Agreement PartyVInfo
// @return New Ecdh1PU instance
func NewEcdh1PU(algId, apu, apv []byte) *Ecdh1PU {
	return &Ecdh1PU{
		AlgId: algId,
		Apu:   apu,
		Apv:   apv,
	}
}

// DeriveKey derives a key using ECDH-1PU
// @param encryptionAlg The algorithm for the derived key
// @param ephemeralKey The ephemeral key
// @param senderKey The sender's key
// @param recipientKey The recipient's key
// @param ccTag Content commitment tag (optional)
// @param receive Whether deriving for receiving (true) or sending (false)
// @return The derived Key and error if any
func (e *Ecdh1PU) DeriveKey(encryptionAlg enums.KeyAlgorithm, ephemeralKey, senderKey, recipientKey *Key, ccTag []byte, receive bool) (*Key, error) {
	algStr := C.CString(string(encryptionAlg))
	defer C.free(unsafe.Pointer(algStr))
	
	// Convert keys to handles
	ephKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(ephemeralKey.handle.Ptr())}
	senderKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(senderKey.handle.Ptr())}
	recipKeyHandle := C.LocalKeyHandle{_0: (*C.struct_LocalKey)(recipientKey.handle.Ptr())}
	
	// Create ByteBuffers for parameters
	var algIdBuffer, apuBuffer, apvBuffer, ccTagBuffer C.ByteBuffer
	if len(e.AlgId) > 0 {
		algIdBuffer.data = (*C.uint8_t)(unsafe.Pointer(&e.AlgId[0]))
		algIdBuffer.len = C.int64_t(len(e.AlgId))
	}
	if len(e.Apu) > 0 {
		apuBuffer.data = (*C.uint8_t)(unsafe.Pointer(&e.Apu[0]))
		apuBuffer.len = C.int64_t(len(e.Apu))
	}
	if len(e.Apv) > 0 {
		apvBuffer.data = (*C.uint8_t)(unsafe.Pointer(&e.Apv[0]))
		apvBuffer.len = C.int64_t(len(e.Apv))
	}
	if len(ccTag) > 0 {
		ccTagBuffer.data = (*C.uint8_t)(unsafe.Pointer(&ccTag[0]))
		ccTagBuffer.len = C.int64_t(len(ccTag))
	}
	
	var receiveFlag C.int8_t
	if receive {
		receiveFlag = 1
	}
	
	var keyHandle C.LocalKeyHandle
	code := C.askar_key_derive_ecdh_1pu(
		algStr,
		ephKeyHandle,
		senderKeyHandle,
		recipKeyHandle,
		algIdBuffer,
		apuBuffer,
		apvBuffer,
		ccTagBuffer,
		receiveFlag,
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

// EncryptDirect performs direct ECDH-1PU encryption
// @param encryptionAlg The encryption algorithm
// @param ephemeralKey The ephemeral key
// @param senderKey The sender's private key
// @param recipientKey The recipient's public key
// @param message The plaintext message
// @param aad Additional authenticated data
// @param nonce The encryption nonce
// @return The encrypted buffer and error if any
func (e *Ecdh1PU) EncryptDirect(encryptionAlg enums.KeyAlgorithm, ephemeralKey, senderKey, recipientKey *Key, message, aad, nonce []byte) (*EncryptedBuffer, error) {
	// Derive encryption key
	derived, err := e.DeriveKey(encryptionAlg, ephemeralKey, senderKey, recipientKey, nil, false)
	if err != nil {
		return nil, err
	}
	defer derived.Free()
	
	// Encrypt message
	return derived.AEADEncrypt(message, nonce, aad)
}

// DecryptDirect performs direct ECDH-1PU decryption
// @param encryptionAlg The encryption algorithm
// @param ephemeralKey The ephemeral key
// @param senderKey The sender's public key
// @param recipientKey The recipient's private key
// @param ciphertext The encrypted message
// @param nonce The encryption nonce
// @param tag The authentication tag
// @param aad Additional authenticated data
// @return The decrypted plaintext and error if any
func (e *Ecdh1PU) DecryptDirect(encryptionAlg enums.KeyAlgorithm, ephemeralKey, senderKey, recipientKey *Key, ciphertext, nonce, tag, aad []byte) ([]byte, error) {
	// Derive decryption key
	derived, err := e.DeriveKey(encryptionAlg, ephemeralKey, senderKey, recipientKey, nil, true)
	if err != nil {
		return nil, err
	}
	defer derived.Free()
	
	// Decrypt message
	return derived.AEADDecrypt(ciphertext, nonce, tag, aad)
}

// SenderWrapKey wraps a CEK using ECDH-1PU for the sender
// @param keyWrappingAlg The key wrapping algorithm
// @param ephemeralKey The ephemeral key
// @param senderKey The sender's private key
// @param recipientKey The recipient's public key
// @param cek The content encryption key to wrap
// @param ccTag Content commitment tag (optional)
// @return The wrapped key buffer and error if any
func (e *Ecdh1PU) SenderWrapKey(keyWrappingAlg enums.KeyAlgorithm, ephemeralKey, senderKey, recipientKey, cek *Key, ccTag []byte) (*EncryptedBuffer, error) {
	// Derive key wrapping key
	derived, err := e.DeriveKey(keyWrappingAlg, ephemeralKey, senderKey, recipientKey, ccTag, false)
	if err != nil {
		return nil, err
	}
	defer derived.Free()
	
	// Wrap the CEK
	return derived.WrapKey(cek, nil)
}

// ReceiverUnwrapKey unwraps a CEK using ECDH-1PU for the receiver
// @param keyWrappingAlg The key wrapping algorithm
// @param encryptionAlg The encryption algorithm for the unwrapped key
// @param ephemeralKey The ephemeral key
// @param senderKey The sender's public key
// @param recipientKey The recipient's private key
// @param ciphertext The wrapped key ciphertext
// @param nonce The wrapping nonce
// @param tag The authentication tag
// @param ccTag Content commitment tag (optional)
// @return The unwrapped Key and error if any
func (e *Ecdh1PU) ReceiverUnwrapKey(keyWrappingAlg, encryptionAlg enums.KeyAlgorithm, ephemeralKey, senderKey, recipientKey *Key, ciphertext, nonce, tag, ccTag []byte) (*Key, error) {
	// Derive key wrapping key
	derived, err := e.DeriveKey(keyWrappingAlg, ephemeralKey, senderKey, recipientKey, ccTag, true)
	if err != nil {
		return nil, err
	}
	defer derived.Free()
	
	// Unwrap the CEK
	return derived.UnwrapKey(encryptionAlg, ciphertext, tag, nonce)
}