package tests

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEcdhEs(t *testing.T) {
	t.Run("Direct Encryption/Decryption", func(t *testing.T) {
		ecdh := &crypto.EcdhEs{}
		
		// Generate recipient key
		recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		// Test data
		message := []byte("secret message for ECDH-ES")
		apu := []byte("producer")
		apv := []byte("consumer")
		nonce := []byte("unique nonce for ECDH-ES")[:24]
		
		// Encrypt
		encrypted, err := ecdh.EncryptDirect(recipientKey, message, apu, apv, nonce)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
		require.NotEmpty(t, encrypted.EphemeralPublicKey)
		require.NotEmpty(t, encrypted.Ciphertext)
		require.NotEmpty(t, encrypted.Tag)
		
		// Decrypt
		decrypted, err := ecdh.DecryptDirect(
			recipientKey,
			encrypted.EphemeralPublicKey,
			encrypted.Ciphertext,
			encrypted.Tag,
			apu,
			apv,
			encrypted.Nonce,
		)
		require.NoError(t, err)
		assert.Equal(t, message, decrypted)
	})
	
	t.Run("Key Derivation", func(t *testing.T) {
		ecdh := &crypto.EcdhEs{}
		
		// Generate keys
		ephemeralKey, err := crypto.Generate(enums.KeyAlgX25519, true)
		require.NoError(t, err)
		
		recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		apu := []byte("producer")
		apv := []byte("consumer")
		
		// Derive key for sender
		senderDerived, err := ecdh.DeriveKey(
			enums.KeyAlgChacha20Poly1305,
			ephemeralKey,
			recipientKey,
			apu,
			apv,
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, senderDerived)
		
		// Derive key for recipient
		recipientDerived, err := ecdh.DeriveKey(
			enums.KeyAlgChacha20Poly1305,
			ephemeralKey,
			recipientKey,
			apu,
			apv,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, recipientDerived)
		
		// Both should derive the same shared secret
		senderSecret, err := senderDerived.GetSecretBytes()
		require.NoError(t, err)
		
		recipientSecret, err := recipientDerived.GetSecretBytes()
		require.NoError(t, err)
		
		assert.Equal(t, senderSecret, recipientSecret)
	})
	
	t.Run("JSON Serialization", func(t *testing.T) {
		ecdh := &crypto.EcdhEs{}
		
		recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		message := []byte("test message")
		nonce := []byte("24-byte nonce for test  ")[:24]
		
		// Encrypt
		encrypted, err := ecdh.EncryptDirect(recipientKey, message, nil, nil, nonce)
		require.NoError(t, err)
		
		// Serialize to JSON
		jsonData, err := encrypted.ToJSON()
		require.NoError(t, err)
		require.NotEmpty(t, jsonData)
		
		// Deserialize from JSON
		deserialized, err := crypto.EcdhEsEncryptedFromJSON(jsonData)
		require.NoError(t, err)
		
		assert.Equal(t, encrypted.EphemeralPublicKey, deserialized.EphemeralPublicKey)
		assert.Equal(t, encrypted.Ciphertext, deserialized.Ciphertext)
		assert.Equal(t, encrypted.Tag, deserialized.Tag)
		assert.Equal(t, encrypted.Nonce, deserialized.Nonce)
	})
}

func TestEcdh1PU(t *testing.T) {
	t.Run("Key Derivation", func(t *testing.T) {
		ecdh := &crypto.Ecdh1PU{}
		
		// Generate keys
		ephemeralKey, err := crypto.Generate(enums.KeyAlgX25519, true)
		require.NoError(t, err)
		
		senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		apu := []byte("producer")
		apv := []byte("consumer")
		ccTag := []byte("tag")
		
		// Derive key for sender
		senderDerived, err := ecdh.DeriveKey(
			enums.KeyAlgChacha20Poly1305,
			ephemeralKey,
			senderKey,
			recipientKey,
			apu,
			apv,
			ccTag,
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, senderDerived)
		
		// Derive key for recipient
		recipientDerived, err := ecdh.DeriveKey(
			enums.KeyAlgChacha20Poly1305,
			ephemeralKey,
			senderKey,
			recipientKey,
			apu,
			apv,
			ccTag,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, recipientDerived)
		
		// Both should derive the same shared secret
		senderSecret, err := senderDerived.GetSecretBytes()
		require.NoError(t, err)
		
		recipientSecret, err := recipientDerived.GetSecretBytes()
		require.NoError(t, err)
		
		assert.Equal(t, senderSecret, recipientSecret)
	})
}

func TestFromKeyExchange(t *testing.T) {
	t.Run("Basic Key Exchange", func(t *testing.T) {
		// Generate static keys
		aliceKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		bobKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		// Alice derives shared key
		aliceShared, err := crypto.FromKeyExchange(
			enums.KeyAlgChacha20Poly1305,
			aliceKey,
			bobKey,
			nil,
			nil,
		)
		require.NoError(t, err)
		require.NotNil(t, aliceShared)
		
		// Bob derives shared key
		bobShared, err := crypto.FromKeyExchange(
			enums.KeyAlgChacha20Poly1305,
			bobKey,
			aliceKey,
			nil,
			nil,
		)
		require.NoError(t, err)
		require.NotNil(t, bobShared)
		
		// Both should have the same shared secret
		aliceSecret, err := aliceShared.GetSecretBytes()
		require.NoError(t, err)
		
		bobSecret, err := bobShared.GetSecretBytes()
		require.NoError(t, err)
		
		assert.Equal(t, aliceSecret, bobSecret)
	})
	
	t.Run("With APU/APV", func(t *testing.T) {
		// Generate keys
		senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		apu := []byte("Alice")
		apv := []byte("Bob")
		
		// Derive with APU/APV
		derived, err := crypto.FromKeyExchange(
			enums.KeyAlgChacha20Poly1305,
			senderKey,
			recipientKey,
			apu,
			apv,
		)
		require.NoError(t, err)
		require.NotNil(t, derived)
		
		// Different APU/APV should give different key
		derivedDifferent, err := crypto.FromKeyExchange(
			enums.KeyAlgChacha20Poly1305,
			senderKey,
			recipientKey,
			[]byte("Different"),
			[]byte("Values"),
		)
		require.NoError(t, err)
		
		secret1, _ := derived.GetSecretBytes()
		secret2, _ := derivedDifferent.GetSecretBytes()
		
		assert.NotEqual(t, secret1, secret2)
	})
}

func TestEcdhWithTestVectors(t *testing.T) {
	// Test vectors from IETF drafts or specifications would go here
	// For now, we test with known values
	
	t.Run("ECDH-ES Test Vector", func(t *testing.T) {
		// This would use actual test vectors from specifications
		// Example structure:
		seed := []byte("testseed000000000000000000000001")
		
		ephemeralKey, err := crypto.FromSeed(enums.KeyAlgX25519, seed)
		require.NoError(t, err)
		
		// Verify the ephemeral key produces expected public key
		ephPub, err := ephemeralKey.GetPublicBytes()
		require.NoError(t, err)
		
		// Expected from the seed (this is an example, real test vectors would be from specs)
		expectedPub := "0506eeaa9eb0277e5b77ba4b0861d86b67c00173af5e31c6b74c60e996beb278"
		assert.Equal(t, expectedPub, hex.EncodeToString(ephPub))
	})
}