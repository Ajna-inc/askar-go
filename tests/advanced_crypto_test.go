package tests

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyWrapping(t *testing.T) {
	t.Run("WrapAndUnwrapKey", func(t *testing.T) {
		// Create wrapping key (KEK - Key Encryption Key)
		kek, err := crypto.Generate(enums.KeyAlgAES256KW, false)
		require.NoError(t, err)
		
		// Create key to be wrapped
		keyToWrap, err := crypto.Generate(enums.KeyAlgAES256GCM, false)
		require.NoError(t, err)
		
		// Get original key bytes for comparison
		originalBytes, err := keyToWrap.GetSecretBytes()
		require.NoError(t, err)
		
		// Wrap the key
		wrapped, err := kek.WrapKey(keyToWrap, nil)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		require.NotEmpty(t, wrapped.Data)
		
		// Unwrap the key
		unwrapped, err := kek.UnwrapKey(
			enums.KeyAlgAES256GCM,
			wrapped.GetCiphertext(),
			wrapped.GetNonce(),
			wrapped.GetTag(),
		)
		require.NoError(t, err)
		require.NotNil(t, unwrapped)
		
		// Verify unwrapped key matches original
		unwrappedBytes, err := unwrapped.GetSecretBytes()
		require.NoError(t, err)
		assert.Equal(t, originalBytes, unwrappedBytes)
		
		// Test that unwrapped key works
		testMessage := []byte("test message")
		nonce := []byte("unique nonce for test   ")[:12] // AES-GCM needs 12-byte nonce
		
		// Encrypt with original
		encrypted1, err := keyToWrap.AEADEncrypt(testMessage, nonce, nil)
		require.NoError(t, err)
		
		// Decrypt with unwrapped
		decrypted, err := unwrapped.AEADDecrypt(
			encrypted1.GetCiphertext(),
			nonce,
			encrypted1.GetTag(),
			nil,
		)
		require.NoError(t, err)
		assert.Equal(t, testMessage, decrypted)
	})
	
	t.Run("WrapWithNonce", func(t *testing.T) {
		kek, err := crypto.Generate(enums.KeyAlgAES256KW, false)
		require.NoError(t, err)
		
		keyToWrap, err := crypto.Generate(enums.KeyAlgAES128GCM, false)
		require.NoError(t, err)
		
		// Use specific nonce
		nonce := []byte("specific nonce")
		
		wrapped, err := kek.WrapKey(keyToWrap, nonce)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		
		// Unwrap
		unwrapped, err := kek.UnwrapKey(
			enums.KeyAlgAES128GCM,
			wrapped.GetCiphertext(),
			nonce,
			wrapped.GetTag(),
		)
		require.NoError(t, err)
		require.NotNil(t, unwrapped)
	})
}

func TestAEADParameters(t *testing.T) {
	t.Run("GetAEADParams", func(t *testing.T) {
		testCases := []struct {
			name               string
			algorithm          enums.KeyAlgorithm
			expectedNonceLen   int32
			expectedTagLen     int32
		}{
			{"AES128GCM", enums.KeyAlgAES128GCM, 12, 16},
			{"AES256GCM", enums.KeyAlgAES256GCM, 12, 16},
			{"ChaCha20Poly1305", enums.KeyAlgChacha20Poly1305, 12, 16},
			{"XChaCha20Poly1305", enums.KeyAlgChacha20XPoly1305, 24, 16},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				key, err := crypto.Generate(tc.algorithm, false)
				require.NoError(t, err)
				
				params, err := key.AEADGetParams()
				require.NoError(t, err)
				require.NotNil(t, params)
				
				assert.Equal(t, tc.expectedNonceLen, params.NonceLength)
				assert.Equal(t, tc.expectedTagLen, params.TagLength)
			})
		}
	})
	
	t.Run("GetAEADPadding", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgAES256GCM, false)
		require.NoError(t, err)
		
		// Test different message lengths
		testCases := []int64{0, 1, 16, 17, 32, 100, 1024}
		
		for _, msgLen := range testCases {
			padding, err := key.AEADGetPadding(msgLen)
			require.NoError(t, err)
			
			// Padding should be non-negative
			assert.GreaterOrEqual(t, padding, int32(0))
			
			// Total length after padding should be aligned
			totalLen := msgLen + int64(padding)
			// Check if it's aligned to block size (typically 16 for AES)
			if msgLen > 0 {
				assert.Equal(t, int64(0), totalLen%16)
			}
		}
	})
	
	t.Run("AEADRandomNonce", func(t *testing.T) {
		testCases := []struct {
			name         string
			algorithm    enums.KeyAlgorithm
			expectedLen  int
		}{
			{"AES128GCM", enums.KeyAlgAES128GCM, 12},
			{"AES256GCM", enums.KeyAlgAES256GCM, 12},
			{"ChaCha20Poly1305", enums.KeyAlgChacha20Poly1305, 12},
			{"XChaCha20Poly1305", enums.KeyAlgChacha20XPoly1305, 24},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				key, err := crypto.Generate(tc.algorithm, false)
				require.NoError(t, err)
				
				// Generate random nonce
				nonce1, err := key.AEADRandomNonce()
				require.NoError(t, err)
				assert.Len(t, nonce1, tc.expectedLen)
				
				// Generate another nonce
				nonce2, err := key.AEADRandomNonce()
				require.NoError(t, err)
				assert.Len(t, nonce2, tc.expectedLen)
				
				// Should be different (with very high probability)
				assert.False(t, bytes.Equal(nonce1, nonce2))
				
				// Test that the nonce works with encryption
				message := []byte("test message")
				encrypted, err := key.AEADEncrypt(message, nonce1, nil)
				require.NoError(t, err)
				
				decrypted, err := key.AEADDecrypt(
					encrypted.GetCiphertext(),
					nonce1,
					encrypted.GetTag(),
					nil,
				)
				require.NoError(t, err)
				assert.Equal(t, message, decrypted)
			})
		}
	})
}

func TestStoreRawKeyGeneration(t *testing.T) {
	t.Run("GenerateRawKey", func(t *testing.T) {
		// Generate without seed
		key1, err := store.GenerateRawKey(nil)
		require.NoError(t, err)
		require.NotEmpty(t, key1)
		
		// Generate another without seed - should be different
		key2, err := store.GenerateRawKey(nil)
		require.NoError(t, err)
		require.NotEmpty(t, key2)
		assert.NotEqual(t, key1, key2)
		
		// Generate with seed - should be deterministic
		seed := []byte("deterministic seed for testing")
		key3, err := store.GenerateRawKey(seed)
		require.NoError(t, err)
		require.NotEmpty(t, key3)
		
		// Same seed should give same key
		key4, err := store.GenerateRawKey(seed)
		require.NoError(t, err)
		assert.Equal(t, key3, key4)
		
		// Different seed should give different key
		differentSeed := []byte("different seed")
		key5, err := store.GenerateRawKey(differentSeed)
		require.NoError(t, err)
		assert.NotEqual(t, key3, key5)
	})
	
	t.Run("UseRawKeyForStore", func(t *testing.T) {
		// Generate a raw key
		rawKey, err := store.GenerateRawKey(nil)
		require.NoError(t, err)
		
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		// Use raw key to provision store
		s, err := store.Provision(uri, enums.KdfRaw, rawKey, "", false)
		require.NoError(t, err)
		require.NotNil(t, s)
		s.Close()
		
		// Should be able to open with same raw key
		s, err = store.Open(uri, enums.KdfRaw, rawKey, "")
		require.NoError(t, err)
		require.NotNil(t, s)
		s.Close()
		
		// Should fail with different key
		differentKey, err := store.GenerateRawKey(nil)
		require.NoError(t, err)
		
		_, err = store.Open(uri, enums.KdfRaw, differentKey, "")
		assert.Error(t, err)
	})
}

func TestCryptoBoxRandomNonce(t *testing.T) {
	t.Run("RandomNonce", func(t *testing.T) {
		// Generate random nonce for CryptoBox
		nonce1, err := crypto.CryptoBoxRandomNonce()
		require.NoError(t, err)
		assert.Len(t, nonce1, 24) // NaCl box nonce is 24 bytes
		
		// Generate another - should be different
		nonce2, err := crypto.CryptoBoxRandomNonce()
		require.NoError(t, err)
		assert.Len(t, nonce2, 24)
		assert.False(t, bytes.Equal(nonce1, nonce2))
		
		// Test that nonce works with CryptoBox
		senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
		require.NoError(t, err)
		
		message := []byte("test message")
		
		// Encrypt with random nonce
		encrypted, err := crypto.CryptoBox(recipientKey, senderKey, message, nonce1)
		require.NoError(t, err)
		
		// Decrypt
		decrypted, err := crypto.CryptoBoxOpen(recipientKey, senderKey, encrypted, nonce1)
		require.NoError(t, err)
		assert.Equal(t, message, decrypted)
	})
}