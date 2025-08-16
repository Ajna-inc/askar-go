package tests

import (
	"encoding/json"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwkOperations(t *testing.T) {
	t.Run("GetJwkPublic", func(t *testing.T) {
		// Test with different key types
		testCases := []struct {
			name      string
			algorithm enums.KeyAlgorithm
		}{
			{"Ed25519", enums.KeyAlgEd25519},
			{"X25519", enums.KeyAlgX25519},
			{"P256", enums.KeyAlgECP256},
			{"P384", enums.KeyAlgECP384},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				key, err := crypto.Generate(tc.algorithm, false)
				require.NoError(t, err)
				
				jwkStr, err := key.GetJwkPublic()
				require.NoError(t, err)
				require.NotEmpty(t, jwkStr)
				
				// Verify it's valid JSON
				var jwkMap map[string]interface{}
				err = json.Unmarshal([]byte(jwkStr), &jwkMap)
				require.NoError(t, err)
				
				// Should have kty field
				assert.Contains(t, jwkMap, "kty")
				
				// Public JWK should not have private key material
				assert.NotContains(t, jwkMap, "d")
			})
		}
	})
	
	t.Run("GetJwkSecret", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		jwkStr, err := key.GetJwkSecret()
		require.NoError(t, err)
		require.NotEmpty(t, jwkStr)
		
		// Verify it's valid JSON
		var jwkMap map[string]interface{}
		err = json.Unmarshal([]byte(jwkStr), &jwkMap)
		require.NoError(t, err)
		
		// Should have kty field
		assert.Contains(t, jwkMap, "kty")
		
		// Secret JWK should have private key material
		assert.Contains(t, jwkMap, "d")
	})
	
	t.Run("GetJwkThumbprint", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		thumbprint, err := key.GetJwkThumbprint()
		require.NoError(t, err)
		require.NotEmpty(t, thumbprint)
		
		// Thumbprint should be consistent
		thumbprint2, err := key.GetJwkThumbprint()
		require.NoError(t, err)
		assert.Equal(t, thumbprint, thumbprint2)
	})
	
	t.Run("FromJWK", func(t *testing.T) {
		// Generate a key and get its JWK
		originalKey, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		jwkStr, err := originalKey.GetJwkSecret()
		require.NoError(t, err)
		
		// Parse JWK to map
		var jwkMap map[string]interface{}
		err = json.Unmarshal([]byte(jwkStr), &jwkMap)
		require.NoError(t, err)
		
		// Create key from JWK
		newKey, err := crypto.FromJWK(jwkMap)
		require.NoError(t, err)
		require.NotNil(t, newKey)
		
		// Verify keys match
		originalPub, err := originalKey.GetPublicBytes()
		require.NoError(t, err)
		
		newPub, err := newKey.GetPublicBytes()
		require.NoError(t, err)
		
		assert.Equal(t, originalPub, newPub)
	})
	
	t.Run("JwkClass", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		// Create JWK from key
		jwk, err := crypto.JwkFromKey(key, false)
		require.NoError(t, err)
		require.NotNil(t, jwk)
		
		// Check standard fields
		assert.NotEmpty(t, jwk.Kty)
		assert.NotEmpty(t, jwk.Crv)
		assert.NotEmpty(t, jwk.X)
		assert.Empty(t, jwk.D) // Public only
		
		// Convert to JSON
		jsonData, err := jwk.ToJSON()
		require.NoError(t, err)
		require.NotEmpty(t, jsonData)
		
		// Parse back
		var parsed map[string]interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)
		assert.Contains(t, parsed, "kty")
		assert.Contains(t, parsed, "crv")
		assert.Contains(t, parsed, "x")
		
		// Convert back to key
		reconstructedKey, err := jwk.ToKey()
		require.NoError(t, err)
		require.NotNil(t, reconstructedKey)
		
		// Verify public keys match
		originalPub, _ := key.GetPublicBytes()
		reconstructedPub, _ := reconstructedKey.GetPublicBytes()
		assert.Equal(t, originalPub, reconstructedPub)
	})
	
	t.Run("JwkWithPrivateKey", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		// Create JWK with private key
		jwk, err := crypto.JwkFromKey(key, true)
		require.NoError(t, err)
		require.NotNil(t, jwk)
		
		// Should have private key material
		assert.NotEmpty(t, jwk.D)
		
		// Convert back to key
		reconstructedKey, err := jwk.ToKey()
		require.NoError(t, err)
		
		// Should be able to get secret bytes
		secret, err := reconstructedKey.GetSecretBytes()
		require.NoError(t, err)
		assert.NotEmpty(t, secret)
		
		// Sign with reconstructed key
		message := []byte("test message")
		signature, err := reconstructedKey.SignMessage(message)
		require.NoError(t, err)
		
		// Verify with original key
		verified, err := key.VerifySignature(message, signature)
		require.NoError(t, err)
		assert.True(t, verified)
	})
	
	t.Run("JwkThumbprint", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		jwk, err := crypto.JwkFromKey(key, false)
		require.NoError(t, err)
		
		// Get thumbprint from JWK
		thumbprint, err := jwk.GetThumbprint()
		require.NoError(t, err)
		require.NotEmpty(t, thumbprint)
		
		// Should match key's thumbprint
		keyThumbprint, err := key.GetJwkThumbprint()
		require.NoError(t, err)
		assert.Equal(t, keyThumbprint, thumbprint)
	})
	
	t.Run("DifferentAlgorithms", func(t *testing.T) {
		algorithms := []enums.KeyAlgorithm{
			enums.KeyAlgEd25519,
			enums.KeyAlgX25519,
			enums.KeyAlgECP256,
			enums.KeyAlgECP384,
			enums.KeyAlgAES128GCM,
			enums.KeyAlgAES256GCM,
		}
		
		for _, alg := range algorithms {
			t.Run(string(alg), func(t *testing.T) {
				key, err := crypto.Generate(alg, false)
				require.NoError(t, err)
				
				// Get JWK
				jwkStr, err := key.GetJwkPublic()
				if err != nil {
					// Some algorithms might not support JWK
					t.Skip("Algorithm doesn't support JWK")
				}
				
				require.NotEmpty(t, jwkStr)
				
				// Parse and validate
				var jwkMap map[string]interface{}
				err = json.Unmarshal([]byte(jwkStr), &jwkMap)
				require.NoError(t, err)
				assert.Contains(t, jwkMap, "kty")
			})
		}
	})
}