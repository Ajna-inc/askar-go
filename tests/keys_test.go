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

func TestKeyGeneration(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm enums.KeyAlgorithm
	}{
		{"Ed25519", enums.KeyAlgEd25519},
		{"X25519", enums.KeyAlgX25519},
		{"P256", enums.KeyAlgECP256},
		{"P384", enums.KeyAlgECP384},
		{"Secp256k1", enums.KeyAlgECSecp256k1},
		{"AES128GCM", enums.KeyAlgAES128GCM},
		{"AES256GCM", enums.KeyAlgAES256GCM},
		{"ChaCha20Poly1305", enums.KeyAlgChacha20Poly1305},
		{"BLS12381G1", enums.KeyAlgBls12381G1},
		{"BLS12381G2", enums.KeyAlgBls12381G2},
		{"BLS12381G1G2", enums.KeyAlgBls12381G1G2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.Generate(tc.algorithm, false)
			require.NoError(t, err, "Failed to generate %s key", tc.name)
			require.NotNil(t, key)

			alg, err := key.GetAlgorithm()
			require.NoError(t, err)
			assert.Equal(t, tc.algorithm, alg)
		})
	}
}

func TestKeyFromSeed(t *testing.T) {
	seed := []byte("testseed000000000000000000000001")

	testCases := []struct {
		name         string
		algorithm    enums.KeyAlgorithm
		expectedPub  string
		expectedPriv string
	}{
		{
			"Ed25519",
			enums.KeyAlgEd25519,
			"3b0b2158f98ed20b91831ec89ec15513c8ad23b1703eca31098cce869a098301",
			"746573747365656430303030303030303030303030303030303030303030303031",
		},
		{
			"X25519",
			enums.KeyAlgX25519,
			"0506eeaa9eb0277e5b77ba4b0861d86b67c00173af5e31c6b74c60e996beb278",
			"b832e9adfdb20c8191ca64877c4298fe4dc59eb8edb8e18f2982c808a2640f4a",
		},
		{
			"BLS12381G1",
			enums.KeyAlgBls12381G1,
			"9461a637e30f263ab371c006f75afb93c960ab96a3f9e527e1e86a66cfb93897c7de87c2c88c32b89c67a4fb95bbfa02",
			"3b5a6dfceb581de4a6a8b5493591b6e5848ce2af726b972971c93bb093f5b052",
		},
		{
			"BLS12381G2",
			enums.KeyAlgBls12381G2,
			"90e87bc5708e8069e52ea069fe3e4cf09a8054a0f37e659bc4f4b3cdba45f9e8bb7f8aa3b17f8b76c95bb228f3df452b0b19ea965e965b96502c0fea988fd829c088fc0be2acb5e8dc866b7e603a1ba38e37c88c8fc214c1c17ac7025c3c7af",
			"6e5b1ad97cdc955e063c3445e0e6b3e4b387af0d6b97d16e056b7e973b060c19",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.FromSeed(tc.algorithm, seed)
			require.NoError(t, err, "Failed to create %s key from seed", tc.name)
			require.NotNil(t, key)

			pub, err := key.GetPublicBytes()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedPub, hex.EncodeToString(pub))

			if tc.expectedPriv != "" {
				priv, err := key.GetSecretBytes()
				require.NoError(t, err)
				assert.Equal(t, tc.expectedPriv, hex.EncodeToString(priv))
			}
		})
	}
}

func TestBLSKeyGenerationG1G2(t *testing.T) {
	seed := []byte("testseed000000000000000000000001")
	expectedPub := "9461a637e30f263ab371c006f75afb93c960ab96a3f9e527e1e86a66cfb93897c7de87c2c88c32b89c67a4fb95bbfa0290e87bc5708e8069e52ea069fe3e4cf09a8054a0f37e659bc4f4b3cdba45f9e8bb7f8aa3b17f8b76c95bb228f3df452b0b19ea965e965b96502c0fea988fd829c088fc0be2acb5e8dc866b7e603a1ba38e37c88c8fc214c1c17ac7025c3c7af"

	key, err := crypto.FromSeed(enums.KeyAlgBls12381G1G2, seed, enums.KeyMethodBLSKeyGen)
	require.NoError(t, err)
	require.NotNil(t, key)

	pub, err := key.GetPublicBytes()
	require.NoError(t, err)
	assert.Equal(t, expectedPub, hex.EncodeToString(pub))
}

func TestKeySignAndVerify(t *testing.T) {
	message := []byte("test message")

	testCases := []struct {
		name      string
		algorithm enums.KeyAlgorithm
		sigAlg    enums.SignatureAlgorithm
	}{
		{"Ed25519", enums.KeyAlgEd25519, enums.SignatureAlgEdDSA},
		{"P256", enums.KeyAlgECP256, enums.SignatureAlgES256},
		{"P384", enums.KeyAlgECP384, enums.SignatureAlgES384},
		{"Secp256k1", enums.KeyAlgECSecp256k1, enums.SignatureAlgES256K},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.Generate(tc.algorithm, false)
			require.NoError(t, err)

			signature, err := key.SignMessage(message, tc.sigAlg)
			require.NoError(t, err)
			require.NotEmpty(t, signature)

			verified, err := key.VerifySignature(message, signature, tc.sigAlg)
			require.NoError(t, err)
			assert.True(t, verified)

			// Test with wrong message
			wrongMessage := []byte("wrong message")
			verified, err = key.VerifySignature(wrongMessage, signature, tc.sigAlg)
			require.NoError(t, err)
			assert.False(t, verified)
		})
	}
}

func TestKeyAEADEncryptDecrypt(t *testing.T) {
	message := []byte("test message for AEAD")
	aad := []byte("additional authenticated data")

	testCases := []struct {
		name      string
		algorithm enums.KeyAlgorithm
	}{
		{"AES128GCM", enums.KeyAlgAES128GCM},
		{"AES256GCM", enums.KeyAlgAES256GCM},
		{"ChaCha20Poly1305", enums.KeyAlgChacha20Poly1305},
		{"XChaCha20Poly1305", enums.KeyAlgChacha20XPoly1305},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.Generate(tc.algorithm, false)
			require.NoError(t, err)

			// Generate random nonce
			nonce := []byte("unique nonce") // In production, use random nonce

			// Encrypt
			encrypted, err := key.AEADEncrypt(message, nonce, aad)
			require.NoError(t, err)
			require.NotNil(t, encrypted)

			// Get components
			ciphertext := encrypted.GetCiphertext()
			tag := encrypted.GetTag()
			_ = encrypted.GetNonce() // Could be used to verify nonce if needed

			// Decrypt
			decrypted, err := key.AEADDecrypt(ciphertext, nonce, tag, aad)
			require.NoError(t, err)
			assert.Equal(t, message, decrypted)

			// Test with wrong AAD
			wrongAAD := []byte("wrong aad")
			_, err = key.AEADDecrypt(ciphertext, nonce, tag, wrongAAD)
			assert.Error(t, err)
		})
	}
}

func TestKeyConvert(t *testing.T) {
	seed := []byte("testseed000000000000000000000001")

	// Test Ed25519 to X25519 conversion
	edKey, err := crypto.FromSeed(enums.KeyAlgEd25519, seed)
	require.NoError(t, err)

	xKey, err := edKey.Convert(enums.KeyAlgX25519)
	require.NoError(t, err)
	require.NotNil(t, xKey)

	alg, err := xKey.GetAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, enums.KeyAlgX25519, alg)

	// Verify the conversion produced expected public key
	expectedXPub := "0506eeaa9eb0277e5b77ba4b0861d86b67c00173af5e31c6b74c60e996beb278"
	xPub, err := xKey.GetPublicBytes()
	require.NoError(t, err)
	assert.Equal(t, expectedXPub, hex.EncodeToString(xPub))
}

func TestCryptoBox(t *testing.T) {
	message := []byte("secret message")
	nonce := []byte("24-byte nonce for crypto")[:24] // NaCl box requires 24-byte nonce

	// Generate sender and recipient keys
	senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	require.NoError(t, err)

	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	require.NoError(t, err)

	// Encrypt
	ciphertext, err := crypto.CryptoBox(recipientKey, senderKey, message, nonce)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Decrypt
	decrypted, err := crypto.CryptoBoxOpen(recipientKey, senderKey, ciphertext, nonce)
	require.NoError(t, err)
	assert.Equal(t, message, decrypted)

	// Test with wrong key
	wrongKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	require.NoError(t, err)

	_, err = crypto.CryptoBoxOpen(recipientKey, wrongKey, ciphertext, nonce)
	assert.Error(t, err)
}

func TestCryptoBoxSeal(t *testing.T) {
	message := []byte("anonymous message")

	// Generate recipient key
	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	require.NoError(t, err)

	// Seal (anonymous encryption)
	ciphertext, err := crypto.CryptoBoxSeal(recipientKey, message)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Open (decrypt)
	decrypted, err := crypto.CryptoBoxSealOpen(recipientKey, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, message, decrypted)

	// Test with wrong key
	wrongKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	require.NoError(t, err)

	_, err = crypto.CryptoBoxSealOpen(wrongKey, ciphertext)
	assert.Error(t, err)
}

func TestFromPublicBytes(t *testing.T) {
	// Generate a key pair
	originalKey, err := crypto.Generate(enums.KeyAlgEd25519, false)
	require.NoError(t, err)

	// Get public bytes
	pubBytes, err := originalKey.GetPublicBytes()
	require.NoError(t, err)

	// Create key from public bytes
	pubKey, err := crypto.FromPublicBytes(enums.KeyAlgEd25519, pubBytes)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	// Verify public bytes match
	pubBytes2, err := pubKey.GetPublicBytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(pubBytes, pubBytes2))

	// Public key shouldn't have secret bytes
	_, err = pubKey.GetSecretBytes()
	assert.Error(t, err)
}

func TestFromSecretBytes(t *testing.T) {
	// Generate a key
	originalKey, err := crypto.Generate(enums.KeyAlgAES256GCM, false)
	require.NoError(t, err)

	// Get secret bytes
	secretBytes, err := originalKey.GetSecretBytes()
	require.NoError(t, err)

	// Create key from secret bytes
	key, err := crypto.FromSecretBytes(enums.KeyAlgAES256GCM, secretBytes)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Verify secret bytes match
	secretBytes2, err := key.GetSecretBytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secretBytes, secretBytes2))
}