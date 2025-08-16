package crypto_test

import (
	"bytes"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
)

func TestAEADOperations(t *testing.T) {
	// Test with ChaCha20Poly1305
	t.Run("ChaCha20Poly1305", func(t *testing.T) {
		// Generate a key
		key, err := crypto.Generate(enums.KeyAlgChacha20Poly1305, false)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		defer key.Free()

		// Get AEAD parameters
		params, err := key.AEADGetParams()
		if err != nil {
			t.Fatalf("Failed to get AEAD params: %v", err)
		}

		if params.NonceLength != 12 {
			t.Errorf("Expected nonce length 12, got %d", params.NonceLength)
		}
		if params.TagLength != 16 {
			t.Errorf("Expected tag length 16, got %d", params.TagLength)
		}

		// Generate a random nonce
		nonce, err := key.AEADRandomNonce()
		if err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		if len(nonce) != int(params.NonceLength) {
			t.Errorf("Nonce length mismatch: expected %d, got %d", params.NonceLength, len(nonce))
		}

		// Test message
		message := []byte("Hello, World! This is a test message for AEAD encryption.")
		aad := []byte("additional authenticated data")

		// Encrypt
		encrypted, err := key.AEADEncrypt(message, nonce, aad)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Get ciphertext and tag
		ciphertext := encrypted.GetCiphertext()
		tag := encrypted.GetTag()

		if len(ciphertext) != len(message) {
			t.Errorf("Ciphertext length mismatch: expected %d, got %d", len(message), len(ciphertext))
		}

		if len(tag) != int(params.TagLength) {
			t.Errorf("Tag length mismatch: expected %d, got %d", params.TagLength, len(tag))
		}

		// Decrypt
		decrypted, err := key.AEADDecrypt(ciphertext, nonce, tag, aad)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, message) {
			t.Errorf("Decrypted message doesn't match original")
		}
	})

	// Test with AES256-GCM
	t.Run("AES256-GCM", func(t *testing.T) {
		// Generate a key
		key, err := crypto.Generate(enums.KeyAlgAes256Gcm, false)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		defer key.Free()

		// Get AEAD parameters
		_, err = key.AEADGetParams()
		if err != nil {
			t.Fatalf("Failed to get AEAD params: %v", err)
		}

		// Generate a random nonce
		nonce, err := key.AEADRandomNonce()
		if err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		// Test message
		message := []byte("Test message for AES-256-GCM encryption")
		aad := []byte("AAD for AES")

		// Encrypt
		encrypted, err := key.AEADEncrypt(message, nonce, aad)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decrypt
		decrypted, err := key.AEADDecrypt(encrypted.GetCiphertext(), nonce, encrypted.GetTag(), aad)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, message) {
			t.Errorf("Decrypted message doesn't match original")
		}
	})

	// Test with wrong AAD
	t.Run("WrongAAD", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgChacha20Poly1305, false)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		defer key.Free()

		nonce, _ := key.AEADRandomNonce()
		message := []byte("Test message")
		aad := []byte("correct AAD")
		wrongAAD := []byte("wrong AAD")

		encrypted, err := key.AEADEncrypt(message, nonce, aad)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Try to decrypt with wrong AAD - should fail
		_, err = key.AEADDecrypt(encrypted.GetCiphertext(), nonce, encrypted.GetTag(), wrongAAD)
		if err == nil {
			t.Error("Expected decryption to fail with wrong AAD")
		}
	})

	// Test with wrong nonce
	t.Run("WrongNonce", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgChacha20Poly1305, false)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		defer key.Free()

		nonce1, _ := key.AEADRandomNonce()
		nonce2, _ := key.AEADRandomNonce()
		message := []byte("Test message")

		encrypted, err := key.AEADEncrypt(message, nonce1, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Try to decrypt with wrong nonce - should fail or give wrong result
		_, err = key.AEADDecrypt(encrypted.GetCiphertext(), nonce2, encrypted.GetTag(), nil)
		if err == nil {
			t.Error("Expected decryption to fail with wrong nonce")
		}
	})
}

func TestKeyWrapping(t *testing.T) {
	// Generate a key encryption key (KEK)
	kek, err := crypto.Generate(enums.KeyAlgAes256Gcm, false)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}
	defer kek.Free()

	// Generate a content encryption key (CEK) to wrap
	cek, err := crypto.Generate(enums.KeyAlgChacha20Poly1305, false)
	if err != nil {
		t.Fatalf("Failed to generate CEK: %v", err)
	}
	defer cek.Free()

	// Get the original CEK bytes for comparison
	originalCEKBytes, err := cek.GetSecretBytes()
	if err != nil {
		t.Fatalf("Failed to get CEK bytes: %v", err)
	}

	// Generate a nonce for wrapping
	nonce, err := kek.AEADRandomNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Wrap the CEK
	wrapped, err := kek.WrapKey(cek, nonce)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	// Unwrap the CEK
	unwrapped, err := kek.UnwrapKey(enums.KeyAlgChacha20Poly1305, wrapped.GetCiphertext(), wrapped.GetTag(), wrapped.GetNonce())
	if err != nil {
		t.Fatalf("Failed to unwrap key: %v", err)
	}
	defer unwrapped.Free()

	// Get the unwrapped key bytes
	unwrappedBytes, err := unwrapped.GetSecretBytes()
	if err != nil {
		t.Fatalf("Failed to get unwrapped key bytes: %v", err)
	}

	// Compare the keys
	if !bytes.Equal(originalCEKBytes, unwrappedBytes) {
		t.Error("Unwrapped key doesn't match original")
	}

	// Test that we can use the unwrapped key
	testMessage := []byte("Test message with unwrapped key")
	testNonce, _ := unwrapped.AEADRandomNonce()
	encrypted, err := unwrapped.AEADEncrypt(testMessage, testNonce, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt with unwrapped key: %v", err)
	}

	decrypted, err := unwrapped.AEADDecrypt(encrypted.GetCiphertext(), testNonce, encrypted.GetTag(), nil)
	if err != nil {
		t.Fatalf("Failed to decrypt with unwrapped key: %v", err)
	}

	if !bytes.Equal(decrypted, testMessage) {
		t.Error("Decryption with unwrapped key failed")
	}
}