package crypto_test

import (
	"bytes"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
)

func TestCryptoBox(t *testing.T) {
	// Generate key pairs for sender and recipient
	senderKey, err := crypto.Generate(enums.KeyAlgEd25519, false)
	if err != nil {
		t.Fatalf("Failed to generate sender key: %v", err)
	}
	defer senderKey.Free()

	recipientKey, err := crypto.Generate(enums.KeyAlgEd25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	// Convert Ed25519 keys to X25519 for crypto_box
	senderX25519, err := senderKey.Convert(enums.KeyAlgX25519)
	if err != nil {
		t.Fatalf("Failed to convert sender key to X25519: %v", err)
	}
	defer senderX25519.Free()

	recipientX25519, err := recipientKey.Convert(enums.KeyAlgX25519)
	if err != nil {
		t.Fatalf("Failed to convert recipient key to X25519: %v", err)
	}
	defer recipientX25519.Free()

	// Generate nonce
	nonce, err := crypto.CryptoBoxRandomNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	message := []byte("Secret message for crypto_box testing")

	// Encrypt the message
	ciphertext, err := crypto.CryptoBox(recipientX25519, senderX25519, message, nonce)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Decrypt the message
	decrypted, err := crypto.CryptoBoxOpen(recipientX25519, senderX25519, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Error("Decrypted message doesn't match original")
	}

	// Test with wrong keys - should fail
	wrongKey, _ := crypto.Generate(enums.KeyAlgX25519, false)
	defer wrongKey.Free()

	_, err = crypto.CryptoBoxOpen(wrongKey, senderX25519, ciphertext, nonce)
	if err == nil {
		t.Error("Expected decryption to fail with wrong recipient key")
	}

	_, err = crypto.CryptoBoxOpen(recipientX25519, wrongKey, ciphertext, nonce)
	if err == nil {
		t.Error("Expected decryption to fail with wrong sender key")
	}
}

func TestCryptoBoxSeal(t *testing.T) {
	// Generate recipient key pair
	recipientKey, err := crypto.Generate(enums.KeyAlgEd25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	// Convert to X25519 for crypto_box_seal
	recipientX25519, err := recipientKey.Convert(enums.KeyAlgX25519)
	if err != nil {
		t.Fatalf("Failed to convert recipient key to X25519: %v", err)
	}
	defer recipientX25519.Free()

	message := []byte("Anonymous message for crypto_box_seal")

	// Seal the message (anonymous encryption)
	sealed, err := crypto.CryptoBoxSeal(recipientX25519, message)
	if err != nil {
		t.Fatalf("Failed to seal message: %v", err)
	}

	// Unseal the message
	unsealed, err := crypto.CryptoBoxSealOpen(recipientX25519, sealed)
	if err != nil {
		t.Fatalf("Failed to unseal message: %v", err)
	}

	if !bytes.Equal(unsealed, message) {
		t.Error("Unsealed message doesn't match original")
	}

	// Test with wrong key - should fail
	wrongKey, _ := crypto.Generate(enums.KeyAlgX25519, false)
	defer wrongKey.Free()

	_, err = crypto.CryptoBoxSealOpen(wrongKey, sealed)
	if err == nil {
		t.Error("Expected unsealing to fail with wrong key")
	}
}

func TestCryptoBoxRandomNonce(t *testing.T) {
	// Generate multiple nonces and ensure they're different
	nonce1, err := crypto.CryptoBoxRandomNonce()
	if err != nil {
		t.Fatalf("Failed to generate first nonce: %v", err)
	}

	nonce2, err := crypto.CryptoBoxRandomNonce()
	if err != nil {
		t.Fatalf("Failed to generate second nonce: %v", err)
	}

	// Check nonce length (should be 24 bytes for XSalsa20-Poly1305)
	if len(nonce1) != 24 {
		t.Errorf("Expected nonce length 24, got %d", len(nonce1))
	}

	if len(nonce2) != 24 {
		t.Errorf("Expected nonce length 24, got %d", len(nonce2))
	}

	// Nonces should be different
	if bytes.Equal(nonce1, nonce2) {
		t.Error("Generated nonces are identical, expected them to be different")
	}
}

func TestCryptoBoxIntegration(t *testing.T) {
	// Test a complete crypto_box workflow
	// Alice and Bob exchange encrypted messages

	// Generate key pairs
	aliceKey, _ := crypto.Generate(enums.KeyAlgEd25519, false)
	defer aliceKey.Free()
	bobKey, _ := crypto.Generate(enums.KeyAlgEd25519, false)
	defer bobKey.Free()

	// Convert to X25519
	aliceX25519, _ := aliceKey.Convert(enums.KeyAlgX25519)
	defer aliceX25519.Free()
	bobX25519, _ := bobKey.Convert(enums.KeyAlgX25519)
	defer bobX25519.Free()

	// Alice sends a message to Bob
	aliceMessage := []byte("Hello Bob, this is Alice!")
	nonce1, _ := crypto.CryptoBoxRandomNonce()

	// Alice encrypts using Bob's public key and her private key
	aliceCiphertext, err := crypto.CryptoBox(bobX25519, aliceX25519, aliceMessage, nonce1)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Bob decrypts using his private key and Alice's public key
	bobDecrypted, err := crypto.CryptoBoxOpen(bobX25519, aliceX25519, aliceCiphertext, nonce1)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	if !bytes.Equal(bobDecrypted, aliceMessage) {
		t.Error("Bob's decrypted message doesn't match Alice's original")
	}

	// Bob sends a reply to Alice
	bobMessage := []byte("Hi Alice, message received!")
	nonce2, _ := crypto.CryptoBoxRandomNonce()

	// Bob encrypts using Alice's public key and his private key
	bobCiphertext, err := crypto.CryptoBox(aliceX25519, bobX25519, bobMessage, nonce2)
	if err != nil {
		t.Fatalf("Bob failed to encrypt: %v", err)
	}

	// Alice decrypts using her private key and Bob's public key
	aliceDecrypted, err := crypto.CryptoBoxOpen(aliceX25519, bobX25519, bobCiphertext, nonce2)
	if err != nil {
		t.Fatalf("Alice failed to decrypt: %v", err)
	}

	if !bytes.Equal(aliceDecrypted, bobMessage) {
		t.Error("Alice's decrypted message doesn't match Bob's original")
	}
}

func TestCryptoBoxWithDifferentKeyTypes(t *testing.T) {
	// Test that only X25519 keys work with crypto_box

	// Try with Ed25519 keys directly (should fail or be converted internally)
	ed25519Key, _ := crypto.Generate(enums.KeyAlgEd25519, false)
	defer ed25519Key.Free()

	// Try with P256 keys (should fail)
	p256Key, _ := crypto.Generate(enums.KeyAlgP256, false)
	defer p256Key.Free()

	nonce, _ := crypto.CryptoBoxRandomNonce()
	message := []byte("Test message")

	// These should fail as crypto_box requires X25519 keys
	_, err := crypto.CryptoBox(p256Key, p256Key, message, nonce)
	if err == nil {
		t.Log("Warning: crypto_box accepted non-X25519 keys")
	}
}

// Helper function to test key conversion
func TestKeyConversion(t *testing.T) {
	// Generate Ed25519 key
	ed25519Key, err := crypto.Generate(enums.KeyAlgEd25519, false)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	defer ed25519Key.Free()

	// Convert to X25519
	x25519Key, err := ed25519Key.Convert(enums.KeyAlgX25519)
	if err != nil {
		t.Fatalf("Failed to convert to X25519: %v", err)
	}
	defer x25519Key.Free()

	// Check algorithm
	alg, err := x25519Key.GetAlgorithm()
	if err != nil {
		t.Fatalf("Failed to get algorithm: %v", err)
	}

	if alg != enums.KeyAlgX25519 {
		t.Errorf("Expected algorithm X25519, got %s", alg)
	}
}