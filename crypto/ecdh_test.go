package crypto_test

import (
	"bytes"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
)

func TestECDHES(t *testing.T) {
	// Generate recipient key pair
	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	// Generate ephemeral key pair
	ephemeralKey, err := crypto.Generate(enums.KeyAlgX25519, true)
	if err != nil {
		t.Fatalf("Failed to generate ephemeral key: %v", err)
	}
	defer ephemeralKey.Free()

	// Test key derivation
	apu := []byte("Alice")
	apv := []byte("Bob")

	ecdhEs := &crypto.EcdhEs{}

	// Derive key for encryption (sender side)
	encKey, err := ecdhEs.DeriveKey(enums.KeyAlgChacha20Poly1305, ephemeralKey, recipientKey, apu, apv, false)
	if err != nil {
		t.Fatalf("Failed to derive encryption key: %v", err)
	}
	defer encKey.Free()

	// Derive key for decryption (recipient side)
	decKey, err := ecdhEs.DeriveKey(enums.KeyAlgChacha20Poly1305, ephemeralKey, recipientKey, apu, apv, true)
	if err != nil {
		t.Fatalf("Failed to derive decryption key: %v", err)
	}
	defer decKey.Free()

	// The derived keys should be the same
	encKeyBytes, _ := encKey.GetSecretBytes()
	decKeyBytes, _ := decKey.GetSecretBytes()

	if !bytes.Equal(encKeyBytes, decKeyBytes) {
		t.Error("Derived keys don't match")
	}

	// Test encryption/decryption with derived keys
	message := []byte("Test message for ECDH-ES")
	nonce, _ := encKey.AEADRandomNonce()

	encrypted, err := encKey.AEADEncrypt(message, nonce, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := decKey.AEADDecrypt(encrypted.GetCiphertext(), nonce, encrypted.GetTag(), nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Error("Decrypted message doesn't match original")
	}
}

func TestECDHESDirectEncryption(t *testing.T) {
	// Generate recipient key pair
	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	ecdhEs := &crypto.EcdhEs{}

	message := []byte("Direct encryption test message")
	apu := []byte("Alice")
	apv := []byte("Bob")
	nonce, _ := crypto.Generate(enums.KeyAlgChacha20Poly1305, false)
	nonceBytes, _ := nonce.AEADRandomNonce()
	nonce.Free()

	// Encrypt directly
	encrypted, err := ecdhEs.EncryptDirect(recipientKey, message, apu, apv, nonceBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt directly: %v", err)
	}

	// Decrypt directly
	decrypted, err := ecdhEs.DecryptDirect(recipientKey, encrypted.EphemeralPublicKey, encrypted.Ciphertext, encrypted.Tag, apu, apv, encrypted.Nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt directly: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Error("Decrypted message doesn't match original")
	}
}

func TestECDH1PU(t *testing.T) {
	// Generate keys for all parties
	ephemeralKey, err := crypto.Generate(enums.KeyAlgX25519, true)
	if err != nil {
		t.Fatalf("Failed to generate ephemeral key: %v", err)
	}
	defer ephemeralKey.Free()

	senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate sender key: %v", err)
	}
	defer senderKey.Free()

	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	// Create ECDH-1PU instance
	algId := []byte("A256GCM")
	apu := []byte("Alice")
	apv := []byte("Bob")
	ecdh1pu := crypto.NewEcdh1PU(algId, apu, apv)

	// Test key derivation with ccTag
	ccTag := []byte("authentication")

	// Derive key for sender
	senderDerived, err := ecdh1pu.DeriveKey(enums.KeyAlgAes256Gcm, ephemeralKey, senderKey, recipientKey, ccTag, false)
	if err != nil {
		t.Fatalf("Failed to derive sender key: %v", err)
	}
	defer senderDerived.Free()

	// Derive key for receiver
	receiverDerived, err := ecdh1pu.DeriveKey(enums.KeyAlgAes256Gcm, ephemeralKey, senderKey, recipientKey, ccTag, true)
	if err != nil {
		t.Fatalf("Failed to derive receiver key: %v", err)
	}
	defer receiverDerived.Free()

	// The derived keys should be the same
	senderBytes, _ := senderDerived.GetSecretBytes()
	receiverBytes, _ := receiverDerived.GetSecretBytes()

	if !bytes.Equal(senderBytes, receiverBytes) {
		t.Error("Derived keys don't match")
	}
}

func TestECDH1PUDirectEncryption(t *testing.T) {
	// Generate keys
	ephemeralKey, err := crypto.Generate(enums.KeyAlgX25519, true)
	if err != nil {
		t.Fatalf("Failed to generate ephemeral key: %v", err)
	}
	defer ephemeralKey.Free()

	senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate sender key: %v", err)
	}
	defer senderKey.Free()

	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	// Create ECDH-1PU instance
	algId := []byte("A256GCM")
	apu := []byte("Alice")
	apv := []byte("Bob")
	ecdh1pu := crypto.NewEcdh1PU(algId, apu, apv)

	message := []byte("ECDH-1PU test message")
	aad := []byte("additional data")

	// Generate nonce
	tempKey, _ := crypto.Generate(enums.KeyAlgAes256Gcm, false)
	nonce, _ := tempKey.AEADRandomNonce()
	tempKey.Free()

	// Encrypt
	encrypted, err := ecdh1pu.EncryptDirect(enums.KeyAlgAes256Gcm, ephemeralKey, senderKey, recipientKey, message, aad, nonce)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := ecdh1pu.DecryptDirect(enums.KeyAlgAes256Gcm, ephemeralKey, senderKey, recipientKey, encrypted.GetCiphertext(), nonce, encrypted.GetTag(), aad)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Error("Decrypted message doesn't match original")
	}
}

func TestECDH1PUKeyWrapping(t *testing.T) {
	// Generate keys
	ephemeralKey, err := crypto.Generate(enums.KeyAlgX25519, true)
	if err != nil {
		t.Fatalf("Failed to generate ephemeral key: %v", err)
	}
	defer ephemeralKey.Free()

	senderKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate sender key: %v", err)
	}
	defer senderKey.Free()

	recipientKey, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}
	defer recipientKey.Free()

	// Generate a CEK to wrap
	cek, err := crypto.Generate(enums.KeyAlgAes256Gcm, false)
	if err != nil {
		t.Fatalf("Failed to generate CEK: %v", err)
	}
	defer cek.Free()

	originalCEKBytes, _ := cek.GetSecretBytes()

	// Create ECDH-1PU instance
	algId := []byte("A256KW")
	apu := []byte("Alice")
	apv := []byte("Bob")
	ecdh1pu := crypto.NewEcdh1PU(algId, apu, apv)

	ccTag := []byte("key-wrap-auth")

	// Wrap the key (sender side)
	wrapped, err := ecdh1pu.SenderWrapKey(enums.KeyAlgAES256KW, ephemeralKey, senderKey, recipientKey, cek, ccTag)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	// Unwrap the key (receiver side)
	unwrapped, err := ecdh1pu.ReceiverUnwrapKey(enums.KeyAlgAES256KW, enums.KeyAlgAes256Gcm, ephemeralKey, senderKey, recipientKey, wrapped.GetCiphertext(), wrapped.GetNonce(), wrapped.GetTag(), ccTag)
	if err != nil {
		t.Fatalf("Failed to unwrap key: %v", err)
	}
	defer unwrapped.Free()

	unwrappedBytes, _ := unwrapped.GetSecretBytes()

	if !bytes.Equal(originalCEKBytes, unwrappedBytes) {
		t.Error("Unwrapped key doesn't match original")
	}
}

func TestFromKeyExchange(t *testing.T) {
	// Generate two key pairs
	alicePriv, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate Alice's private key: %v", err)
	}
	defer alicePriv.Free()

	bobPriv, err := crypto.Generate(enums.KeyAlgX25519, false)
	if err != nil {
		t.Fatalf("Failed to generate Bob's private key: %v", err)
	}
	defer bobPriv.Free()

	// Get public keys
	alicePubBytes, _ := alicePriv.GetPublicBytes()
	bobPubBytes, _ := bobPriv.GetPublicBytes()

	// Create public key objects
	alicePub, err := crypto.FromPublicBytes(enums.KeyAlgX25519, alicePubBytes)
	if err != nil {
		t.Fatalf("Failed to create Alice's public key: %v", err)
	}
	defer alicePub.Free()

	bobPub, err := crypto.FromPublicBytes(enums.KeyAlgX25519, bobPubBytes)
	if err != nil {
		t.Fatalf("Failed to create Bob's public key: %v", err)
	}
	defer bobPub.Free()

	// Alice derives shared secret using her private key and Bob's public key
	aliceShared, err := crypto.FromKeyExchange(enums.KeyAlgChacha20Poly1305, alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Failed to derive Alice's shared key: %v", err)
	}
	defer aliceShared.Free()

	// Bob derives shared secret using his private key and Alice's public key
	bobShared, err := crypto.FromKeyExchange(enums.KeyAlgChacha20Poly1305, bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Failed to derive Bob's shared key: %v", err)
	}
	defer bobShared.Free()

	// The shared secrets should be identical
	aliceSharedBytes, _ := aliceShared.GetSecretBytes()
	bobSharedBytes, _ := bobShared.GetSecretBytes()

	if !bytes.Equal(aliceSharedBytes, bobSharedBytes) {
		t.Error("Shared secrets don't match")
	}

	// Test that we can use the shared secret for encryption
	message := []byte("Secret message")
	nonce, _ := aliceShared.AEADRandomNonce()

	// Alice encrypts
	encrypted, err := aliceShared.AEADEncrypt(message, nonce, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt with shared key: %v", err)
	}

	// Bob decrypts
	decrypted, err := bobShared.AEADDecrypt(encrypted.GetCiphertext(), nonce, encrypted.GetTag(), nil)
	if err != nil {
		t.Fatalf("Failed to decrypt with shared key: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Error("Decrypted message doesn't match original")
	}
}