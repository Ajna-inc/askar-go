package main

import (
	"encoding/hex"
	"fmt"
	"log"

	askar "github.com/Ajna-inc/askar-go"
)

func main() {
	// Initialize logging
	askar.SetMaxLogLevel(askar.LogLevelWarn)
	
	// Example 1: Key Generation and Operations
	fmt.Println("=== Key Operations ===")
	
	// Generate a key
	key, err := askar.GenerateKey(askar.KeyAlgEd25519, false)
	if err != nil {
		log.Fatal(err)
	}
	
	// Get algorithm
	alg, err := key.GetAlgorithm()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Algorithm: %s\n", alg)
	
	// Get public bytes
	pubBytes, err := key.GetPublicBytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubBytes))
	
	// Get JWK representation
	jwkPub, err := key.GetJwkPublic()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("JWK Public: %s\n", jwkPub)
	
	// Sign and verify
	message := []byte("test message")
	signature, err := key.SignMessage(message)
	if err != nil {
		log.Fatal(err)
	}
	
	verified, err := key.VerifySignature(message, signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature verified: %v\n", verified)
	
	// Example 2: Store Operations
	fmt.Println("\n=== Store Operations ===")
	
	// Provision a store
	store, err := askar.StoreProvision("sqlite:///tmp/test.db", askar.KdfArgon2iMod, "password", "", true)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	
	// Create a session
	session, err := store.Session("")
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	
	// Insert an entry
	err = session.Insert("credentials", "user123", []byte(`{"username":"alice","password":"secret"}`), map[string]interface{}{
		"type": "password",
		"user": "alice",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Entry inserted")
	
	// Insert a key
	err = session.InsertKey(key, "signing-key", "My signing key", map[string]interface{}{
		"purpose": "authentication",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Key stored")
	
	// Fetch the entry
	entry, err := session.Fetch("credentials", "user123", false)
	if err != nil {
		log.Fatal(err)
	}
	if entry != nil {
		fmt.Printf("Fetched entry: %s\n", string(entry.Value))
	}
	
	// Fetch the key
	keyEntry, err := session.FetchKey("signing-key", false)
	if err != nil {
		log.Fatal(err)
	}
	if keyEntry != nil {
		fmt.Printf("Fetched key: %s (algorithm: %s)\n", keyEntry.Name, keyEntry.Algorithm)
		
		// Load the actual key
		loadedKey, err := keyEntry.LoadLocal()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Key loaded successfully")
		_ = loadedKey
	}
	
	// Example 3: CryptoBox Operations
	fmt.Println("\n=== CryptoBox Operations ===")
	
	// Generate keys for sender and recipient
	senderKey, err := askar.GenerateKey(askar.KeyAlgX25519, false)
	if err != nil {
		log.Fatal(err)
	}
	
	recipientKey, err := askar.GenerateKey(askar.KeyAlgX25519, false)
	if err != nil {
		log.Fatal(err)
	}
	
	// Encrypt with CryptoBox
	secretMessage := []byte("secret message")
	nonce := []byte("24-byte nonce for crypto")[:24]
	
	encrypted, err := askar.CryptoBox(recipientKey, senderKey, secretMessage, nonce)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted: %x\n", encrypted)
	
	// Decrypt
	decrypted, err := askar.CryptoBoxOpen(recipientKey, senderKey, encrypted, nonce)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted: %s\n", string(decrypted))
	
	// Example 4: Sealed Box (anonymous encryption)
	sealed, err := askar.CryptoBoxSeal(recipientKey, secretMessage)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sealed: %x\n", sealed)
	
	unsealed, err := askar.CryptoBoxSealOpen(recipientKey, sealed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Unsealed: %s\n", string(unsealed))
	
	// Example 5: ECDH Operations
	fmt.Println("\n=== ECDH Operations ===")
	
	ecdh := &askar.EcdhEs{}
	
	// Generate ephemeral key
	ephemeralKey, err := askar.GenerateKey(askar.KeyAlgX25519, true)
	if err != nil {
		log.Fatal(err)
	}
	
	// Derive shared key
	sharedKey, err := ecdh.DeriveKey(askar.KeyAlgChacha20Poly1305, ephemeralKey, recipientKey, []byte("apu"), []byte("apv"), false)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ECDH key derived successfully")
	_ = sharedKey
	
	// Example 6: Scan Operations
	fmt.Println("\n=== Scan Operations ===")
	
	// Insert more entries for scanning
	for i := 0; i < 5; i++ {
		err = session.Insert("test", fmt.Sprintf("item-%d", i), []byte(fmt.Sprintf("value-%d", i)), map[string]interface{}{
			"index": i,
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	
	// Start a scan
	scan, err := store.StartScan("", "test", nil, 0, 2) // Scan with limit of 2
	if err != nil {
		log.Fatal(err)
	}
	defer scan.Close()
	
	// Iterate through results
	count := 0
	err = scan.Iterate(func(entry *askar.Entry) error {
		fmt.Printf("Scanned: %s = %s\n", entry.Name, string(entry.Value))
		count++
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Total scanned: %d entries\n", count)
	
	fmt.Println("\n=== All operations completed successfully ===")
}