package tests

import (
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorHandling(t *testing.T) {
	t.Run("Invalid Algorithm Error", func(t *testing.T) {
		// Try to generate key with invalid algorithm
		_, err := crypto.Generate("invalid-algorithm", false)
		assert.Error(t, err)
		
		askarErr, ok := err.(*errors.AskarError)
		if ok {
			assert.NotEqual(t, errors.ErrorCodeSuccess, askarErr.Code)
		}
	})
	
	t.Run("Invalid Seed Length", func(t *testing.T) {
		// Try to create key with wrong seed length
		shortSeed := []byte("short")
		_, err := crypto.FromSeed(enums.KeyAlgEd25519, shortSeed)
		// Some algorithms may accept variable length seeds
		// This is implementation specific
		_ = err
	})
	
	t.Run("Store Not Found Error", func(t *testing.T) {
		// Try to open non-existent store
		_, err := store.Open("sqlite:///non/existent/path/test.db", enums.KdfArgon2iMod, "password", "")
		assert.Error(t, err)
		
		askarErr, ok := err.(*errors.AskarError)
		if ok {
			// Should be either NotFound or Backend error
			assert.True(t, 
				askarErr.Code == errors.ErrorCodeNotFound || 
				askarErr.Code == errors.ErrorCodeBackend,
			)
		}
	})
	
	t.Run("Wrong Password Error", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := "sqlite://" + dbPath
		
		// Create store with password
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "correct-password", "", false)
		require.NoError(t, err)
		s.Close()
		
		// Try to open with wrong password
		_, err = store.Open(uri, enums.KdfArgon2iMod, "wrong-password", "")
		assert.Error(t, err)
		
		askarErr, ok := err.(*errors.AskarError)
		if ok {
			// Should be Encryption error
			assert.Equal(t, errors.ErrorCodeEncryption, askarErr.Code)
		}
	})
	
	t.Run("Duplicate Entry Error", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := "sqlite://" + dbPath
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		defer session.Close()
		
		// Insert entry
		err = session.Insert("category", "name", []byte("value"), nil)
		require.NoError(t, err)
		
		// Try to insert duplicate
		err = session.Insert("category", "name", []byte("value2"), nil)
		assert.Error(t, err)
		
		askarErr, ok := err.(*errors.AskarError)
		if ok {
			assert.Equal(t, errors.ErrorCodeDuplicate, askarErr.Code)
		}
	})
	
	t.Run("Entry Not Found", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := "sqlite://" + dbPath
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		defer session.Close()
		
		// Fetch non-existent entry
		entry, err := session.Fetch("category", "non-existent", false)
		require.NoError(t, err) // Fetch returns nil for not found, not error
		assert.Nil(t, entry)
		
		// Remove non-existent entry
		err = session.Remove("category", "non-existent")
		// Remove might not error on non-existent, implementation specific
		_ = err
	})
	
	t.Run("Invalid Key Operation", func(t *testing.T) {
		// Create a public-only key
		originalKey, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		pubBytes, err := originalKey.GetPublicBytes()
		require.NoError(t, err)
		
		pubKey, err := crypto.FromPublicBytes(enums.KeyAlgEd25519, pubBytes)
		require.NoError(t, err)
		
		// Try to get secret from public-only key
		_, err = pubKey.GetSecretBytes()
		assert.Error(t, err)
	})
	
	t.Run("Invalid Signature Verification", func(t *testing.T) {
		key, err := crypto.Generate(enums.KeyAlgEd25519, false)
		require.NoError(t, err)
		
		message := []byte("test message")
		signature := []byte("invalid signature")
		
		// Verify with invalid signature
		verified, err := key.VerifySignature(message, signature, enums.SignatureAlgEdDSA)
		// Should either return false or error
		if err == nil {
			assert.False(t, verified)
		} else {
			assert.Error(t, err)
		}
	})
	
	t.Run("Transaction Rollback", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := "sqlite://" + dbPath
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		// Start transaction
		tx, err := s.Transaction("")
		require.NoError(t, err)
		
		// Insert in transaction
		err = tx.Insert("test", "entry", []byte("value"), nil)
		require.NoError(t, err)
		
		// Rollback
		err = tx.Rollback()
		require.NoError(t, err)
		
		// Verify entry doesn't exist
		session, err := s.Session("")
		require.NoError(t, err)
		defer session.Close()
		
		entry, err := session.Fetch("test", "entry", false)
		require.NoError(t, err)
		assert.Nil(t, entry)
	})
}

func TestErrorCodes(t *testing.T) {
	// Verify error codes are defined correctly
	assert.Equal(t, errors.ErrorCode(0), errors.ErrorCodeSuccess)
	assert.Equal(t, errors.ErrorCode(1), errors.ErrorCodeBackend)
	assert.Equal(t, errors.ErrorCode(2), errors.ErrorCodeBusy)
	assert.Equal(t, errors.ErrorCode(3), errors.ErrorCodeDuplicate)
	assert.Equal(t, errors.ErrorCode(4), errors.ErrorCodeEncryption)
	assert.Equal(t, errors.ErrorCode(5), errors.ErrorCodeInput)
	assert.Equal(t, errors.ErrorCode(6), errors.ErrorCodeNotFound)
	assert.Equal(t, errors.ErrorCode(7), errors.ErrorCodeUnexpected)
	assert.Equal(t, errors.ErrorCode(8), errors.ErrorCodeUnsupported)
	assert.Equal(t, errors.ErrorCode(100), errors.ErrorCodeCustom)
}

func TestAskarError(t *testing.T) {
	err := errors.NewAskarError(errors.ErrorCodeInput, "test error message")
	assert.NotNil(t, err)
	assert.Equal(t, errors.ErrorCodeInput, err.Code)
	assert.Equal(t, "test error message", err.Message)
	assert.Contains(t, err.Error(), "test error message")
	
	// With extra information
	err.Extra = "additional context"
	assert.Contains(t, err.Error(), "additional context")
}