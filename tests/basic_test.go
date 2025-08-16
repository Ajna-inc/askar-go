package tests

import (
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/stretchr/testify/require"
)

func TestBasicKeyGeneration(t *testing.T) {
	// Try to generate a simple Ed25519 key
	key, err := crypto.Generate(enums.KeyAlgEd25519, false)
	require.NoError(t, err, "Failed to generate Ed25519 key")
	require.NotNil(t, key)
	
	// Get the algorithm
	alg, err := key.GetAlgorithm()
	require.NoError(t, err)
	require.Equal(t, enums.KeyAlgEd25519, alg)
	
	// Get public bytes
	pubBytes, err := key.GetPublicBytes()
	require.NoError(t, err)
	require.NotEmpty(t, pubBytes)
	require.Len(t, pubBytes, 32) // Ed25519 public key is 32 bytes
	
	t.Logf("Successfully generated Ed25519 key with public key: %x", pubBytes)
}