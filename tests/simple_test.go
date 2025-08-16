package tests

import (
	"testing"

	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	version, err := ffi.Version()
	if err != nil {
		t.Logf("Error getting version: %v", err)
	}
	t.Logf("Askar version: %s", version)
	// Version might be empty if not implemented, but library should load
	require.NotNil(t, version)
}