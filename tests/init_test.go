package tests

import (
	"log"
	"os"
	"testing"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/ffi"
)

func TestMain(m *testing.M) {
	// Initialize Askar
	version, err := ffi.Version()
	if err != nil {
		log.Fatalf("Failed to get Askar version: %v", err)
	}
	log.Printf("Using Askar version: %s", version)

	// Set log level for debugging
	if err := ffi.SetMaxLogLevel(int32(enums.LogLevelWarn)); err != nil {
		log.Printf("Failed to set log level: %v", err)
	}

	// Run tests
	code := m.Run()
	os.Exit(code)
}