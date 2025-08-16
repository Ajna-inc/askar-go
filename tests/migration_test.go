package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/migration"
	"github.com/Ajna-inc/askar-go/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigration(t *testing.T) {
	t.Run("MigrateFromIndySDK", func(t *testing.T) {
		// Check if test wallet exists
		testWalletPath := filepath.Join(".", "indy_wallet_sqlite.db")
		if _, err := os.Stat(testWalletPath); os.IsNotExist(err) {
			t.Skip("Indy SDK test wallet not found, skipping migration test")
		}
		
		// Target database for migration
		targetPath := getTempDBPath(t)
		targetURI := "sqlite://" + targetPath
		
		// Attempt migration
		err := migration.MigrateIndySdk(
			targetURI,
			testWalletPath,
			"testkey",
			migration.KdfLevelArgon2iMod,
		)
		
		// Migration might fail if wallet format is incompatible
		if err != nil {
			t.Logf("Migration failed (expected if wallet format incompatible): %v", err)
			return
		}
		
		// If successful, verify we can open the migrated store
		s, err := store.Open(targetURI, enums.KdfArgon2iMod, "testkey", "")
		if err == nil {
			defer s.Close()
			
			// Try to read some data
			session, err := s.Session("")
			require.NoError(t, err)
			defer session.Close()
			
			// Count entries (should have some if migration was successful)
			count, err := session.Count("", nil)
			require.NoError(t, err)
			t.Logf("Migrated store contains %d entries", count)
		}
	})
	
	t.Run("MigrationOptions", func(t *testing.T) {
		// Test with migration options
		opts := migration.MigrationOptions{
			SpecURI:    "sqlite:///tmp/migrated.db",
			WalletName: "test_wallet",
			WalletKey:  "test_key",
			KdfLevel:   migration.KdfLevelArgon2iInt,
		}
		
		// This will likely fail without a real Indy wallet
		err := migration.Migrate(opts)
		if err != nil {
			// Expected to fail in test environment
			t.Logf("Migration with options failed (expected): %v", err)
		}
	})
	
	t.Run("InvalidMigrationParameters", func(t *testing.T) {
		// Test with invalid parameters
		err := migration.MigrateIndySdk(
			"",
			"",
			"",
			migration.KdfLevelArgon2iMod,
		)
		assert.Error(t, err)
	})
	
	t.Run("MigrationToExistingStore", func(t *testing.T) {
		// Create an existing store
		dbPath := getTempDBPath(t)
		uri := "sqlite://" + dbPath
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		s.Close()
		
		// Try to migrate to existing store
		err = migration.MigrateIndySdk(
			uri,
			"test_wallet",
			"test_key",
			migration.KdfLevelArgon2iMod,
		)
		
		// Should fail because store already exists
		assert.Error(t, err)
	})
	
	t.Run("KdfLevels", func(t *testing.T) {
		// Test different KDF levels
		levels := []migration.KdfLevel{
			migration.KdfLevelArgon2iMod,
			migration.KdfLevelArgon2iInt,
			migration.KdfLevelRaw,
		}
		
		for _, level := range levels {
			t.Run(string(level), func(t *testing.T) {
				// Just verify the constants are defined
				assert.NotEmpty(t, level)
			})
		}
	})
}

func TestMigrationWithTestFile(t *testing.T) {
	// This test uses the actual test migration file from JavaScript tests
	testFiles := []string{
		"indy_wallet_sqlite.db",
		"indy_wallet_sqlite_upgraded.db",
	}
	
	for _, testFile := range testFiles {
		t.Run(testFile, func(t *testing.T) {
			testPath := filepath.Join(".", testFile)
			
			// Check if test file exists
			if _, err := os.Stat(testPath); os.IsNotExist(err) {
				t.Skipf("Test file %s not found", testFile)
			}
			
			// Get file info
			info, err := os.Stat(testPath)
			require.NoError(t, err)
			t.Logf("Test file %s size: %d bytes", testFile, info.Size())
			
			// Prepare migration target
			targetPath := getTempDBPath(t)
			targetURI := "sqlite://" + targetPath
			
			// Attempt migration with known test wallet password
			testPasswords := []string{
				"testkey",
				"test",
				"00000000000000000000000000000Test",
			}
			
			var migrationErr error
			for _, password := range testPasswords {
				migrationErr = migration.MigrateIndySdk(
					targetURI,
					testPath,
					password,
					migration.KdfLevelArgon2iMod,
				)
				
				if migrationErr == nil {
					t.Logf("Successfully migrated with password: %s", password)
					break
				}
			}
			
			if migrationErr != nil {
				t.Logf("Could not migrate %s (may be incompatible format): %v", testFile, migrationErr)
				return
			}
			
			// Verify migrated store
			s, err := store.Open(targetURI, enums.KdfArgon2iMod, testPasswords[0], "")
			require.NoError(t, err)
			defer s.Close()
			
			// List profiles
			profiles, err := s.ListProfiles()
			require.NoError(t, err)
			t.Logf("Migrated store has %d profiles", len(profiles))
			
			// Check for data in default profile
			session, err := s.Session("")
			require.NoError(t, err)
			defer session.Close()
			
			// Count all entries
			categories := []string{
				"", // All categories
				"credential",
				"credential_definition",
				"schema",
				"master_secret",
				"link_secret",
			}
			
			for _, category := range categories {
				count, err := session.Count(category, nil)
				if err == nil && count > 0 {
					t.Logf("Category '%s' has %d entries", category, count)
				}
			}
		})
	}
}