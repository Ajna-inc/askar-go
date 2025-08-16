package tests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTempDBPath(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "askar-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})
	return filepath.Join(tempDir, "test.db")
}

func TestStoreProvision(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	// Test provision with Argon2i KDF
	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	require.NotNil(t, s)
	defer s.Close()

	// Verify we can get profile name
	profile, err := s.GetProfileName()
	require.NoError(t, err)
	assert.NotEmpty(t, profile)
}

func TestStoreOpenClose(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	// Provision store
	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Close store
	err = s.Close()
	require.NoError(t, err)

	// Open existing store
	s, err = store.Open(uri, enums.KdfArgon2iMod, "test-password", "")
	require.NoError(t, err)
	require.NotNil(t, s)
	defer s.Close()

	// Test opening with wrong password
	s2, err := store.Open(uri, enums.KdfArgon2iMod, "wrong-password", "")
	assert.Error(t, err)
	assert.Nil(t, s2)
}

func TestStoreProfiles(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	defer s.Close()

	// List profiles (should have default)
	profiles, err := s.ListProfiles()
	require.NoError(t, err)
	assert.Len(t, profiles, 1)

	// Create new profile
	err = s.CreateProfile("test-profile")
	require.NoError(t, err)

	// List profiles again
	profiles, err = s.ListProfiles()
	require.NoError(t, err)
	assert.Len(t, profiles, 2)
	assert.Contains(t, profiles, "test-profile")

	// Set default profile
	err = s.SetDefaultProfile("test-profile")
	require.NoError(t, err)

	// Remove profile
	err = s.RemoveProfile("test-profile")
	require.NoError(t, err)

	profiles, err = s.ListProfiles()
	require.NoError(t, err)
	assert.Len(t, profiles, 1)
}

func TestStoreSession(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	defer s.Close()

	// Create session
	session, err := s.Session("")
	require.NoError(t, err)
	require.NotNil(t, session)
	defer session.Close()

	// Test basic CRUD operations
	testEntry := []byte("test value")
	testTags := map[string]interface{}{
		"tag1": "value1",
		"tag2": json.Number("42"),
	}

	// Insert entry
	err = session.Insert("test-category", "test-name", testEntry, testTags)
	require.NoError(t, err)

	// Fetch entry
	entry, err := session.Fetch("test-category", "test-name", false)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "test-category", entry.Category)
	assert.Equal(t, "test-name", entry.Name)
	assert.Equal(t, testEntry, entry.Value)
	assert.Equal(t, "value1", entry.Tags["tag1"])

	// Update entry
	newValue := []byte("updated value")
	err = session.Replace("test-category", "test-name", newValue, nil)
	require.NoError(t, err)

	entry, err = session.Fetch("test-category", "test-name", false)
	require.NoError(t, err)
	assert.Equal(t, newValue, entry.Value)

	// Remove entry
	err = session.Remove("test-category", "test-name")
	require.NoError(t, err)

	entry, err = session.Fetch("test-category", "test-name", false)
	require.NoError(t, err)
	assert.Nil(t, entry)
}

func TestStoreTransaction(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	defer s.Close()

	// Test commit
	tx, err := s.Transaction("")
	require.NoError(t, err)

	err = tx.Insert("test", "entry1", []byte("value1"), nil)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// Verify entry exists
	session, err := s.Session("")
	require.NoError(t, err)
	defer session.Close()

	entry, err := session.Fetch("test", "entry1", false)
	require.NoError(t, err)
	assert.NotNil(t, entry)

	// Test rollback
	tx, err = s.Transaction("")
	require.NoError(t, err)

	err = tx.Insert("test", "entry2", []byte("value2"), nil)
	require.NoError(t, err)

	err = tx.Rollback()
	require.NoError(t, err)

	// Verify entry doesn't exist
	entry, err = session.Fetch("test", "entry2", false)
	require.NoError(t, err)
	assert.Nil(t, entry)
}

func TestStoreKeys(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	defer s.Close()

	session, err := s.Session("")
	require.NoError(t, err)
	defer session.Close()

	// Generate and insert key
	key, err := crypto.Generate(enums.KeyAlgEd25519, false)
	require.NoError(t, err)

	keyTags := map[string]interface{}{
		"type": "signing",
	}

	err = session.InsertKey(key, "test-key", "key metadata", keyTags)
	require.NoError(t, err)

	// Fetch key
	keyEntry, err := session.FetchKey("test-key", false)
	require.NoError(t, err)
	require.NotNil(t, keyEntry)
	assert.Equal(t, enums.KeyAlgEd25519, keyEntry.Algorithm)
	assert.Equal(t, "test-key", keyEntry.Name)
	assert.Equal(t, "key metadata", keyEntry.Metadata)
	assert.Equal(t, "signing", keyEntry.Tags["type"])

	// Load the actual key
	loadedKey, err := keyEntry.LoadLocal()
	require.NoError(t, err)
	require.NotNil(t, loadedKey)

	// Update key metadata
	err = session.UpdateKey("test-key", "updated metadata", nil)
	require.NoError(t, err)

	keyEntry, err = session.FetchKey("test-key", false)
	require.NoError(t, err)
	assert.Equal(t, "updated metadata", keyEntry.Metadata)

	// Fetch all keys
	keys, err := session.FetchAllKeys("", "", nil, 10, false)
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Remove key
	err = session.RemoveKey("test-key")
	require.NoError(t, err)

	keyEntry, err = session.FetchKey("test-key", false)
	require.NoError(t, err)
	assert.Nil(t, keyEntry)
}

func TestStoreFetchAll(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	s, err := store.Provision(uri, enums.KdfArgon2iMod, "test-password", "", false)
	require.NoError(t, err)
	defer s.Close()

	session, err := s.Session("")
	require.NoError(t, err)
	defer session.Close()

	// Insert multiple entries
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("entry-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		tags := map[string]interface{}{
			"index": json.Number(fmt.Sprintf("%d", i)),
			"even":  i%2 == 0,
		}
		err = session.Insert("test", name, value, tags)
		require.NoError(t, err)
	}

	// Fetch all
	entries, err := session.FetchAll("test", nil, -1, false)
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	// Fetch with tag filter
	evenFilter := map[string]interface{}{
		"even": true,
	}
	entries, err = session.FetchAll("test", evenFilter, -1, false)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// Test count
	count, err := session.Count("test", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)

	count, err = session.Count("test", evenFilter)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	// Remove all with filter
	removed, err := session.RemoveAll("test", evenFilter)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed)

	entries, err = session.FetchAll("test", nil, -1, false)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestStoreCopy(t *testing.T) {
	dbPath1 := getTempDBPath(t)
	dbPath2 := getTempDBPath(t)
	uri1 := fmt.Sprintf("sqlite://%s", dbPath1)
	uri2 := fmt.Sprintf("sqlite://%s", dbPath2)

	// Create and populate original store
	s1, err := store.Provision(uri1, enums.KdfArgon2iMod, "password1", "", false)
	require.NoError(t, err)

	session, err := s1.Session("")
	require.NoError(t, err)

	err = session.Insert("test", "entry1", []byte("value1"), nil)
	require.NoError(t, err)
	session.Close()

	// Copy store
	s2, err := s1.Copy(uri2, enums.KdfArgon2iMod, "password2", false)
	require.NoError(t, err)
	defer s2.Close()
	s1.Close()

	// Verify data was copied
	session, err = s2.Session("")
	require.NoError(t, err)
	defer session.Close()

	entry, err := session.Fetch("test", "entry1", false)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	assert.Equal(t, []byte("value1"), entry.Value)
}

func TestStoreRekey(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	// Create store with initial password
	s, err := store.Provision(uri, enums.KdfArgon2iMod, "old-password", "", false)
	require.NoError(t, err)

	// Add some data
	session, err := s.Session("")
	require.NoError(t, err)
	err = session.Insert("test", "entry", []byte("value"), nil)
	require.NoError(t, err)
	session.Close()

	// Rekey with new password
	err = s.Rekey(enums.KdfArgon2iMod, "new-password")
	require.NoError(t, err)
	s.Close()

	// Try opening with old password (should fail)
	s, err = store.Open(uri, enums.KdfArgon2iMod, "old-password", "")
	assert.Error(t, err)

	// Open with new password (should succeed)
	s, err = store.Open(uri, enums.KdfArgon2iMod, "new-password", "")
	require.NoError(t, err)
	defer s.Close()

	// Verify data is still there
	session, err = s.Session("")
	require.NoError(t, err)
	defer session.Close()

	entry, err := session.Fetch("test", "entry", false)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	assert.Equal(t, []byte("value"), entry.Value)
}

func TestStoreRemove(t *testing.T) {
	dbPath := getTempDBPath(t)
	uri := fmt.Sprintf("sqlite://%s", dbPath)

	// Create store
	s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
	require.NoError(t, err)
	s.Close()

	// Remove store
	err = store.Remove(uri)
	require.NoError(t, err)

	// Try to open removed store (should fail)
	s, err = store.Open(uri, enums.KdfArgon2iMod, "password", "")
	assert.Error(t, err)
}