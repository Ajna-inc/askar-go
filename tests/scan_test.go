package tests

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanOperations(t *testing.T) {
	t.Run("Basic Scan", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert test data
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("entry-%d", i)
			value := []byte(fmt.Sprintf("value-%d", i))
			tags := map[string]interface{}{
				"index": json.Number(fmt.Sprintf("%d", i)),
				"type":  "test",
			}
			err = session.Insert("scan-test", name, value, tags)
			require.NoError(t, err)
		}
		session.Close()
		
		// Start scan
		scan, err := s.StartScan("", "scan-test", nil, 0, -1)
		require.NoError(t, err)
		require.NotNil(t, scan)
		defer scan.Close()
		
		// Get all entries
		allEntries, err := scan.CollectAll()
		require.NoError(t, err)
		assert.Len(t, allEntries, 10)
		
		// Verify entries
		for _, entry := range allEntries {
			assert.Equal(t, "scan-test", entry.Category)
			assert.Contains(t, entry.Name, "entry-")
			assert.Contains(t, string(entry.Value), "value-")
		}
	})
	
	t.Run("Scan with Limit", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert test data
		for i := 0; i < 20; i++ {
			name := fmt.Sprintf("item-%d", i)
			value := []byte(fmt.Sprintf("data-%d", i))
			err = session.Insert("limited", name, value, nil)
			require.NoError(t, err)
		}
		session.Close()
		
		// Scan with limit
		scan, err := s.StartScan("", "limited", nil, 0, 5)
		require.NoError(t, err)
		defer scan.Close()
		
		entries, err := scan.CollectAll()
		require.NoError(t, err)
		assert.LessOrEqual(t, len(entries), 5)
	})
	
	t.Run("Scan with Offset", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert numbered entries
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("num-%03d", i) // Padded for consistent ordering
			value := []byte(fmt.Sprintf("%d", i))
			err = session.Insert("offset-test", name, value, nil)
			require.NoError(t, err)
		}
		session.Close()
		
		// Scan with offset
		scan, err := s.StartScan("", "offset-test", nil, 5, -1)
		require.NoError(t, err)
		defer scan.Close()
		
		entries, err := scan.CollectAll()
		require.NoError(t, err)
		assert.LessOrEqual(t, len(entries), 5)
	})
	
	t.Run("Scan with Tag Filter", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert entries with different tags
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("tagged-%d", i)
			value := []byte(fmt.Sprintf("value-%d", i))
			tags := map[string]interface{}{
				"color": map[string]interface{}{
					"$in": []string{"red", "blue", "green"}[i%3],
				},
				"number": json.Number(fmt.Sprintf("%d", i)),
			}
			if i%2 == 0 {
				tags["even"] = true
			}
			err = session.Insert("tagged", name, value, tags)
			require.NoError(t, err)
		}
		session.Close()
		
		// Scan with tag filter
		tagFilter := map[string]interface{}{
			"even": true,
		}
		
		scan, err := s.StartScan("", "tagged", tagFilter, 0, -1)
		require.NoError(t, err)
		defer scan.Close()
		
		entries, err := scan.CollectAll()
		require.NoError(t, err)
		
		// Should only get even entries
		for _, entry := range entries {
			assert.Contains(t, entry.Tags, "even")
			assert.Equal(t, true, entry.Tags["even"])
		}
	})
	
	t.Run("Scan Iteration", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert test data
		for i := 0; i < 15; i++ {
			name := fmt.Sprintf("iter-%d", i)
			value := []byte(fmt.Sprintf("val-%d", i))
			err = session.Insert("iteration", name, value, nil)
			require.NoError(t, err)
		}
		session.Close()
		
		// Start scan with small batch size
		scan, err := s.StartScan("", "iteration", nil, 0, 3)
		require.NoError(t, err)
		defer scan.Close()
		
		// Iterate through entries
		count := 0
		err = scan.Iterate(func(entry *store.Entry) error {
			count++
			assert.Equal(t, "iteration", entry.Category)
			assert.Contains(t, entry.Name, "iter-")
			return nil
		})
		require.NoError(t, err)
		assert.LessOrEqual(t, count, 3) // Should respect limit
	})
	
	t.Run("Scan Next", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert test data
		for i := 0; i < 25; i++ {
			name := fmt.Sprintf("batch-%d", i)
			value := []byte(fmt.Sprintf("data-%d", i))
			err = session.Insert("batch-test", name, value, nil)
			require.NoError(t, err)
		}
		session.Close()
		
		// Start scan
		scan, err := s.StartScan("", "batch-test", nil, 0, 10)
		require.NoError(t, err)
		defer scan.Close()
		
		// Get first batch
		batch1, err := scan.Next()
		require.NoError(t, err)
		assert.NotNil(t, batch1)
		assert.LessOrEqual(t, len(batch1), 10)
		
		// Try to get next batch (should be nil since we limited to 10)
		batch2, err := scan.Next()
		require.NoError(t, err)
		assert.Nil(t, batch2)
	})
	
	t.Run("Empty Scan", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		// Scan empty category
		scan, err := s.StartScan("", "empty-category", nil, 0, -1)
		require.NoError(t, err)
		defer scan.Close()
		
		entries, err := scan.CollectAll()
		require.NoError(t, err)
		assert.Len(t, entries, 0)
	})
	
	t.Run("Scan with Complex Filter", func(t *testing.T) {
		dbPath := getTempDBPath(t)
		uri := fmt.Sprintf("sqlite://%s", dbPath)
		
		s, err := store.Provision(uri, enums.KdfArgon2iMod, "password", "", false)
		require.NoError(t, err)
		defer s.Close()
		
		session, err := s.Session("")
		require.NoError(t, err)
		
		// Insert entries with complex tags
		for i := 0; i < 20; i++ {
			name := fmt.Sprintf("complex-%d", i)
			value := []byte(fmt.Sprintf("data-%d", i))
			tags := map[string]interface{}{
				"department": []string{"eng", "sales", "hr", "finance"}[i%4],
				"level":      json.Number(fmt.Sprintf("%d", i%5)),
				"active":     i%3 != 0,
			}
			err = session.Insert("complex", name, value, tags)
			require.NoError(t, err)
		}
		session.Close()
		
		// Complex filter
		filter := map[string]interface{}{
			"department": map[string]interface{}{
				"$in": []string{"eng", "sales"},
			},
			"active": true,
		}
		
		scan, err := s.StartScan("", "complex", filter, 0, -1)
		require.NoError(t, err)
		defer scan.Close()
		
		entries, err := scan.CollectAll()
		require.NoError(t, err)
		
		// Verify filter worked
		for _, entry := range entries {
			dept := entry.Tags["department"].(string)
			assert.True(t, dept == "eng" || dept == "sales")
			assert.Equal(t, true, entry.Tags["active"])
		}
	})
}