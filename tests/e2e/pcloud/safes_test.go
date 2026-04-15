//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	safes "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestListSafes verifies that we can successfully list PCloud safes.
// This is a basic smoke test that validates connectivity to PCloud.
func TestListSafes(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: List PCloud Safes")

		// Get the PCloud Safes service
		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err, "Failed to get PCloud Safes service")

		// List safes
		t.Log("Listing PCloud safes...")
		safesChan, err := safesSvc.List()
		require.NoError(t, err, "Failed to list safes")

		// Count safes
		safeCount := 0
		for page := range safesChan {
			safeCount += len(page.Items)
			if len(page.Items) > 0 && safeCount <= 5 {
				// Log first few safes for visibility
				for _, safe := range page.Items {
					t.Logf("  Safe: %s (ID: %s)", safe.SafeName, safe.SafeID)
				}
			}
		}

		t.Logf("Found %d safe(s)", safeCount)
		assert.NotNil(t, safesChan, "Safes channel should not be nil")
	}, safes.ServiceConfig)
}

// TestCreateAndDeleteSafe is a quick smoke test for basic safe operations.
// It tests only Create and Get operations, with Delete handled via automatic cleanup.
// For comprehensive CRUD testing including Update, see TestSafeLifecycle.
func TestCreateAndDeleteSafe(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete Safe")

		// Get the PCloud Safes service
		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		// Create a safe with unique name
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Creating safe: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "E2E test safe",
		})
		require.NoError(t, err, "Failed to create safe")
		require.NotNil(t, safe)
		assert.Equal(t, safeName, safe.SafeName)

		t.Logf("Safe created successfully: %s (ID: %s)", safe.SafeName, safe.SafeID)

		// Register cleanup
		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			t.Logf("Cleaning up safe: %s", safe.SafeName)
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// Verify safe exists by getting it
		t.Log("Verifying safe exists...")
		retrievedSafe, err := safesSvc.Get(&safesmodels.IdsecPCloudGetSafe{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err, "Failed to retrieve safe")
		assert.Equal(t, safe.SafeName, retrievedSafe.SafeName)
		assert.Equal(t, safe.SafeID, retrievedSafe.SafeID)

		t.Log("Safe verified successfully")
	}, safes.ServiceConfig)
}

// TestSafeLifecycle tests the complete CRUD lifecycle: Create -> Get -> Update -> Delete.
// This is a comprehensive test that exercises all safe operations in sequence.
// For a quick smoke test of basic operations, see TestCreateAndDeleteSafe.
func TestSafeLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Safe Lifecycle (CRUD)")

		// Get the PCloud Safes service
		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		// 1. CREATE
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Step 1: Creating safe: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "Initial description",
		})
		require.NoError(t, err, "Failed to create safe")
		require.NotNil(t, safe)

		t.Logf("Safe created: %s", safe.SafeName)

		// Register cleanup
		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// 2. READ
		t.Logf("Step 2: Reading safe: %s", safe.SafeID)
		retrievedSafe, err := safesSvc.Get(&safesmodels.IdsecPCloudGetSafe{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err, "Failed to retrieve safe")
		assert.Equal(t, safe.SafeName, retrievedSafe.SafeName)
		assert.Equal(t, "Initial description", retrievedSafe.Description)

		// 3. UPDATE
		t.Logf("Step 3: Updating safe: %s", safe.SafeID)
		updatedDescription := "Updated description"
		updatedSafe, err := safesSvc.Update(&safesmodels.IdsecPCloudUpdateSafe{
			SafeID:      safe.SafeID,
			SafeName:    safe.SafeName, // Required by API even though we're updating by ID
			Description: updatedDescription,
		})
		require.NoError(t, err, "Failed to update safe")
		assert.Equal(t, updatedDescription, updatedSafe.Description)

		// Verify update
		retrievedSafe, err = safesSvc.Get(&safesmodels.IdsecPCloudGetSafe{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err, "Failed to retrieve updated safe")
		assert.Equal(t, updatedDescription, retrievedSafe.Description)

		t.Log("Safe lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, safes.ServiceConfig)
}

// TestSafeWithCustomSettings tests creating a safe with custom retention settings.
func TestSafeWithCustomSettings(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Safe with Custom Settings")

		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Creating safe with custom settings: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:              safeName,
			Description:           "Safe with custom retention",
			NumberOfDaysRetention: intPtr(30),
		})
		require.NoError(t, err, "Failed to create safe")
		require.NotNil(t, safe)

		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// Verify settings
		retrievedSafe, err := safesSvc.Get(&safesmodels.IdsecPCloudGetSafe{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err)
		assert.Equal(t, 30, retrievedSafe.NumberOfDaysRetention)

		t.Log("Safe with custom settings created successfully")
	}, safes.ServiceConfig)
}
