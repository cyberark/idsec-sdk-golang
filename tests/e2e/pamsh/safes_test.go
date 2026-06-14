//go:build (e2e && pamsh) || e2e

package pamsh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pamshsafes "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestCreateAndUpdateSafes verifies that pamsh can create a safe, update it, and read it back via Get.
func TestCreateAndUpdateSafes(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create, Update, and Get pamsh Safes")

		safesSvc := pamshSafesService(t, ctx)
		safe := createPamshTestSafe(t, ctx, "E2E PAMSH safe create/update", "e2e-pamsh-safe")
		t.Logf("Step 1: Safe created: %s (ID: %s)", safe.SafeName, safe.SafeID)

		updatedDescription := "E2E PAMSH safe updated description"
		t.Logf("Step 2: Updating safe %q description", safe.SafeID)
		updatedSafe, err := safesSvc.Update(&safesmodels.IdsecPamshUpdateSafe{
			SafeID:      safe.SafeID,
			SafeName:    safe.SafeName,
			Description: updatedDescription,
		})
		require.NoError(t, err, "Failed to update pamsh safe")
		require.NotNil(t, updatedSafe)
		assert.Equal(t, updatedDescription, updatedSafe.Description)

		t.Logf("Step 3: Reading safe %q after update", safe.SafeID)
		retrieved, err := safesSvc.Get(&safesmodels.IdsecPamshGetSafe{SafeID: safe.SafeID})
		require.NoError(t, err, "Failed to get pamsh safe after update")
		require.NotNil(t, retrieved)
		assert.Equal(t, safe.SafeID, retrieved.SafeID)
		assert.Equal(t, safe.SafeName, retrieved.SafeName)
		assert.Equal(t, updatedDescription, retrieved.Description)
	}, pamshsafes.ServiceConfig)
}
