//go:build (e2e && sechub) || e2e

package sechub

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
	secretstoresmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"
	syncpolicy "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies"
	syncpoliciesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

const (
	e2eSyncPolicyTargetStoreName        = "e2e-sync-policy-target-store"
	e2eSyncPolicyTargetStoreDescription = "E2E test sync policy target store"
	e2eSyncPolicyStoreType              = "AWS_ASM"
	e2eSyncPolicyAccountAlias           = "test-account-alias"
	e2eSyncPolicyRegionID               = "eu-north-1"
	e2eSyncPolicyRoleName               = "TestSecretsAccessRole"
	e2eSyncPolicyAuthMethod             = "GLOBAL_ROLE_EXTERNAL_ID"
	e2eSyncPolicySafeType               = "PAM_SAFE"
)

func TestCreateAndDeleteSyncPolicy(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete Sync Policy")
		err, _ := setUpSyncPolicy(ctx, t)
		require.NoError(t, err, "Failed to set up sync policy")
	}, syncpolicy.ServiceConfig)
}

func DeleteSyncPolicyWithSateAlreadyDisabledStillDeletesThePolicy(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete Sync Policy That Is already Disabled")
		syncPolicySvc, err := ctx.API.SechubSyncpolicies()
		err, syncPolicy := setUpSyncPolicy(ctx, t)
		state := syncpoliciesmodels.IdsecSecHubSetSyncPolicyState{
			PolicyID: syncPolicy.ID,
			Action:   "disable",
		}
		t.Logf("Step 2: Setting sync policy state to disabled")
		err = syncPolicySvc.SetState(&state)

		require.NoError(t, err, "Failed to disable sync policy")

		t.Logf("Step 3: Deleting sync policy that is already disabled")
		// Now delete the sync policy already in disabled state
		err = syncPolicySvc.Delete(&syncpoliciesmodels.IdsecSecHubDeleteSyncPolicy{
			PolicyID: syncPolicy.ID,
		})

		// Verify sync policy no longer exists by getting it
		t.Log("Step 4: Verifying sync policy no longer exists...")
		_, err = syncPolicySvc.Get(&syncpoliciesmodels.IdsecSecHubGetSyncPolicy{
			PolicyID: syncPolicy.ID,
		})

		require.Error(t, err, "Expected error when fetching a deleted policy, but got none")
		require.Contains(t, err.Error(), "404", "Expected 'not found' error, but got: %s", err.Error())

	}, syncpolicy.ServiceConfig)

}

func TestUpdateSyncPolicyThrowsAnError(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		// Get the SecHub SecretStores service
		syncPolicySvc, err := ctx.API.SechubSyncpolicies()
		require.NoError(t, err)
		_, err = syncPolicySvc.Update(&syncpoliciesmodels.IdsecSecHubUpdateSyncPolicy{
			ID: "1234",
		})
		require.Error(t, err, "Expected error when updating sync policy, but got none")
		require.Contains(t, err.Error(), "updating the sync policy is not supported through terraform", "Expected 'operation not supported' error, but got: %s", err.Error())
	}, syncpolicy.ServiceConfig)
}

func TestListSyncPolicies(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: List Sync Policies")

		syncPolicySvc, err := ctx.API.SechubSyncpolicies()
		require.NoError(t, err, "Failed to create api service")

		// Create a sync policy so we have at least one to list
		err, createdPolicy := setUpSyncPolicy(ctx, t)
		require.NoError(t, err, "Failed to set up sync policy")

		// List all sync policies and verify the created one is present
		t.Log("Listing all sync policies...")
		policiesChan, err := syncPolicySvc.List(&syncpoliciesmodels.IdsecSecHubGetSyncPolicies{
			Projection: "REGULAR",
		})
		require.NoError(t, err, "Failed to list sync policies")

		var allPolicies []*syncpoliciesmodels.IdsecSecHubPolicy
		for page := range policiesChan {
			allPolicies = append(allPolicies, page.Items...)
		}

		require.Greater(t, len(allPolicies), 0, "Expected at least one sync policy in the list")

		var retrievedSyncPolicy *syncpoliciesmodels.IdsecSecHubPolicy
		for _, p := range allPolicies {
			if p.ID == createdPolicy.ID {
				retrievedSyncPolicy = p
				break
			}
		}
		require.NotNil(t, retrievedSyncPolicy, "Created sync policy %s not found in list results", createdPolicy.ID)

		assert.Equal(t, createdPolicy.Name, retrievedSyncPolicy.Name)
		assert.Equal(t, createdPolicy.ID, retrievedSyncPolicy.ID)
		assert.Equal(t, createdPolicy.Description, retrievedSyncPolicy.Description)
		assert.Equal(t, createdPolicy.Source.ID, retrievedSyncPolicy.Source.ID)
		assert.Equal(t, createdPolicy.Target.ID, retrievedSyncPolicy.Target.ID)
		assert.Equal(t, createdPolicy.Filter.Type, retrievedSyncPolicy.Filter.Type)
		assert.Equal(t, createdPolicy.Filter.Data.SafeName, retrievedSyncPolicy.Filter.Data.SafeName)
		assert.Equal(t, createdPolicy.Transformation.Predefined, retrievedSyncPolicy.Transformation.Predefined)

		t.Log("List sync policies test completed successfully")
	}, syncpolicy.ServiceConfig)
}

func TestSyncPolicyLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create, Get and Delete Sync Policy")
		syncPolicySvc, err := ctx.API.SechubSyncpolicies()

		// Get the tenant pcloud source store
		err, syncPolicy := setUpSyncPolicy(ctx, t)

		// Verify sync policy exists by getting it
		t.Log("Step 2: Verifying sync policy exists...")
		retrievedSyncPolicy, err := syncPolicySvc.Get(&syncpoliciesmodels.IdsecSecHubGetSyncPolicy{
			PolicyID: syncPolicy.ID,
		})
		require.NoError(t, err, "Failed to retrieve sync policy")
		assert.Equal(t, syncPolicy.Name, retrievedSyncPolicy.Name)
		assert.Equal(t, syncPolicy.ID, retrievedSyncPolicy.ID)
		assert.Equal(t, syncPolicy.Description, retrievedSyncPolicy.Description)
		assert.Equal(t, syncPolicy.Source.ID, retrievedSyncPolicy.Source.ID)
		assert.Equal(t, syncPolicy.Target.ID, retrievedSyncPolicy.Target.ID)
		assert.Equal(t, syncPolicy.Filter.Type, retrievedSyncPolicy.Filter.Type)
		assert.Equal(t, syncPolicy.Filter.Data.SafeName, retrievedSyncPolicy.Filter.Data.SafeName)
		assert.Equal(t, syncPolicy.Transformation.Predefined, retrievedSyncPolicy.Transformation.Predefined)

	}, syncpolicy.ServiceConfig)
}

func setUpSyncPolicy(ctx *framework.TestContext, t *testing.T) (error, *syncpoliciesmodels.IdsecSecHubPolicy) {
	sourceId := getSourceStoreID(t, ctx, "PAM_PCLOUD")
	// Create or get a secret store target

	data := secretstoresmodels.IdsecSecHubCreateSecretStoreData{
		AccountAlias:         e2eSyncPolicyAccountAlias,
		AccountID:            randomAWSAccountID(),
		RegionID:             e2eSyncPolicyRegionID,
		RoleName:             e2eSyncPolicyRoleName,
		AuthenticationMethod: e2eSyncPolicyAuthMethod,
	}
	targetStore := creteSecretStoreResourceForTest(t,
		ctx,
		e2eSyncPolicyTargetStoreName,
		e2eSyncPolicyTargetStoreDescription,
		e2eSyncPolicyStoreType,
		data)
	// Create safe for the filter object
	safeName := createTestSafeWithSecretsHubAsMemberForSyncPolicy(t, ctx, "Test Safe for sync policy")
	// Create a sync policy with unique name
	syncPolicyName := framework.RandomResourceName("e2e-sync-policy")
	t.Logf("Creating sync policy: %s", syncPolicyName)
	syncPolicySvc, err := ctx.API.SechubSyncpolicies()
	require.NoError(t, err, "Failed to create api service")

	// Create the sync policy per https://api-docs.cyberark.com/secretshub-api/docs/secrets-hub-api#/Sync%20Policies/policy-create-api-policies-post
	syncPolicy, err := syncPolicySvc.Create(&syncpoliciesmodels.IdsecSechubCreateSyncPolicy{
		Name:        syncPolicyName,
		Description: "E2E test sync policy",
		Source: syncpoliciesmodels.IdsecSecHubPolicyStore{
			ID: sourceId,
		},
		Target: syncpoliciesmodels.IdsecSecHubPolicyStore{
			ID: targetStore.ID,
		},
		Filter: syncpoliciesmodels.IdsecSecHubPolicyFilter{
			Data: syncpoliciesmodels.IdsecSechubSyncPolicyFilterData{
				SafeName: safeName.SafeName,
			},
			Type: e2eSyncPolicySafeType,
		},
		Transformation: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
			Predefined: "password_only_plain_text",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, syncPolicy)
	t.Logf("Step 1: Created sync policy with ID: %s", syncPolicy.ID)

	// Register cleanup
	ctx.TrackResourceByType("SyncPolicy", syncPolicy.ID, func() error {
		t.Logf("Finally: Cleaning up sync policy: %s", syncPolicy.ID)
		time.Sleep(10 * time.Second)
		err := syncPolicySvc.Delete(&syncpoliciesmodels.IdsecSecHubDeleteSyncPolicy{
			PolicyID: syncPolicy.ID,
		})
		// Ignore 404 — policy may have already been deleted by the test see DeleteSyncPolicyWithSateAlreadyDisabledStillDeletesThePolicy
		if err != nil && strings.Contains(err.Error(), "404") {
			t.Logf("Sync policy %s already deleted, skipping cleanup", syncPolicy.ID)
			return nil
		}
		return err
	})
	return err, syncPolicy
}

func getSourceStoreID(t *testing.T, ctx *framework.TestContext, st string) string {
	// Get the SecHub SecretStores service
	secretStoresSvc, err := ctx.API.SechubSecretstores()
	require.NoError(t, err)

	srcStoresChan, err := secretStoresSvc.ListBy(&secretstoresmodels.IdsecSecHubSecretStoresFilters{
		Behavior: "SECRETS_SOURCE",
		Filters:  fmt.Sprintf("type EQ %s", st),
	})

	// Read only the first page from the channel
	firstPage, ok := <-srcStoresChan
	require.True(t, ok, "Expected at least one page of source secret stores")
	require.Greater(t, len(firstPage.Items), 0, "At least one source secret store is required for sync policy tests")

	// Drain the remaining pages to avoid leaking the producer goroutine
	for range srcStoresChan {
	}

	// Register cleanup not needed as we don't want to remove pcloud sec store
	return firstPage.Items[0].ID
}

// createTestSafeWithSecretsHubAsMemberForSyncPolicy creates a safe with the given description and registers automatic cleanup.
// It also adds the "SecretsHub" user as a member with specific permissions required for sync policy operations.
// The safe name is generated randomly to ensure uniqueness.
func createTestSafeWithSecretsHubAsMemberForSyncPolicy(t *testing.T, ctx *framework.TestContext, description string) *safesmodels.IdsecPCloudSafe {

	safesSvc, err := ctx.API.PcloudSafes()
	require.NoError(t, err, "Failed to get PCloud Safes service")

	safeName := framework.RandomResourceName("e2e-sync-policy")
	t.Logf("Creating test safe: %s", safeName)

	safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
		SafeName:    safeName,
		Description: description,
	})
	require.NoError(t, err, "Failed to create test safe")

	//Add Secrets Hub as a member or else the sync policy creation fails as both the user and sechub need
	//"List Safe Members" permission on the Safe.
	_, addErr := safesSvc.AddMember(&safesmodels.IdsecPCloudAddSafeMember{
		SafeID:        safe.SafeID,
		MemberName:    "SecretsHub",
		MemberType:    "User",
		PermissionSet: safesmodels.Custom,
		Permissions: &safesmodels.IdsecPCloudSafeMemberPermissions{
			ListAccounts:              true,
			ViewSafeMembers:           true,
			AccessWithoutConfirmation: true,
			RetrieveAccounts:          true,
		},
	})
	require.NoError(t, addErr, "Failed to add Secrets Hub as member to the safe")

	//No need to delete the Secrets Hub user resource
	t.Log("Added Secrets Hub as member member ...")

	//Register cleanup for safe
	ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
		return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
			SafeID: safe.SafeID,
		})
	})

	return safe
}
