//go:build (e2e && sechub) || e2e

package sechub

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretstores "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores"
	secretstoresmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

const (
	e2eSecretStoreNamePrefix = "e2e-secret-store"
)

func TestCreateAndDeleteAWSSecretStore(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete SecretStore AWS")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"E2E test secret store",
			"AWS_ASM",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				AccountAlias:         "test-account-alias",
				AccountID:            randomAWSAccountID(),
				RegionID:             "eu-north-1",
				RoleName:             "TestSecretsAccessRole",
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)

		// Verify secret store exists by getting it
		t.Log("Verifying secret store exists...")
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secretStore")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, secretStore.ID, retrievedSecretStore.ID)

		t.Log("SecretStore verified successfully")
	}, secretstores.ServiceConfig)
}

func TestCreateAndDeleteAzureSecretStore(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete SecretStore Azure")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"E2E test secret store (Azure)",
			"AZURE_AKV",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				AppClientDirectoryID: "c389961d-a0cd-46ab-9f69-877f756a59c1",
				AzureVaultURL:        randomAzureKeyVaultURL(),
				AppClientID:          "11111111-2222-3333-4444-555555555555",
				SubscriptionID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				SubscriptionName:     "test-subscription-name",
				ResourceGroupName:    "test-resource-group_01",
				ConnectionConfig: &secretstoresmodels.IdsecSecHubCreateSecretStoreConnectionConfig{
					ConnectionType: "PUBLIC",
				},
				AuthenticationMethod: "FEDERATED_IDENTITY",
			})

		// Verify secret store exists by getting it
		t.Log("Verifying secret store exists...")
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secretStore")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, secretStore.ID, retrievedSecretStore.ID)

		t.Log("SecretStore verified successfully")
	}, secretstores.ServiceConfig)
}

func TestCreateAndDeleteGCPSecretStore(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete SecretStore GCP")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"E2E test secret store (GCP)",
			"GCP_GSM",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				GcpProjectName:   "gcp-project-name-example",
				GcpProjectNumber: randomGCPProjectNumber(),
				GcpAuthentication: &secretstoresmodels.IdsecSecHubSecretStoreGcpAuthentication{
					GcpProjectNumber:          randomGCPProjectNumber(),
					GcpWorkloadIdentityPoolID: "gcp-pool-id-example",
					GcpPoolProviderID:         "gcp-provider-id-example",
					ServiceAccountEmail:       "svcacct1@exampleproj.iam.gserviceaccount.com",
					AuthenticationMethod:      "GLOBAL_ROLE_EXTERNAL_ID",
				},
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)
		// Verify secret store exists by getting it
		t.Log("Verifying secret store exists...")
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secretStore")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, secretStore.ID, retrievedSecretStore.ID)

		t.Log("SecretStore verified successfully")
	}, secretstores.ServiceConfig)
}

// TestSecretStoreLifecycleAWS tests the complete CRUD lifecycle: Create -> Get -> Update -> Delete.
// This is a comprehensive test that exercises all secret store operations in sequence.
func TestSecretStoreLifecycleAWS(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Secret Store Lifecycle (CRUD)")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		//	1. CREATE

		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"Initial description",
			"AWS_ASM",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				AccountAlias:         "test-account-alias",
				AccountID:            randomAWSAccountID(),
				RegionID:             "eu-north-1",
				RoleName:             "TestSecretsAccessRole",
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)
		// 2. READ
		t.Logf("Step 2: Reading secret store: %s", secretStore.ID)
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, "Initial description", retrievedSecretStore.Description)

		// 3. UPDATE
		t.Logf("Step 3: Updating secret store: %s", secretStore.ID)
		updatedDescription := "Updated description"
		updatedRoleName := "TestSecretsAccessRoleUpdated"
		updatedSecretStore, err := secretStoresSvc.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescription,
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				AccountAlias:         "test-account-alias",
				RoleName:             updatedRoleName,
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			},
		})
		require.NoError(t, err, "Failed to update secret store")
		assert.Equal(t, updatedDescription, updatedSecretStore.Description)

		// Verify update
		retrievedSecretStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve updated secret sore")
		assert.Equal(t, updatedDescription, retrievedSecretStore.Description)

		t.Log("SecretStore lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, secretstores.ServiceConfig)
}

// TestSecretStoreUpdateTFLifecycle tests the UpdateTF method which combines field updates and state changes.
// Flow: Create -> UpdateTF (fields only, same state) -> Verify
// -> UpdateTF (fields + disable) -> Verify -> UpdateTF (re-enable)
// -> Verify -> Delete.
func TestSecretStoreUpdateTFLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Secret Store UpdateTF Lifecycle")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		// 1. CREATE
		secretStore := creteSecretStoreResourceForTest(t,
			ctx,
			e2eSecretStoreNamePrefix,
			"Initial TF description",
			"AWS_ASM",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				AccountAlias:         "test-account-alias",
				AccountID:            randomAWSAccountID(),
				RegionID:             "eu-north-1",
				RoleName:             "TestSecretsAccessRole",
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			})

		t.Logf("SecretStore created successfully: %s (ID: %s, State: %s)", secretStore.Name, secretStore.ID, secretStore.State)

		// 2. UpdateTF - update fields only, keep the same state (no SetState call expected)
		t.Log("Step 2: UpdateTF - fields only, same state")
		updatedDescriptionV1 := "Updated TF description v1"
		updatedRoleNameV1 := "TestSecretsAccessRoleUpdatedV1"
		updatedStore, err := secretStoresSvc.UpdateTf(&secretstoresmodels.IdsecSecHubUpdateTfSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescriptionV1,
			State:       secretStore.State, // same state as current — no state change
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				AccountAlias:         "test-account-alias",
				RoleName:             updatedRoleNameV1,
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			},
		})
		require.NoError(t, err, "Failed to UpdateTF (fields only)")
		assert.Equal(t, updatedDescriptionV1, updatedStore.Description)

		// Verify via GET
		retrievedStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store after UpdateTF fields-only")
		assert.Equal(t, updatedDescriptionV1, retrievedStore.Description)
		assert.Equal(t, secretStore.State, retrievedStore.State, "State should remain unchanged")

		// 3. UpdateTF - update fields and change state to DISABLED
		t.Log("Step 3: UpdateTF - fields + disable state")
		updatedDescriptionV2 := "Updated TF description v2"
		updatedStore, err = secretStoresSvc.UpdateTf(&secretstoresmodels.IdsecSecHubUpdateTfSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescriptionV2,
			State:       "DISABLED",
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				AccountAlias:         "test-account-alias",
				RoleName:             updatedRoleNameV1,
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			},
		})
		require.NoError(t, err, "Failed to UpdateTF (disable)")
		assert.Equal(t, updatedDescriptionV2, updatedStore.Description)
		assert.Equal(t, "DISABLED", updatedStore.State)

		// Verify via GET
		retrievedStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store after UpdateTF disable")
		assert.Equal(t, updatedDescriptionV2, retrievedStore.Description)
		assert.Equal(t, "DISABLED", retrievedStore.State)

		// 4. UpdateTF - re-enable the secret store
		t.Log("Step 4: UpdateTF - re-enable state")
		updatedStore, err = secretStoresSvc.UpdateTf(&secretstoresmodels.IdsecSecHubUpdateTfSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescriptionV2,
			State:       "ENABLED",
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				AccountAlias:         "test-account-alias",
				RoleName:             updatedRoleNameV1,
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			},
		})
		require.NoError(t, err, "Failed to UpdateTF (re-enable)")
		assert.Equal(t, "ENABLED", updatedStore.State)

		// Verify via GET
		retrievedStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store after UpdateTF re-enable")
		assert.Equal(t, "ENABLED", retrievedStore.State)

		t.Log("SecretStore UpdateTF lifecycle completed successfully")
		// 5. DELETE happens automatically via cleanup
	}, secretstores.ServiceConfig)
}

// TestSecretStoreLifecycleGCP tests the complete CRUD lifecycle for a GCP secret store: Create -> Get -> Update -> Delete.
// This is a comprehensive test that exercises all GCP secret store operations in sequence.
func TestSecretStoreLifecycleGCP(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Secret Store Lifecycle (CRUD)")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		//	1. CREATE

		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"Initial description",
			"GCP_GSM",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				GcpProjectName:   "gcp-project-name-example",
				GcpProjectNumber: randomGCPProjectNumber(),
				GcpAuthentication: &secretstoresmodels.IdsecSecHubSecretStoreGcpAuthentication{
					GcpProjectNumber:          randomGCPProjectNumber(),
					GcpWorkloadIdentityPoolID: "gcp-pool-id-example",
					GcpPoolProviderID:         "gcp-provider-id-example",
					ServiceAccountEmail:       "svcacct1@exampleproj.iam.gserviceaccount.com",
					AuthenticationMethod:      "GLOBAL_ROLE_EXTERNAL_ID",
				},
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)
		// 2. READ
		t.Logf("Step 2: Reading secret store: %s", secretStore.ID)
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, "Initial description", retrievedSecretStore.Description)

		// 3. UPDATE
		t.Logf("Step 3: Updating secret store: %s", secretStore.ID)
		updatedDescription := "Updated description"
		updatedProjectName := "gcp-project-name-updated"
		updatedSecretStore, err := secretStoresSvc.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescription,
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				GcpProjectName: updatedProjectName,

				GcpAuthentication: &secretstoresmodels.IdsecSecHubSecretStoreGcpAuthentication{
					GcpProjectNumber:          randomGCPProjectNumber(),
					GcpWorkloadIdentityPoolID: "gcp-pool-id-updated",
					GcpPoolProviderID:         "gcp-provider-id-updated",
					ServiceAccountEmail:       "svcacct2@exampleproj.iam.gserviceaccount.com",
					AuthenticationMethod:      "GLOBAL_ROLE_EXTERNAL_ID",
				},
			},
		})
		require.NoError(t, err, "Failed to update secret store")
		assert.Equal(t, updatedDescription, updatedSecretStore.Description)

		// Verify update
		retrievedSecretStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve updated secret sore")
		assert.Equal(t, updatedDescription, retrievedSecretStore.Description)

		t.Log("SecretStore lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, secretstores.ServiceConfig)
}

func TestSecretStoreLifecycleHashi(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Secret Store Lifecycle HashiCorp Vault (CRUD)")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		// 1. CREATE
		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"Initial description",
			"HASHICORP_VAULT",
			secretstoresmodels.IdsecSecHubCreateSecretStoreData{
				HashiVaultURL:      randomHashiVaultURL(),
				MountPath:          "secret",
				RoleName:           "secrets-hub-role",
				AuthenticationPath: "auth/jwt/login",
				ConnectionConfig: &secretstoresmodels.IdsecSecHubCreateSecretStoreConnectionConfig{
					ConnectionType: "PUBLIC",
				},
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)

		// 2. READ
		t.Logf("Step 2: Reading secret store: %s", secretStore.ID)
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, "Initial description", retrievedSecretStore.Description)

		// 3. UPDATE
		t.Logf("Step 3: Updating secret store: %s", secretStore.ID)
		updatedDescription := "Updated description"
		updatedRoleName := "secrets-hub-role-updated"
		updatedSecretStore, err := secretStoresSvc.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescription,
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				RoleName:           updatedRoleName,
				AuthenticationPath: "auth/jwt/login",
			},
		})
		require.NoError(t, err, "Failed to update secret store")
		assert.Equal(t, updatedDescription, updatedSecretStore.Description)

		// Verify update
		retrievedSecretStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve updated secret store")
		assert.Equal(t, updatedDescription, retrievedSecretStore.Description)

		t.Log("SecretStore lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, secretstores.ServiceConfig)
}
