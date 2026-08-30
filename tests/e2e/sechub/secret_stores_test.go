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
			secretstoresmodels.IdsecSecHubSecretStoreData{
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
			secretstoresmodels.IdsecSecHubSecretStoreData{
				AppClientDirectoryID: "c389961d-a0cd-46ab-9f69-877f756a59c1",
				AzureVaultURL:        randomAzureKeyVaultURL(),
				AppClientID:          "11111111-2222-3333-4444-555555555555",
				SubscriptionID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				SubscriptionName:     "test-subscription-name",
				ResourceGroupName:    "test-resource-group_01",
				ConnectionConfig: &secretstoresmodels.IdsecSecHubSecretStoreConnectionConfig{
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
			secretstoresmodels.IdsecSecHubSecretStoreData{
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
			secretstoresmodels.IdsecSecHubSecretStoreData{
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
			secretstoresmodels.IdsecSecHubSecretStoreData{
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
			secretstoresmodels.IdsecSecHubSecretStoreData{
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

// TestSecretStoreUpdateAuthenticationMethodAWS tests that the AuthenticationMethod field
// can be updated from TENANT_ROLE to GLOBAL_ROLE_EXTERNAL_ID on an AWS secret store.
func TestSecretStoreUpdateAuthenticationMethodAWS(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Update AuthenticationMethod TENANT_ROLE -> GLOBAL_ROLE_EXTERNAL_ID (AWS)")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		// 1. CREATE
		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"AuthMethod transition test",
			"AWS_ASM",
			secretstoresmodels.IdsecSecHubSecretStoreData{
				AccountAlias:         "test-account-alias",
				AccountID:            randomAWSAccountID(),
				RegionID:             "eu-north-1",
				RoleName:             "TestSecretsAccessRole",
				AuthenticationMethod: "TENANT_ROLE",
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)

		// 2. READ
		t.Logf("Step 2: Reading secret store: %s", secretStore.ID)
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, "TENANT_ROLE", retrievedSecretStore.Data.AuthenticationMethod)

		// 3. UPDATE - change AuthenticationMethod from TENANT_ROLE to GLOBAL_ROLE_EXTERNAL_ID
		t.Logf("Step 3: Updating secret store AuthenticationMethod to GLOBAL_ROLE_EXTERNAL_ID: %s", secretStore.ID)
		updatedSecretStore, err := secretStoresSvc.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: "AuthMethod transition test",
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				AccountAlias:         "test-account-alias",
				RoleName:             "TestSecretsAccessRole",
				AuthenticationMethod: "GLOBAL_ROLE_EXTERNAL_ID",
			},
		})
		require.NoError(t, err, "Failed to update secret store AuthenticationMethod")
		assert.Equal(t, "GLOBAL_ROLE_EXTERNAL_ID", updatedSecretStore.Data.AuthenticationMethod)

		// Verify update
		retrievedSecretStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store after AuthenticationMethod update")
		assert.Equal(t, "GLOBAL_ROLE_EXTERNAL_ID", retrievedSecretStore.Data.AuthenticationMethod)

		t.Log("SecretStore AuthenticationMethod update completed successfully")
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
		hashiVaultURL := randomHashiVaultURL()
		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"Initial description",
			"HASHICORP_VAULT",
			secretstoresmodels.IdsecSecHubSecretStoreData{
				HashiVaultURL:      hashiVaultURL,
				MountPath:          "secret/",
				RoleName:           "secrets-hub-role",
				AuthenticationPath: "auth/jwt/login/",
				ConnectionConfig: &secretstoresmodels.IdsecSecHubSecretStoreConnectionConfig{
					ConnectionType: "PUBLIC",
				},
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)
		assert.Equal(t, hashiVaultURL, secretStore.Data.HashiVaultURL)
		assert.Equal(t, "secret/", secretStore.Data.MountPath)
		assert.Equal(t, "auth/jwt/login/", secretStore.Data.AuthenticationPath)

		// 2. READ
		t.Logf("Step 2: Reading secret store: %s", secretStore.ID)
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, "Initial description", retrievedSecretStore.Description)
		assert.Equal(t, hashiVaultURL, retrievedSecretStore.Data.HashiVaultURL)
		assert.Equal(t, "secret/", retrievedSecretStore.Data.MountPath)
		assert.Equal(t, "auth/jwt/login/", retrievedSecretStore.Data.AuthenticationPath)

		// 3. UPDATE
		t.Logf("Step 3: Updating secret store: %s", secretStore.ID)
		updatedDescription := "Updated description"
		updatedRoleName := "secrets-hub-role-updated"
		updatedAuthPath := "auth/jwt/v2/login/"
		updatedSecretStore, err := secretStoresSvc.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescription,
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				RoleName:           updatedRoleName,
				AuthenticationPath: updatedAuthPath,
				ConnectionConfig: &secretstoresmodels.IdsecSecHubSecretStoreConnectionConfig{
					ConnectionType: "PUBLIC",
				},
			},
		})
		require.NoError(t, err, "Failed to update secret store")
		assert.Equal(t, updatedDescription, updatedSecretStore.Description)
		assert.Equal(t, hashiVaultURL, updatedSecretStore.Data.HashiVaultURL)
		assert.Equal(t, updatedRoleName, updatedSecretStore.Data.RoleName)
		assert.Equal(t, updatedAuthPath, updatedSecretStore.Data.AuthenticationPath)
		assert.Equal(t, "secret/", updatedSecretStore.Data.MountPath)

		// Verify update
		retrievedSecretStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve updated secret store")
		assert.Equal(t, updatedDescription, retrievedSecretStore.Description)
		assert.Equal(t, hashiVaultURL, retrievedSecretStore.Data.HashiVaultURL)
		assert.Equal(t, updatedRoleName, retrievedSecretStore.Data.RoleName)
		assert.Equal(t, updatedAuthPath, retrievedSecretStore.Data.AuthenticationPath)
		assert.Equal(t, "secret/", retrievedSecretStore.Data.MountPath)

		t.Log("SecretStore lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, secretstores.ServiceConfig)
}

// TestSecretStoreLifecycleHashiEnt tests the complete CRUD lifecycle for a HashiCorp Vault Enterprise secret store: Create -> Get -> Update -> Delete.
func TestSecretStoreLifecycleHashiEnt(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Secret Store Lifecycle HashiCorp Vault Enterprise (CRUD)")

		// Get the SecHub SecretStores service
		secretStoresSvc, err := ctx.API.SechubSecretstores()
		require.NoError(t, err)

		// 1. CREATE
		hashiVaultURL := randomHashiVaultURL()
		secretStore := creteSecretStoreResourceForTest(t, ctx,
			e2eSecretStoreNamePrefix,
			"Initial description",
			"HASHICORP_VAULT_ENT",
			secretstoresmodels.IdsecSecHubSecretStoreData{
				HashiVaultURL:      hashiVaultURL,
				Namespace:          "root",
				MountPath:          "secret/",
				RoleName:           "secrets-hub-role",
				AuthenticationPath: "auth/jwt/login/",
				ConnectionConfig: &secretstoresmodels.IdsecSecHubSecretStoreConnectionConfig{
					ConnectionType: "PUBLIC",
				},
			})

		t.Logf("SecretStore created successfully: %s (ID: %s)", secretStore.Name, secretStore.ID)
		assert.Equal(t, hashiVaultURL, secretStore.Data.HashiVaultURL)
		assert.Equal(t, "root", secretStore.Data.Namespace)
		assert.Equal(t, "secret/", secretStore.Data.MountPath)
		assert.Equal(t, "auth/jwt/login/", secretStore.Data.AuthenticationPath)

		// 2. READ
		t.Logf("Step 2: Reading secret store: %s", secretStore.ID)
		retrievedSecretStore, err := secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve secret store")
		assert.Equal(t, secretStore.Name, retrievedSecretStore.Name)
		assert.Equal(t, "Initial description", retrievedSecretStore.Description)
		assert.Equal(t, hashiVaultURL, retrievedSecretStore.Data.HashiVaultURL)
		assert.Equal(t, "root", retrievedSecretStore.Data.Namespace)
		assert.Equal(t, "secret/", retrievedSecretStore.Data.MountPath)
		assert.Equal(t, "auth/jwt/login/", retrievedSecretStore.Data.AuthenticationPath)

		// 3. UPDATE - exercise all mutable fields with different values than those set at creation.
		// Immutable fields (HashiVaultURL, MountPath, Namespace) are intentionally omitted from the PATCH body.
		t.Logf("Step 3: Updating secret store: %s", secretStore.ID)
		updatedDescription := "Updated description"
		updatedRoleName := "secrets-hub-role-updated"
		updatedAuthPath := "auth/jwt/v2/login/"
		updatedSecretStore, err := secretStoresSvc.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
			ID:          secretStore.ID,
			Name:        secretStore.Name,
			Description: updatedDescription,
			Data: &secretstoresmodels.IdsecSecHubSecretStoreData{
				RoleName:           updatedRoleName,
				AuthenticationPath: updatedAuthPath,
				ConnectionConfig: &secretstoresmodels.IdsecSecHubSecretStoreConnectionConfig{
					ConnectionType: "PUBLIC",
				},
			},
		})
		require.NoError(t, err, "Failed to update secret store")
		assert.Equal(t, updatedDescription, updatedSecretStore.Description)
		assert.Equal(t, hashiVaultURL, updatedSecretStore.Data.HashiVaultURL)
		assert.Equal(t, "root", updatedSecretStore.Data.Namespace)
		assert.Equal(t, updatedRoleName, updatedSecretStore.Data.RoleName)
		assert.Equal(t, updatedAuthPath, updatedSecretStore.Data.AuthenticationPath)

		// Verify update via GET
		retrievedSecretStore, err = secretStoresSvc.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
			ID: secretStore.ID,
		})
		require.NoError(t, err, "Failed to retrieve updated secret store")
		assert.Equal(t, updatedDescription, retrievedSecretStore.Description)
		assert.Equal(t, hashiVaultURL, retrievedSecretStore.Data.HashiVaultURL)
		assert.Equal(t, "root", retrievedSecretStore.Data.Namespace)
		assert.Equal(t, updatedRoleName, retrievedSecretStore.Data.RoleName)
		assert.Equal(t, updatedAuthPath, retrievedSecretStore.Data.AuthenticationPath)
		assert.Equal(t, "secret/", retrievedSecretStore.Data.MountPath)

		t.Log("SecretStore lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, secretstores.ServiceConfig)
}
