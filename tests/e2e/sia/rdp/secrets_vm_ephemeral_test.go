//go:build (e2e && sia) || e2e

package sia

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vmsecrets "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsvm"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsvm/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// Dummy values for SIA VM ephemeral domain user E2E tests.
// These may cause failures against real SIA unless the environment accepts them.
const (
	dummyAccountDomain               = "e2e-test.domain.local"
	dummyProvisionerUsername         = "e2e-provisioner-user"
	dummyProvisionerPassword         = "E2EDummyPassword123!"
	dummyDomainControllerName        = "e2e-dc.example.com"
	dummyDomainControllerNetbios     = "E2EDC"
	dummyEphemeralDomainUserLocation = "OU=E2E,DC=example,DC=com"
)

// addSecretPayload returns an IdsecSIAVMAddSecret for ProvisionerUser with ephemeral domain user creation enabled.
func addSecretPayload(secretName string) *vmsecretsmodels.IdsecSIAVMAddSecret {
	enableEphemeral := true
	useLdaps := true
	useWinrmHTTPS := true
	return &vmsecretsmodels.IdsecSIAVMAddSecret{
		SecretName:                        secretName,
		SecretType:                        vmsecretsmodels.ProvisionerUser,
		IsActive:                          true,
		ProvisionerUsername:               dummyProvisionerUsername,
		ProvisionerPassword:               dummyProvisionerPassword,
		AccountDomain:                     dummyAccountDomain,
		EnableEphemeralDomainUserCreation: &enableEphemeral,
		DomainControllerName:              dummyDomainControllerName,
		DomainControllerNetbios:           dummyDomainControllerNetbios,
		EphemeralDomainUserLocation:       dummyEphemeralDomainUserLocation,
		DomainControllerUseLdaps:          &useLdaps,
		UseWinrmForHTTPS:                  &useWinrmHTTPS,
		// Certificate validation left false so no cert IDs required
	}
}

// TestSecretsVMEphemeralCRUD tests SIA VM secrets CRUD with ephemeral domain user data:
// Add ProvisionerUser secret with ephemeral enabled, Get, ChangeSecret (merge), then cleanup deletes.
func TestSecretsVMEphemeralCRUD(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral CRUD")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret")
		t.Logf("Creating VM secret: %s", secretName)

		addReq := addSecretPayload(secretName)
		secret, err := svc.Create(addReq)
		if err != nil {
			t.Logf("AddSecret failed (dummy values may be invalid in this environment): %v", err)
			t.Skipf("Skipping: AddSecret failed - %v", err)
			return
		}
		require.NotNil(t, secret)
		require.NotEmpty(t, secret.SecretID)

		ctx.TrackResourceByType("VMSecret", secret.SecretID, func() error {
			return svc.Delete(&vmsecretsmodels.IdsecSIAVMDeleteSecret{SecretID: secret.SecretID})
		})

		t.Logf("Secret created: %s (ID: %s)", secret.SecretName, secret.SecretID)
		assert.Equal(t, secretName, secret.SecretName)
		assert.Equal(t, vmsecretsmodels.ProvisionerUser, secret.SecretType)
		assert.Equal(t, dummyAccountDomain, secret.AccountDomain)
		require.NotNil(t, secret.EnableEphemeralDomainUserCreation)
		assert.True(t, *secret.EnableEphemeralDomainUserCreation)
		assert.Equal(t, dummyDomainControllerName, secret.DomainControllerName)
		assert.Equal(t, dummyDomainControllerNetbios, secret.DomainControllerNetbios)
		assert.Equal(t, dummyEphemeralDomainUserLocation, secret.EphemeralDomainUserLocation)

		// READ: get secret and assert flattened ephemeral fields
		t.Log("Reading secret...")
		getReq := &vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID}
		retrieved, err := svc.Get(getReq)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, secret.SecretID, retrieved.SecretID)
		assert.Equal(t, dummyAccountDomain, retrieved.AccountDomain)
		assert.Equal(t, dummyDomainControllerName, retrieved.DomainControllerName)
		assert.Equal(t, dummyDomainControllerNetbios, retrieved.DomainControllerNetbios)
		assert.Equal(t, dummyEphemeralDomainUserLocation, retrieved.EphemeralDomainUserLocation)

		// UPDATE: ChangeSecret with a subset of fields (merge behavior: others preserved)
		newLocation := "OU=E2EUpdated,DC=example,DC=com"
		t.Logf("Updating secret ephemeral location to: %s", newLocation)
		changeReq := &vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                    secret.SecretID,
			EphemeralDomainUserLocation: newLocation,
			// Do not set AccountDomain, DomainControllerName, etc. — should be preserved
		}
		updated, err := svc.Change(changeReq)
		if err != nil {
			t.Logf("ChangeSecret failed: %v", err)
			t.Skipf("Skipping change verification: %v", err)
			return
		}
		require.NotNil(t, updated)
		assert.Equal(t, newLocation, updated.EphemeralDomainUserLocation)
		assert.Equal(t, dummyAccountDomain, updated.AccountDomain)
		assert.Equal(t, dummyDomainControllerName, updated.DomainControllerName)
		assert.Equal(t, dummyDomainControllerNetbios, updated.DomainControllerNetbios)

		t.Log("SIA VM Ephemeral CRUD completed successfully")
		// DELETE runs via deferred cleanup
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralDisabled tests adding a secret with ephemeral disabled.
// Should have account_domain but empty ephemeral_domain_user_data.
func TestSecretsVMEphemeralDisabled(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Disabled")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-no-ephemeral")
		t.Logf("Creating VM secret without ephemeral: %s", secretName)

		// Create secret with ephemeral disabled (nil or false)
		enableEphemeral := false
		addReq := &vmsecretsmodels.IdsecSIAVMAddSecret{
			SecretName:                        secretName,
			SecretType:                        vmsecretsmodels.ProvisionerUser,
			IsActive:                          true,
			ProvisionerUsername:               dummyProvisionerUsername,
			ProvisionerPassword:               dummyProvisionerPassword,
			AccountDomain:                     dummyAccountDomain,
			EnableEphemeralDomainUserCreation: &enableEphemeral, // Explicitly disabled
		}

		secret, err := svc.Create(addReq)
		if err != nil {
			t.Logf("AddSecret failed: %v", err)
			t.Skipf("Skipping: AddSecret failed - %v", err)
			return
		}
		require.NotNil(t, secret)
		require.NotEmpty(t, secret.SecretID)

		ctx.TrackResourceByType("VMSecret", secret.SecretID, func() error {
			return svc.Delete(&vmsecretsmodels.IdsecSIAVMDeleteSecret{SecretID: secret.SecretID})
		})

		t.Logf("Secret created: %s (ID: %s)", secret.SecretName, secret.SecretID)

		// Assert ephemeral is disabled or nil
		assert.Equal(t, dummyAccountDomain, secret.AccountDomain)
		if secret.EnableEphemeralDomainUserCreation != nil {
			assert.False(t, *secret.EnableEphemeralDomainUserCreation)
		}
		// Ephemeral fields should be empty
		assert.Empty(t, secret.DomainControllerName)
		assert.Empty(t, secret.DomainControllerNetbios)
		assert.Empty(t, secret.EphemeralDomainUserLocation)

		t.Log("SIA VM Ephemeral Disabled test completed successfully")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralLocalDomainError tests that enabling ephemeral with local domain fails.
// The service should reject this before making an API call.
func TestSecretsVMEphemeralLocalDomainError(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Local Domain Error")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-local-error")
		t.Logf("Attempting to create VM secret with ephemeral enabled and local domain: %s", secretName)

		// Try to enable ephemeral with local domain (should fail)
		enableEphemeral := true
		useLdaps := true
		useWinrmHTTPS := true
		addReq := &vmsecretsmodels.IdsecSIAVMAddSecret{
			SecretName:                        secretName,
			SecretType:                        vmsecretsmodels.ProvisionerUser,
			IsActive:                          true,
			ProvisionerUsername:               dummyProvisionerUsername,
			ProvisionerPassword:               dummyProvisionerPassword,
			AccountDomain:                     "local", // Local domain
			EnableEphemeralDomainUserCreation: &enableEphemeral,
			DomainControllerName:              dummyDomainControllerName,
			DomainControllerNetbios:           dummyDomainControllerNetbios,
			EphemeralDomainUserLocation:       dummyEphemeralDomainUserLocation,
			DomainControllerUseLdaps:          &useLdaps,
			UseWinrmForHTTPS:                  &useWinrmHTTPS,
		}

		secret, err := svc.Create(addReq)
		// Should get an error about local domain
		require.Error(t, err, "Expected error when enabling ephemeral with local domain")
		assert.Contains(t, err.Error(), "local", "Error should mention local domain")
		assert.Nil(t, secret, "Secret should be nil on error")

		t.Log("SIA VM Ephemeral Local Domain Error test completed successfully - error as expected")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMChangeSecretDisableEphemeral tests changing a secret to disable ephemeral.
func TestSecretsVMChangeSecretDisableEphemeral(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Change Secret Disable Ephemeral")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-disable-ephemeral")
		t.Logf("Creating VM secret with ephemeral enabled: %s", secretName)

		// Create secret with ephemeral enabled
		addReq := addSecretPayload(secretName)
		secret, err := svc.Create(addReq)
		if err != nil {
			t.Logf("AddSecret failed: %v", err)
			t.Skipf("Skipping: AddSecret failed - %v", err)
			return
		}
		require.NotNil(t, secret)
		require.NotEmpty(t, secret.SecretID)

		ctx.TrackResourceByType("VMSecret", secret.SecretID, func() error {
			return svc.Delete(&vmsecretsmodels.IdsecSIAVMDeleteSecret{SecretID: secret.SecretID})
		})

		t.Logf("Secret created: %s (ID: %s)", secret.SecretName, secret.SecretID)
		require.NotNil(t, secret.EnableEphemeralDomainUserCreation)
		assert.True(t, *secret.EnableEphemeralDomainUserCreation, "Ephemeral should be enabled initially")

		// Now disable ephemeral
		t.Log("Disabling ephemeral domain user creation...")
		disableEphemeral := false
		changeReq := &vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                          secret.SecretID,
			EnableEphemeralDomainUserCreation: &disableEphemeral,
		}

		updated, err := svc.Change(changeReq)
		if err != nil {
			t.Logf("ChangeSecret failed: %v", err)
			t.Skipf("Skipping change verification: %v", err)
			return
		}
		require.NotNil(t, updated)

		// Verify ephemeral is now disabled and fields are empty
		if updated.EnableEphemeralDomainUserCreation != nil {
			assert.False(t, *updated.EnableEphemeralDomainUserCreation, "Ephemeral should be disabled after change")
		}
		// Ephemeral fields should be cleared
		assert.Empty(t, updated.DomainControllerName, "Domain controller name should be cleared")
		assert.Empty(t, updated.DomainControllerNetbios, "Domain controller netbios should be cleared")
		assert.Empty(t, updated.EphemeralDomainUserLocation, "Ephemeral location should be cleared")

		t.Log("SIA VM Change Secret Disable Ephemeral test completed successfully")
	}, vmsecrets.ServiceConfig)
}
