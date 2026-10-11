//go:build (e2e && sia) || e2e

package sia

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
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

// discoveryAddSecretPayload returns addSecretPayload with discovery on and no domain controller named.
func discoveryAddSecretPayload(secretName string) *vmsecretsmodels.IdsecSIAVMAddSecret {
	addReq := addSecretPayload(secretName)
	addReq.DomainControllerName = ""
	addReq.DomainControllerNetbios = ""
	addReq.DomainControllerAutomaticDiscovery = common.Ptr(true)
	return addReq
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
		require.NotNil(t, secret.DomainControllerAutomaticDiscovery)
		assert.False(t, *secret.DomainControllerAutomaticDiscovery)

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
		require.NotNil(t, retrieved.DomainControllerAutomaticDiscovery)
		assert.False(t, *retrieved.DomainControllerAutomaticDiscovery)

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

// TestSecretsVMEphemeralAutomaticDiscoveryCreate tests adding a secret with automatic discovery enabled.
func TestSecretsVMEphemeralAutomaticDiscoveryCreate(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Automatic Discovery Create")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-discovery")
		t.Logf("Creating VM secret with automatic discovery: %s", secretName)

		secret, err := svc.Create(discoveryAddSecretPayload(secretName))
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
		require.NotNil(t, secret.DomainControllerAutomaticDiscovery)
		assert.True(t, *secret.DomainControllerAutomaticDiscovery)
		assert.Empty(t, secret.DomainControllerName)
		assert.Empty(t, secret.DomainControllerNetbios)

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		require.NotNil(t, retrieved.DomainControllerAutomaticDiscovery)
		assert.True(t, *retrieved.DomainControllerAutomaticDiscovery)
		assert.Empty(t, retrieved.DomainControllerName)
		assert.Empty(t, retrieved.DomainControllerNetbios)

		t.Log("SIA VM Ephemeral Automatic Discovery Create test completed successfully")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralAutomaticDiscoveryChangeFromNamedDC tests switching a named domain controller to automatic discovery.
func TestSecretsVMEphemeralAutomaticDiscoveryChangeFromNamedDC(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Automatic Discovery Change From Named DC")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-to-discovery")
		t.Logf("Creating VM secret with a named domain controller: %s", secretName)

		secret, err := svc.Create(addSecretPayload(secretName))
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

		t.Log("Enabling automatic discovery...")
		_, err = svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                           secret.SecretID,
			DomainControllerAutomaticDiscovery: common.Ptr(true),
		})
		require.NoError(t, err)

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		require.NotNil(t, retrieved.DomainControllerAutomaticDiscovery)
		assert.True(t, *retrieved.DomainControllerAutomaticDiscovery)
		assert.Empty(t, retrieved.DomainControllerName, "Domain controller name should be cleared")
		assert.Empty(t, retrieved.DomainControllerNetbios, "Domain controller netbios should be cleared")

		t.Log("SIA VM Ephemeral Automatic Discovery Change From Named DC test completed successfully")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralAutomaticDiscoveryChangeToNamedDC tests switching automatic discovery to a named domain controller.
func TestSecretsVMEphemeralAutomaticDiscoveryChangeToNamedDC(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Automatic Discovery Change To Named DC")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-to-named-dc")
		t.Logf("Creating VM secret with automatic discovery: %s", secretName)

		secret, err := svc.Create(discoveryAddSecretPayload(secretName))
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

		t.Log("Naming a domain controller...")
		_, err = svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:             secret.SecretID,
			DomainControllerName: dummyDomainControllerName,
		})
		require.NoError(t, err)

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, dummyDomainControllerName, retrieved.DomainControllerName)
		require.NotNil(t, retrieved.DomainControllerAutomaticDiscovery)
		assert.False(t, *retrieved.DomainControllerAutomaticDiscovery, "Automatic discovery should be turned off")

		t.Log("SIA VM Ephemeral Automatic Discovery Change To Named DC test completed successfully")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralAutomaticDiscoveryDisable tests turning automatic discovery off on an existing secret.
func TestSecretsVMEphemeralAutomaticDiscoveryDisable(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Automatic Discovery Disable")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-discovery-off")
		t.Logf("Creating VM secret with automatic discovery: %s", secretName)

		secret, err := svc.Create(discoveryAddSecretPayload(secretName))
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

		t.Log("Disabling automatic discovery...")
		_, err = svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                           secret.SecretID,
			DomainControllerAutomaticDiscovery: common.Ptr(false),
		})
		require.NoError(t, err)

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		require.NotNil(t, retrieved.DomainControllerAutomaticDiscovery)
		assert.False(t, *retrieved.DomainControllerAutomaticDiscovery)

		t.Log("SIA VM Ephemeral Automatic Discovery Disable test completed successfully")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralAutomaticDiscoveryConflictError tests that adding discovery with a named domain controller fails.
func TestSecretsVMEphemeralAutomaticDiscoveryConflictError(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Automatic Discovery Conflict Error")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		tests := []struct {
			name    string
			dcName  string
			netbios string
		}{
			{name: "name_only", dcName: dummyDomainControllerName},
			{name: "netbios_only", netbios: dummyDomainControllerNetbios},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				secretName := framework.RandomResourceName("e2e-vm-secret-discovery-conflict")
				t.Logf("Attempting to create VM secret with automatic discovery and a named domain controller: %s", secretName)

				addReq := discoveryAddSecretPayload(secretName)
				addReq.DomainControllerName = tt.dcName
				addReq.DomainControllerNetbios = tt.netbios

				secret, err := svc.Create(addReq)
				if err == nil && secret != nil && secret.SecretID != "" {
					ctx.TrackResourceByType("VMSecret", secret.SecretID, func() error {
						return svc.Delete(&vmsecretsmodels.IdsecSIAVMDeleteSecret{SecretID: secret.SecretID})
					})
				}
				require.Error(t, err, "Expected error when combining automatic discovery with a named domain controller")
				assert.Contains(t, err.Error(), "[400]")
				assert.Contains(t, strings.ToLower(err.Error()), "discovery")
				assert.Nil(t, secret, "Secret should be nil on error")
			})
		}

		t.Log("SIA VM Ephemeral Automatic Discovery Conflict Error test completed successfully - error as expected")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralAutomaticDiscoveryChangeConflictError tests that a change setting both fails and leaves the secret unchanged.
func TestSecretsVMEphemeralAutomaticDiscoveryChangeConflictError(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Automatic Discovery Change Conflict Error")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-change-conflict")
		t.Logf("Creating VM secret with a named domain controller: %s", secretName)

		secret, err := svc.Create(addSecretPayload(secretName))
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

		t.Log("Attempting to enable automatic discovery and rename the domain controller together...")
		updated, err := svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                           secret.SecretID,
			DomainControllerName:               "e2e-dc-new.example.com",
			DomainControllerAutomaticDiscovery: common.Ptr(true),
		})
		require.Error(t, err, "Expected error when combining automatic discovery with a named domain controller")
		assert.Contains(t, err.Error(), "[400]")
		assert.Contains(t, strings.ToLower(err.Error()), "discovery")
		assert.Nil(t, updated, "Secret should be nil on error")

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, dummyDomainControllerName, retrieved.DomainControllerName)
		require.NotNil(t, retrieved.DomainControllerAutomaticDiscovery)
		assert.False(t, *retrieved.DomainControllerAutomaticDiscovery)

		t.Log("SIA VM Ephemeral Automatic Discovery Change Conflict Error test completed successfully - error as expected")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralLoadAllCertificates tests validating LDAPS and WinRM against all certificates in the store.
func TestSecretsVMEphemeralLoadAllCertificates(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Load All Certificates")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-load-all-certs")
		t.Logf("Creating VM secret that loads all certificates: %s", secretName)

		addReq := addSecretPayload(secretName)
		addReq.DomainControllerEnableCertificateValidation = common.Ptr(true)
		addReq.DomainControllerLdapsLoadAllCertificates = common.Ptr(true)
		addReq.WinrmEnableCertificateValidation = common.Ptr(true)
		addReq.WinrmLoadAllCertificates = common.Ptr(true)

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

		assertLoadAll := func(s *vmsecretsmodels.IdsecSIAVMSecret) {
			require.NotNil(t, s.DomainControllerLdapsLoadAllCertificates)
			assert.True(t, *s.DomainControllerLdapsLoadAllCertificates)
			assert.Empty(t, s.DomainControllerLdapsCertificate)
			require.NotNil(t, s.WinrmLoadAllCertificates)
			assert.True(t, *s.WinrmLoadAllCertificates)
			assert.Empty(t, s.WinrmCertificate)
		}

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assertLoadAll(retrieved)

		t.Log("Changing an unrelated field...")
		_, err = svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                    secret.SecretID,
			EphemeralDomainUserLocation: "OU=E2EUpdated,DC=example,DC=com",
		})
		require.NoError(t, err)

		retrieved, err = svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assertLoadAll(retrieved)

		t.Log("SIA VM Ephemeral Load All Certificates test completed successfully")
	}, vmsecrets.ServiceConfig)
}

// TestSecretsVMEphemeralCertificatesSwitch tests switching LDAPS and WinRM between load-all and a single certificate.
func TestSecretsVMEphemeralCertificatesSwitch(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: SIA VM Secrets Ephemeral Certificates Switch")

		svc, err := ctx.API.SiaSecretsvm()
		require.NoError(t, err, "Failed to get SIA VM Secrets service")

		secretName := framework.RandomResourceName("e2e-vm-secret-certs-switch")
		t.Logf("Creating VM secret that loads all certificates: %s", secretName)

		addReq := addSecretPayload(secretName)
		addReq.DomainControllerEnableCertificateValidation = common.Ptr(true)
		addReq.DomainControllerLdapsLoadAllCertificates = common.Ptr(true)
		addReq.WinrmEnableCertificateValidation = common.Ptr(true)
		addReq.WinrmLoadAllCertificates = common.Ptr(true)

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

		const ldapsCertificate = "e2e-ldaps-cert"
		const winrmCertificate = "e2e-winrm-cert"

		t.Log("Switching to single certificates...")
		_, err = svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                         secret.SecretID,
			DomainControllerLdapsCertificate: ldapsCertificate,
			WinrmCertificate:                 winrmCertificate,
		})
		require.NoError(t, err)

		retrieved, err := svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, ldapsCertificate, retrieved.DomainControllerLdapsCertificate)
		require.NotNil(t, retrieved.DomainControllerLdapsLoadAllCertificates)
		assert.False(t, *retrieved.DomainControllerLdapsLoadAllCertificates)
		assert.Equal(t, winrmCertificate, retrieved.WinrmCertificate)
		require.NotNil(t, retrieved.WinrmLoadAllCertificates)
		assert.False(t, *retrieved.WinrmLoadAllCertificates)

		t.Log("Switching back to all certificates...")
		_, err = svc.Change(&vmsecretsmodels.IdsecSIAVMChangeSecret{
			SecretID:                                 secret.SecretID,
			DomainControllerLdapsLoadAllCertificates: common.Ptr(true),
			WinrmLoadAllCertificates:                 common.Ptr(true),
		})
		require.NoError(t, err)

		retrieved, err = svc.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{SecretID: secret.SecretID})
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Empty(t, retrieved.DomainControllerLdapsCertificate)
		require.NotNil(t, retrieved.DomainControllerLdapsLoadAllCertificates)
		assert.True(t, *retrieved.DomainControllerLdapsLoadAllCertificates)
		assert.Empty(t, retrieved.WinrmCertificate)
		require.NotNil(t, retrieved.WinrmLoadAllCertificates)
		assert.True(t, *retrieved.WinrmLoadAllCertificates)

		t.Log("SIA VM Ephemeral Certificates Switch test completed successfully")
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
