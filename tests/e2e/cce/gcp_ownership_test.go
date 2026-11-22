//go:build (e2e && cce) || e2e

package cce

import (
	"testing"

	"github.com/stretchr/testify/require"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestGCPTakeOwnershipOfProgrammaticOnboarding verifies against the real backend that a programmatic GCP
// onboarding is converted to terraform_provider only on an explicit opt-in, and that CCE then accepts
// updates from the Terraform update path.
//
// The tests use only dpa: other services may not be enabled for the CI tenant, and their deployments can
// stay in progress for longer than the cleanup waits.
//
// The targets run one after another: the organization and the project fixtures belong to the same GCP
// organization, and CCE rejects concurrent changes to an onboarding.
func TestGCPTakeOwnershipOfProgrammaticOnboarding(t *testing.T) {
	for _, target := range gcpTargets {
		t.Run(target.name, func(t *testing.T) {
			framework.Run(t, func(ctx *framework.TestContext) {
				framework.LogSection(t, "Test: take ownership of a programmatic GCP "+target.name)

				svc, err := ctx.API.CceGcp()
				require.NoError(t, err)

				services := target.initialServices(t)
				id := createProgrammaticOnboarding(ctx, svc, target, services)
				requireOnboardingType(t, svc, target, id, ccemodels.Programmatic)

				t.Log("Step 1: update without onboarding_type must be rejected and change nothing")
				_, err = target.update(svc, id, services, "")
				require.ErrorContains(t, err, ownershipHint)
				requireOnboardingType(t, svc, target, id, ccemodels.Programmatic)
				requireServices(t, svc, target, id, services)

				t.Log("Step 2: update with onboarding_type = terraform_provider must convert it")
				updated, err := target.update(svc, id, services, ccemodels.TerraformProvider)
				require.NoError(t, err, "CCE must accept the update after the conversion")
				require.Equal(t, ccemodels.TerraformProvider, updated.OnboardingType)
				requireOnboardingType(t, svc, target, id, ccemodels.TerraformProvider)
				requireServices(t, svc, target, id, services)

				t.Log("Step 3: repeating the update must be a no-op")
				repeated, err := target.update(svc, id, services, ccemodels.TerraformProvider)
				require.NoError(t, err, "a repeat after the conversion must not import again")
				require.Equal(t, ccemodels.TerraformProvider, repeated.OnboardingType)
				requireServices(t, svc, target, id, services)
			}, gcp.ServiceConfig)
		})
	}
}

func requireOnboardingType(t *testing.T, svc *gcp.IdsecCCEGCPService, target gcpTarget, id, want string) {
	t.Helper()
	current, err := target.get(svc, id)
	require.NoError(t, err)
	require.Equal(t, want, current.OnboardingType, "%s %s onboarding type", target.name, id)
}

func requireServices(t *testing.T, svc *gcp.IdsecCCEGCPService, target gcpTarget, id string, want []ccemodels.IdsecCCEServiceInput) {
	t.Helper()
	current, err := target.get(svc, id)
	require.NoError(t, err)
	names := make([]string, 0, len(want))
	for _, service := range want {
		names = append(names, service.ServiceName)
	}
	require.ElementsMatch(t, names, current.Services, "%s %s services", target.name, id)
}
