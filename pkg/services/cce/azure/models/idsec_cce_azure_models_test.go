package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// validServices returns a minimal, valid services slice for update inputs.
func validServices() []ccemodels.IdsecCCEServiceInput {
	return []ccemodels.IdsecCCEServiceInput{
		{
			ServiceName: ccemodels.DPA,
			Resources:   map[string]interface{}{},
		},
	}
}

// TestTfIdsecCCEAzureUpdateSubscription_IDRequired ensures the subscription
// onboarding ID is mandatory when updating an Azure subscription.
func TestTfIdsecCCEAzureUpdateSubscription_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAzureUpdateSubscription{
			ID:       "",
			Services: validServices(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAzureUpdateSubscription{
			ID:       "subscription-123",
			Services: validServices(),
		})
		require.NoError(t, err)
	})
}

// TestTfIdsecCCEAzureUpdateManagementGroup_IDRequired ensures the management
// group onboarding ID is mandatory when updating an Azure management group.
func TestTfIdsecCCEAzureUpdateManagementGroup_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAzureUpdateManagementGroup{
			ID:       "",
			Services: validServices(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAzureUpdateManagementGroup{
			ID:       "mgmt-group-123",
			Services: validServices(),
		})
		require.NoError(t, err)
	})
}

// TestTfIdsecCCEAzureUpdateEntra_IDRequired ensures the Entra tenant onboarding
// ID is mandatory when updating an Azure Entra tenant.
func TestTfIdsecCCEAzureUpdateEntra_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAzureUpdateEntra{
			ID:       "",
			Services: validServices(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAzureUpdateEntra{
			ID:       "entra-123",
			Services: validServices(),
		})
		require.NoError(t, err)
	})
}
