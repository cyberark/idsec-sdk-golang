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

// TestTfIdsecCCEAWSUpdateAccount_IDRequired ensures the account onboarding ID is
// mandatory when updating an AWS account.
func TestTfIdsecCCEAWSUpdateAccount_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAWSUpdateAccount{
			ID:       "",
			Services: validServices(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAWSUpdateAccount{
			ID:       "ef858a2d8f8f4f1781578089bb4ea010",
			Services: validServices(),
		})
		require.NoError(t, err)
	})
}

// TestTfIdsecCCEAWSUpdateOrganization_IDRequired ensures the organization
// onboarding ID is mandatory when updating an AWS organization.
func TestTfIdsecCCEAWSUpdateOrganization_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAWSUpdateOrganization{
			ID:       "",
			Services: validServices(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEAWSUpdateOrganization{
			ID:       "ef858a2d8f8f4f1781578089bb4ea010",
			Services: validServices(),
		})
		require.NoError(t, err)
	})
}
