package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// validServices returns a minimal, valid services slice for add/update inputs.
func validServices() []ccemodels.IdsecCCEServiceInput {
	return []ccemodels.IdsecCCEServiceInput{
		{
			ServiceName: ccemodels.DPA,
			Resources:   map[string]interface{}{},
		},
	}
}

// validAddProject returns a minimal, valid TfIdsecCCEGCPAddProject.
// OrganizationID intentionally uses 13 digits (beyond the old, incorrect 8-12
// digit assumption) since real-world GCP organization IDs can be up to 19 digits.
func validAddProject() *TfIdsecCCEGCPAddProject {
	return &TfIdsecCCEGCPAddProject{
		ProjectID:      "gcp-project-12345",
		OrganizationID: "1234567890123",
		ProjectNumber:  "987654321012",
		Services:       validServices(),
	}
}

// TestTfIdsecCCEGCPAddProject_Validation ensures the required fields for onboarding
// a GCP project are enforced: project ID, organization ID, project number, and services.
func TestTfIdsecCCEGCPAddProject_Validation(t *testing.T) {
	t.Run("valid_input_passes", func(t *testing.T) {
		require.NoError(t, validation.ValidateStruct(validAddProject()))
	})

	t.Run("missing_project_id_fails", func(t *testing.T) {
		input := validAddProject()
		input.ProjectID = ""
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("project_id_too_short_fails", func(t *testing.T) {
		input := validAddProject()
		input.ProjectID = "abc"
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("missing_organization_id_fails", func(t *testing.T) {
		input := validAddProject()
		input.OrganizationID = ""
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("organization_id_longer_than_12_digits_passes", func(t *testing.T) {
		// GCP organization IDs are not bounded to 8-12 digits; up to 19 digits are valid.
		input := validAddProject()
		input.OrganizationID = "9999999999999999" // 16 digits
		err := validation.ValidateStruct(input)
		require.NoError(t, err)
	})

	t.Run("organization_id_non_numeric_fails", func(t *testing.T) {
		input := validAddProject()
		input.OrganizationID = "not-an-org"
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("organization_id_leading_zero_fails", func(t *testing.T) {
		input := validAddProject()
		input.OrganizationID = "01234567" // leading zero, 8 digits
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("organization_id_shorter_than_8_digits_fails", func(t *testing.T) {
		input := validAddProject()
		input.OrganizationID = "1234567" // 7 digits
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("organization_id_longer_than_19_digits_fails", func(t *testing.T) {
		input := validAddProject()
		input.OrganizationID = "12345678901234567890" // 20 digits
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("organization_id_19_digits_passes", func(t *testing.T) {
		input := validAddProject()
		input.OrganizationID = "1234567890123456789" // 19 digits, upper bound
		err := validation.ValidateStruct(input)
		require.NoError(t, err)
	})

	t.Run("missing_project_number_fails", func(t *testing.T) {
		input := validAddProject()
		input.ProjectNumber = ""
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("non_numeric_project_number_fails", func(t *testing.T) {
		input := validAddProject()
		input.ProjectNumber = "not-a-number"
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})

	t.Run("missing_services_fails", func(t *testing.T) {
		input := validAddProject()
		input.Services = nil
		err := validation.ValidateStruct(input)
		require.Error(t, err)
	})
}

// validAddOrganization returns a minimal, valid TfIdsecCCEGCPAddOrganization.
func validAddOrganization() *TfIdsecCCEGCPAddOrganization {
	return &TfIdsecCCEGCPAddOrganization{
		DeploymentProjectID: "gcp-hub-project-42",
		OrganizationID:      "1234567890123",
		ProjectNumber:       "987654321012",
		Services:            validServices(),
		CCEResources: TfIdsecCCEGCPResources{
			WorkloadIdentityPoolID:     "my-pool-id01",
			WorkloadIdentityProviderID: "my-provider01",
			TargetServiceAccountEmail:  "sa@project.iam.gserviceaccount.com",
		},
	}
}

// TestTfIdsecCCEGCPAddOrganization_Validation ensures the required fields for onboarding
// a GCP organization are enforced, with particular focus on DeploymentProjectID which must
// match the GCP project ID format (^[a-z][a-z0-9-]{4,28}[a-z0-9]$), not a plain number.
func TestTfIdsecCCEGCPAddOrganization_Validation(t *testing.T) {
	t.Run("valid_input_passes", func(t *testing.T) {
		require.NoError(t, validation.ValidateStruct(validAddOrganization()))
	})

	t.Run("missing_deployment_project_id_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.DeploymentProjectID = ""
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("numeric_only_deployment_project_id_fails", func(t *testing.T) {
		// GCP project IDs are not plain numbers; a numeric string must not pass.
		input := validAddOrganization()
		input.DeploymentProjectID = "123456789"
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("deployment_project_id_starts_with_digit_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.DeploymentProjectID = "1my-project-id"
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("deployment_project_id_too_short_fails", func(t *testing.T) {
		// Minimum valid length is 6 chars (1 + at least 4 middle + 1 end).
		input := validAddOrganization()
		input.DeploymentProjectID = "abcde" // 5 chars
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("deployment_project_id_too_long_fails", func(t *testing.T) {
		// Maximum valid length is 30 chars (1 + 28 middle + 1 end).
		input := validAddOrganization()
		input.DeploymentProjectID = "a" + "bcdefghijklmnopqrstuvwxyz0123" + "z" // 31 chars: middle = 29 > 28
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("deployment_project_id_min_length_passes", func(t *testing.T) {
		input := validAddOrganization()
		input.DeploymentProjectID = "abcde1" // 6 chars: a + bcde + 1
		require.NoError(t, validation.ValidateStruct(input))
	})

	t.Run("deployment_project_id_max_length_passes", func(t *testing.T) {
		input := validAddOrganization()
		input.DeploymentProjectID = "a" + "bcdefghijklmnopqrstuvwxyz012" + "z" // 30 chars: middle = 28
		require.NoError(t, validation.ValidateStruct(input))
	})

	t.Run("deployment_project_id_uppercase_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.DeploymentProjectID = "MyProject-id1"
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("missing_organization_id_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.OrganizationID = ""
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("missing_project_number_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.ProjectNumber = ""
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("non_numeric_project_number_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.ProjectNumber = "not-a-number"
		require.Error(t, validation.ValidateStruct(input))
	})

	t.Run("missing_services_fails", func(t *testing.T) {
		input := validAddOrganization()
		input.Services = nil
		require.Error(t, validation.ValidateStruct(input))
	})
}

// TestTfIdsecCCEGCPUpdateProject_IDRequired ensures the project onboarding ID is
// mandatory when updating a GCP project's services.
func TestTfIdsecCCEGCPUpdateProject_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEGCPUpdateProject{
			ID:       "",
			Services: validServices(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEGCPUpdateProject{
			ID:       "project-123",
			Services: validServices(),
		})
		require.NoError(t, err)
	})
}

// TestTfIdsecCCEGCPDeleteProject_IDRequired ensures the project onboarding ID is
// mandatory when deleting a GCP project.
func TestTfIdsecCCEGCPDeleteProject_IDRequired(t *testing.T) {
	t.Run("empty_id_fails", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEGCPDeleteProject{ID: ""})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id")
	})

	t.Run("populated_id_passes", func(t *testing.T) {
		err := validation.ValidateStruct(&TfIdsecCCEGCPDeleteProject{ID: "project-123"})
		require.NoError(t, err)
	})
}
