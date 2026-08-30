package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEGCPGetOrganization is the input for getting GCP organization details.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/gcp/manual/organization/{id}
type TfIdsecCCEGCPGetOrganization struct {
	// ID is the organization's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE organization onboarding ID."`
}

// TfIdsecCCEGCPOrganization represents the details of a GCP organization.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GcpGetOrgDetailsOutput
type TfIdsecCCEGCPOrganization struct {
	// ID is the CCE onboarding ID for the organization, used to uniquely identify this onboarding in CCE.
	ID string `json:"id" mapstructure:"id" desc:"CCE organization onboarding ID."`
	// ProjectID is the GCP project ID of the "hub" project used to create the Workload Identity Federation
	// resources for the organization. This is not a child project of the organization.
	ProjectID string `json:"projectId" mapstructure:"project_id" desc:"GCP project ID of the hub project used to create the Workload Identity Federation resources for the organization."`
	// OrganizationID is the GCP organization identifier (numeric).
	OrganizationID string `json:"organizationId" mapstructure:"organization_id" desc:"GCP organization ID."`
	// OnboardingType indicates how the organization was onboarded: "standard" (UI), "programmatic" (API), or "terraform_provider".
	OnboardingType string `json:"onboardingType" mapstructure:"onboarding_type" desc:"Onboarding type: standard (UI), programmatic (API), or terraform_provider." possible_values:"standard,programmatic,terraform_provider."`
	// Region is the cloud region where CCE resources were created (nullable).
	Region string `json:"region,omitempty" mapstructure:"region,omitempty" desc:"The region where CCE resources are deployed."`
	// DisplayName is the human-readable display name shown in the CCE UI (nullable).
	DisplayName string `json:"displayName,omitempty" mapstructure:"display_name,omitempty" desc:"Display name shown in the CCE UI."`
	// Parameters contains service-specific configuration parameters, keyed by service name (nullable).
	Parameters map[string]map[string]interface{} `json:"parameters,omitempty" mapstructure:"parameters,omitempty" desc:"A key-value map of service-specific configuration parameters, keyed by service name."`
	// Status is the overall onboarding status (e.g., "Completely added", "Partially added", "Failed to add") (nullable).
	Status string `json:"status,omitempty" mapstructure:"status,omitempty" desc:"Onboarding status: Completely added, Partially added, Failed to add."`
	// Services is the list of onboarded service names (e.g., ["dpa", "sca"]).
	Services []string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"List of services (SIA, SCA, SecretsHub, CDS)."`
	// ServicesData contains detailed information about each onboarded service.
	ServicesData []ccemodels.IdsecCCEOnboardedService `json:"servicesData,omitempty" mapstructure:"services_data,omitempty" desc:"Detailed information about each onboarded service."`
}
