package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEGCPGetProject is the input for getting GCP Project details.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/gcp/manual/project/{id}
type TfIdsecCCEGCPGetProject struct {
	// ID is the project's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE project onboarding ID."`
}

// TfIdsecCCEGCPProject represents the details of a GCP Project.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GcpGetProjectDetailsOutput
type TfIdsecCCEGCPProject struct {
	// ID is the CCE onboarding ID for the project, used to uniquely identify this onboarding in CCE.
	ID string `json:"id" mapstructure:"id" desc:"CCE project onboarding ID."`
	// ProjectID is the GCP project identifier.
	ProjectID string `json:"projectId" mapstructure:"project_id" desc:"GCP project ID."`
	// OnboardingType indicates how the project was onboarded: "standard" (UI), "programmatic" (API), or "terraform_provider".
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
	// OrganizationID is the CCE onboarding ID of the parent GCP organization if this project belongs to one (nullable).
	OrganizationID string `json:"organizationId,omitempty" mapstructure:"organization_id,omitempty" desc:"CCE onboarding ID of the parent GCP organization."`
	// OrganizationName is the display name of the parent GCP organization if this project belongs to one (nullable).
	OrganizationName string `json:"organizationName,omitempty" mapstructure:"organization_name,omitempty" desc:"Display name of the parent GCP organization shown in the CCE UI."`
	// DuplicatedServices lists services that are deployed both in this project and in a parent organization (nullable).
	DuplicatedServices *[]string `json:"duplicatedServices,omitempty" mapstructure:"duplicated_services,omitempty" desc:"Service resources deployed to this project and to the parent organization."`
}
