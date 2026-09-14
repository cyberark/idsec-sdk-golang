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
	// mapstructure is intentionally "-": this name collides with the Dynamic "services"
	// attribute on the create/update inputs (TfIdsecCCEGCPAddProject/TfIdsecCCEGCPUpdateProject).
	// Exposing it here would let a Terraform Read overwrite the user's configured services
	// with this bare name list on every refresh. Use ServicesData for the onboarded-service view.
	Services []string `json:"services,omitempty" mapstructure:"-" desc:"List of services (SIA, SCA, SecretsHub, CDS)."`
	// ServicesData contains detailed information about each onboarded service.
	ServicesData []ccemodels.IdsecCCEOnboardedService `json:"servicesData,omitempty" mapstructure:"services_data,omitempty" desc:"Detailed information about each onboarded service."`
	// OrganizationID is the CCE onboarding ID of the parent GCP organization if this project belongs to one (nullable).
	// mapstructure is intentionally "-": the manual-onboarding GET never echoes back the
	// numeric GCP organization ID sent on create (it is stored separately and omitted from
	// standalone-project responses), so surfacing this field would zero out the user's
	// configured organization_id on every Terraform refresh. Use OrganizationName instead.
	OrganizationID string `json:"organizationId,omitempty" mapstructure:"-" desc:"CCE onboarding ID of the parent GCP organization."`
	// OrganizationName is the display name of the parent GCP organization if this project belongs to one (nullable).
	OrganizationName string `json:"organizationName,omitempty" mapstructure:"organization_name,omitempty" desc:"Display name of the parent GCP organization shown in the CCE UI."`
	// DuplicatedServices lists services that are deployed both in this project and in a parent organization (nullable).
	DuplicatedServices *[]string `json:"duplicatedServices,omitempty" mapstructure:"duplicated_services,omitempty" desc:"Service resources deployed to this project and to the parent organization."`
}

// TfIdsecCCEGCPAddProject is the input for adding a GCP Project manually.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GcpProgrammaticGeneralOnboardInput
type TfIdsecCCEGCPAddProject struct {
	// ProjectID is the GCP project identifier to onboard.
	ProjectID string `json:"deploymentProjectId" mapstructure:"project_id" validate:"required,min=6,max=30" desc:"GCP project ID to onboard."`
	// OrganizationID is the GCP organization ID (8-19 numeric digits, no leading zero) that the project belongs to.
	// The validator splits the `validate` tag on literal commas before parsing individual rules, so the
	// {7,18} quantifier's comma must be written as the UTF-8 hex escape 0x2C (see go-playground/validator's
	// doc.go) or it gets misread as a tag separator and panics when the struct is first validated.
	OrganizationID string `json:"organizationId" mapstructure:"organization_id" validate:"required,pattern=^[1-9][0-9]{70x2C18}$" desc:"GCP organization ID (8-19 numeric digits, no leading zero) that the project belongs to."`
	// ProjectNumber is the numeric GCP project number.
	ProjectNumber string `json:"projectNumber" mapstructure:"project_number" validate:"required,number" desc:"GCP project number."`
	// Services is the list of services to add and their associated resources.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add (SIA, SCA, SecretsHub, CDS) and their associated resources."`
}

// TfIdsecCCEGCPUpdateProject is the input for updating a GCP Project's services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Custom input combining multiple endpoints
type TfIdsecCCEGCPUpdateProject struct {
	// ID is the Project's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE project onboarding ID."`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add (SIA, SCA, SecretsHub, CDS) and their associated resources."`
}

// TfIdsecCCEGCPDeleteProject is the input for deleting a GCP Project.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/gcp/manual/{id}
type TfIdsecCCEGCPDeleteProject struct {
	// ID is the Project's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE project onboarding ID."`
}
