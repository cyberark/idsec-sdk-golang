package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// IdsecCCEGCPAddOutput is the output returned after adding a GCP manual onboarding.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GcpProgrammaticGeneralOnboardOutput
type IdsecCCEGCPAddOutput struct {
	// ID is the onboarding ID for the created resource.
	ID string `json:"id" mapstructure:"id" desc:"CCE onboarding ID for the created resource."`
}

// TfIdsecCCEGCPResources represents the Workload Identity Federation resources required for organization onboarding.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
type TfIdsecCCEGCPResources struct {
	// The {4,32} quantifier's comma must be written as the UTF-8 hex escape 0x2C (see go-playground/validator's
	// doc.go) or it gets misread as a tag separator and panics when the struct is first validated.
	WorkloadIdentityPoolID     string `json:"workloadIdentityPoolId" mapstructure:"workload_identity_pool_id" validate:"required,pattern=^[a-z0-9-]{40x2C32}$" desc:"GCP workload identity pool ID."`
	WorkloadIdentityProviderID string `json:"workloadIdentityProviderId" mapstructure:"workload_identity_provider_id" validate:"required,pattern=^[a-z0-9-]{40x2C32}$" desc:"GCP workload identity provider ID."`
	TargetServiceAccountEmail  string `json:"targetServiceAccountEmail" mapstructure:"target_service_account_email" validate:"required,email" desc:"GCP target service account email."`
}

// TfIdsecCCEGCPAddOrganization is the input for adding a GCP organization manually.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GcpProgrammaticGeneralOnboardInput
type TfIdsecCCEGCPAddOrganization struct {
	// DeploymentProjectID is the GCP project ID of the "hub" project used to host the
	// Workload Identity Federation resources for the organization.
	// GCP project IDs are lowercase strings (e.g. "my-hub-project-42"), not numbers.
	// The {4,28} quantifier comma is hex-escaped (0x2C) to avoid go-playground/validator
	// misreading it as a tag separator (see go-playground/validator doc.go).
	DeploymentProjectID string `json:"deploymentProjectId" mapstructure:"deployment_project_id" validate:"required,pattern=^[a-z][a-z0-9-]{40x2C28}[a-z0-9]$" desc:"GCP project ID of the hub project used to create the Workload Identity Federation resources."`
	// OrganizationID is the GCP organization identifier (numeric).
	OrganizationID string `json:"organizationId" mapstructure:"organization_id" validate:"required,pattern=^[1-9][0-9]{70x2C18}$" desc:"GCP organization ID (8-19 numeric digits, no leading zero) that the project belongs to."`
	// ProjectNumber is the numeric GCP project number.
	ProjectNumber string `json:"projectNumber" mapstructure:"project_number" validate:"required,number" desc:"GCP project number."`
	// Services is the list of services to onboard with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add (SIA, SCA, SecretsHub, CDS) and their associated resources."`
	// CCEResources contains the Workload Identity Federation resources required for organization onboarding.
	CCEResources TfIdsecCCEGCPResources `json:"cceResources" mapstructure:"cce_resources" validate:"required" desc:"CCE WIF resources: workload_identity_pool_id, workload_identity_provider_id, target_service_account_email."`
}

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

// TfIdsecCCEGCPUpdateOrganization is the input for updating a GCP organization's services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Custom input combining POST/DELETE /api/gcp/manual/{id}/services
type TfIdsecCCEGCPUpdateOrganization struct {
	// ID is the organization's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE organization onboarding ID."`
	// Services is the desired list of services with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (SIA, SCA, SecretsHub, CDS) and their associated resources."`
}

// TfIdsecCCEGCPDeleteOrganization is the input for deleting a GCP organization.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/gcp/manual/{id}
type TfIdsecCCEGCPDeleteOrganization struct {
	// ID is the organization's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE organization onboarding ID."`
}
