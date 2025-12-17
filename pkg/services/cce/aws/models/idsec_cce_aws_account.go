package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEAWSAddAccount is the input for adding an AWS account programmatically.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AwsProgrammaticCreateAccountInput
type TfIdsecCCEAWSAddAccount struct {
	// AccountID is the AWS account ID (12 digits). Can be found under the user name menu in the upper right corner of the AWS console.
	AccountID string `json:"accountId" mapstructure:"account_id" validate:"required,len=12,numeric" desc:"AWS account ID (12 digits) found in the upper right corner of AWS console"`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
	// AccountDisplayName is the optional display name for the account that will appear in the CCE UI.
	AccountDisplayName string `json:"accountDisplayName,omitempty" mapstructure:"account_display_name" desc:"Optional display name for the account shown in CCE UI"`
	// DeploymentRegion is the AWS region where resources will be created (e.g., "us-east-1"). If not specified, the tenant region will be used.
	DeploymentRegion string `json:"deploymentRegion,omitempty" mapstructure:"deployment_region" desc:"AWS region for deployment (e.g., us-east-1). Uses tenant region if not specified"`
	// OnboardingType is set programmatically and never populated from user input
	// The mapstructure:"-" tag tells mapstructure to ignore this field
	OnboardingType *string `json:"onboardingType,omitempty" mapstructure:"-" desc:"Onboarding type (set terraform_porvider, not from user input)" choices:"standard,programmatic,terraform_provider"`
}

// TfIdsecCCEAWSUpdateAccount is the input for updating an AWS account programmatically.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
type TfIdsecCCEAWSUpdateAccount struct {
	// ID is the GUID of the onboarded account without hyphens
	ID string `json:"id,omitempty" mapstructure:"id" desc:"GUID of the onboarded account without hyphens (e.g., ef858a2d8f8f4f1781578089bb4ea010)"`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
}

// TfIdsecCCEAWSAddedAccount is the output returned after adding an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AwsProgrammaticCreateAccountOutput
type TfIdsecCCEAWSAddedAccount struct {
	// ID is the onboarding ID for the created account.
	ID string `json:"id" mapstructure:"id" desc:"CCE onboarding ID for the created account"`
}

// TfIdsecCCEAWSGetAccount is the input for getting AWS account details.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/aws/programmatic/account/{id}
type TfIdsecCCEAWSGetAccount struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the account"`
}

// TfIdsecCCEAWSAccount represents the details of an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GetAccountDetailsOutput
type TfIdsecCCEAWSAccount struct {
	// ID is the CCE onboarding ID for the account, used to uniquely identify this onboarding in CCE.
	ID string `json:"id" mapstructure:"id" desc:"CCE onboarding ID for the account"`
	// AccountID is the AWS account ID (12 digits).
	AccountID string `json:"accountId" mapstructure:"account_id" desc:"AWS account ID (12 digits)"`
	// OnboardingType indicates how the account was onboarded: "standard" (UI), "programmatic" (API), or "terraform_provider".
	OnboardingType string `json:"onboardingType" mapstructure:"onboarding_type" desc:"Onboarding type: standard (UI), programmatic (API), or terraform" choices:"standard,programmatic,terraform_provider"`
	// Region is the AWS deployment region where CCE resources were created (nullable).
	Region string `json:"region,omitempty" mapstructure:"region" desc:"AWS deployment region where CCE resources were created"`
	// Services is the list of onboarded service names (e.g., ["dpa", "sca"]) from the API
	ServiceNames []string `json:"services" mapstructure:"-" desc:"List of onboarded service names (e.g., dpa, sca)"`
	// DisplayName is the human-readable display name shown in the CCE UI (nullable).
	DisplayName string `json:"displayName,omitempty" mapstructure:"display_name" desc:"Human-readable display name shown in CCE UI"`
	// Parameters contains service-specific configuration parameters, keyed by service name (nullable).
	Parameters map[string]map[string]interface{} `json:"parameters,omitempty" mapstructure:"parameters" desc:"Service-specific configuration parameters, keyed by service name"`
	// Status is the overall onboarding status (e.g., "Completely added", "Partially added", "Failed to add") (nullable).
	Status string `json:"status,omitempty" mapstructure:"status" desc:"Overall onboarding status (e.g., Completely added, Partially added, Failed to add)"`
	// OrganizationID is the CCE onboarding ID of the parent AWS organization if this account belongs to one (nullable).
	OrganizationID string `json:"organizationId,omitempty" mapstructure:"organization_id" desc:"CCE onboarding ID of parent AWS organization if account belongs to one"`
	// OrganizationName is the display name of the parent AWS organization if this account belongs to one (nullable).
	OrganizationName string `json:"organizationName,omitempty" mapstructure:"organization_name" desc:"Display name of parent AWS organization if account belongs to one"`
	// DuplicatedServices lists services that are deployed both in this account and in a parent organization  (nullable).
	DuplicatedServices *[]string `json:"duplicatedServices,omitempty" mapstructure:"duplicated_services" desc:"Services deployed both in this account and in a parent organization"`
}

// TfIdsecCCEAWSDeleteAccount is the input for deleting an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/aws/programmatic/account/{id}
type TfIdsecCCEAWSDeleteAccount struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the account to delete"`
}

// TfIdsecCCEAWSAddAccountServices is the input for adding services to an AWS account.
// OPENAPI-CORRELATION: AwsProgrammaticAddServicesBodyInput + path parameter
type TfIdsecCCEAWSAddAccountServices struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the account"`
	// Services is the list of services to add with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add with their resource configurations"`
}

// TfIdsecCCEAWSDeleteAccountServices is the input for deleting services from an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/aws/programmatic/account/{id}/services
type TfIdsecCCEAWSDeleteAccountServices struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the account"`
	// ServiceNames is the list of service names to remove (e.g., ["dpa", "sca"]).
	ServiceNames []string `json:"servicesNames" mapstructure:"services_names" validate:"required,min=1" desc:"List of service names to remove (e.g., dpa, sca)"`
}
