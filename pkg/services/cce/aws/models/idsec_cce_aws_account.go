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
	AccountID string `json:"accountId" mapstructure:"account_id" validate:"required,len=12,numeric" desc:"AWS account ID (12 digits) found in the upper right corner of the AWS console."`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add to the account (SIA, SCA, SecretsHub, CDS) and their associated resources."`
	// AccountDisplayName is the optional display name for the account that will appear in the CCE UI.
	AccountDisplayName string `json:"accountDisplayName,omitempty" mapstructure:"account_display_name" desc:"Optional name for the account shown in the CCE UI."`
	// DeploymentRegion is the AWS region where resources will be created (e.g., "us-east-1"). If not specified, the tenant region will be used.
	DeploymentRegion string `json:"deploymentRegion,omitempty" mapstructure:"deployment_region" desc:"AWS region where the account is deployed, for example, us-east-1. If not specified, the tenant region is used."`
	// OnboardingType is set programmatically and never populated from user input
	// The mapstructure:"-" tag tells mapstructure to ignore this field
	OnboardingType *string `json:"onboardingType,omitempty" mapstructure:"-" desc:"The method used to deploy resources in AWS (set to use Terraform Provider, not from user input)." possible_values:"standard, programmatic,terraform_provider."`
}

// TfIdsecCCEAWSUpdateAccount is the input for updating an AWS account programmatically.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
type TfIdsecCCEAWSUpdateAccount struct {
	// ID is the GUID of the onboarded account without hyphens
	ID string `json:"id,omitempty" mapstructure:"id" desc:"GUID of the added account without hyphens. For example, ef858a2d8f8f4f1781578089bb4ea010."`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add to the account (SIA, SCA, SecretsHub, CDS) and their associated resources."`
}

// TfIdsecCCEAWSAddedAccount is the output returned after adding an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AwsProgrammaticCreateAccountOutput
type TfIdsecCCEAWSAddedAccount struct {
	// ID is the onboarding ID for the created account.
	ID string `json:"id" mapstructure:"id" desc:"CCE account onboarding ID."`
}

// TfIdsecCCEAWSGetAccount is the input for getting AWS account details.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/aws/programmatic/account/{id}
type TfIdsecCCEAWSGetAccount struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE account onboarding ID."`
}

// TfIdsecCCEAWSAccount represents the details of an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GetAccountDetailsOutput
type TfIdsecCCEAWSAccount struct {
	// ID is the CCE onboarding ID for the account, used to uniquely identify this onboarding in CCE.
	ID string `json:"id" mapstructure:"id" desc:"CCE account onboarding ID."`
	// AccountID is the AWS account ID (12 digits).
	AccountID string `json:"accountId" mapstructure:"account_id" desc:"AWS account ID (12 digits)"`
	// OnboardingType indicates how the account was onboarded: "standard" (UI), "programmatic" (API), or "terraform_provider".
	OnboardingType string `json:"onboardingType" mapstructure:"onboarding_type" desc:"The method used to deploy resources in AWS: standard (UI), programmatic (API), or Terraform Provider." possible_values:"standard, programmatic, terraform_provider."`
	// Region is the AWS deployment region where CCE resources were created (nullable).
	Region string `json:"region,omitempty" mapstructure:"region" desc:"AWS region where CCE resources were created."`
	// Services is the list of onboarded service names (e.g., ["dpa", "sca"]) from the API
	ServiceNames []string `json:"services" mapstructure:"-" desc:"List of services (SIA, SCA, SecretsHub, CDS)."`
	// DisplayName is the human-readable display name shown in the CCE UI (nullable).
	DisplayName string `json:"displayName,omitempty" mapstructure:"display_name" desc:"Display name shown in the CCE UI."`
	// Parameters contains service-specific configuration parameters, keyed by service name (nullable).
	Parameters map[string]map[string]interface{} `json:"parameters,omitempty" mapstructure:"parameters" desc:"A key-value map of service-specific configuration parameters, keyed by service name."`
	// Status is the overall onboarding status (e.g., "Completely added", "Partially added", "Failed to add") (nullable).
	Status string `json:"status,omitempty" mapstructure:"status" desc:"Onboarding status: Completely added, Partially added, Failed to add."`
	// OrganizationID is the CCE onboarding ID of the parent AWS organization if this account belongs to one (nullable).
	OrganizationID string `json:"organizationId,omitempty" mapstructure:"organization_id" desc:"CCE onboarding ID of the parent AWS organization."`
	// OrganizationName is the display name of the parent AWS organization if this account belongs to one (nullable).
	OrganizationName string `json:"organizationName,omitempty" mapstructure:"organization_name" desc:"Display name of the parent AWS organization shown in the CCE UI."`
	// DuplicatedServices lists services that are deployed both in this account and in a parent organization  (nullable).
	DuplicatedServices *[]string `json:"duplicatedServices,omitempty" mapstructure:"duplicated_services" desc:"Service resources deployed to this account and to the parent organization."`
}

// TfIdsecCCEAWSDeleteAccount is the input for deleting an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/aws/programmatic/account/{id}
type TfIdsecCCEAWSDeleteAccount struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE account onboarding ID."`
}

// TfIdsecCCEAWSAddAccountServices is the input for adding services to an AWS account.
// OPENAPI-CORRELATION: AwsProgrammaticAddServicesBodyInput + path parameter
type TfIdsecCCEAWSAddAccountServices struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE account onboarding ID."`
	// Services is the list of services to add with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add to the account (SIA, SCA, SecretsHub, CDS) and their associated resources."`
}

// TfIdsecCCEAWSDeleteAccountServices is the input for deleting services from an AWS account.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/aws/programmatic/account/{id}/services
type TfIdsecCCEAWSDeleteAccountServices struct {
	// ID is the account's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE account onboarding ID."`
	// ServiceNames is the list of service names to remove (e.g., ["dpa", "sca"]).
	ServiceNames []string `json:"servicesNames" mapstructure:"services_names" validate:"required,min=1" desc:"List of services to remove from the account (SIA, SCA, SecretsHub, CDS)."`
}
