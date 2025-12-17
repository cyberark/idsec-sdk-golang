package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEAWSGetOrganization is the input for getting AWS organization details.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/aws/programmatic/organization/{id}
type TfIdsecCCEAWSGetOrganization struct {
	ID string `json:"id" mapstructure:"id" desc:"Organization's onboarding ID"`
}

// TfIdsecCCEAWSOrganization represents the details of an AWS organization.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GetAwsOrganizationDetailsOutput
type TfIdsecCCEAWSOrganization struct {
	ID                  string                            `json:"id" mapstructure:"id" desc:"Organization's onboarding ID"`
	OrganizationRootID  string                            `json:"organizationRootId" mapstructure:"organization_root_id" desc:"Root ID of the AWS organization"`
	ManagementAccountID string                            `json:"managementAccountId" mapstructure:"management_account_id" desc:"Management account ID of the AWS organization"`
	OrganizationID      string                            `json:"organizationId" mapstructure:"organization_id" desc:"AWS organization ID"`
	OnboardingType      string                            `json:"onboardingType" mapstructure:"onboarding_type" choices:"standard,programmatic,terraform_provider" desc:"Type of onboarding process used"`
	Region              string                            `json:"region,omitempty" mapstructure:"region,omitempty" desc:"AWS region where the organization is located"`
	DisplayName         string                            `json:"displayName,omitempty" mapstructure:"display_name,omitempty" desc:"Display name for the organization"`
	Parameters          map[string]map[string]interface{} `json:"parameters,omitempty" mapstructure:"parameters" desc:"Service-specific configuration parameters, keyed by service name"`
	Status              string                            `json:"status,omitempty" mapstructure:"status,omitempty" choices:"Removing,Deploying resources,Waiting for deployment,Partially added,Failed to add,Service Error,Completely added" desc:"Overall onboarding status of the organization"`
	LastSuccessfulScan  string                            `json:"lastSuccessfulScan,omitempty" mapstructure:"last_successful_scan,omitempty" desc:"Timestamp of the last successful organization scan (RFC3339 format)"`
}

// TfIdsecCCEAWSAddOrganization is the input for adding an AWS organization programmatically.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AwsProgrammaticCreateOrganizationInput
type TfIdsecCCEAWSAddOrganization struct {
	OrganizationRootID         string                           `json:"organizationRootId" mapstructure:"organization_root_id" validate:"required,pattern=^r-[0-9a-z]{4,32}$"`
	ManagementAccountID        string                           `json:"managementAccountId" mapstructure:"management_account_id" validate:"required,pattern=^\\d{12}$"`
	OrganizationID             string                           `json:"organizationId" mapstructure:"organization_id" validate:"required,pattern=^o-[a-z0-9]{10,32}$"`
	Services                   []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required"`
	OrganizationDisplayName    string                           `json:"organizationDisplayName,omitempty" mapstructure:"organization_display_name,omitempty"`
	ScanOrganizationRoleArn    string                           `json:"scanOrganizationRoleArn" mapstructure:"scan_organization_role_arn" validate:"required,pattern=arn:aws:iam::\\d{12}:role/.+"`
	CrossAccountRoleExternalID string                           `json:"crossAccountRoleExternalId" mapstructure:"cross_account_role_external_id" validate:"required,pattern=cyberark-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"`
	DeploymentRegion           string                           `json:"deploymentRegion,omitempty" mapstructure:"region,omitempty"`
}

// TfIdsecCCEAWSAddOrganizationOutput is the output from adding an AWS organization.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AwsProgrammaticCreateOrganizationOutput
type TfIdsecCCEAWSAddOrganizationOutput struct {
	ID string `json:"id" mapstructure:"id" desc:"Organization's onboarding ID"`
}

// TfIdsecCCEAWSUpdateOrganization is the input for updating an AWS organization's services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Custom input combining multiple endpoints
type TfIdsecCCEAWSUpdateOrganization struct {
	// ID is the organization's onboarding ID.
	ID string `json:"id,omitempty" mapstructure:"id" desc:"Organization's onboarding ID (e.g., ef858a2d8f8f4f1781578089bb4ea010)"`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
}

// TfIdsecCCEAWSAddOrganizationServices is the input for adding services to an AWS organization.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AwsProgrammaticAddServicesOrgBodyInput + path parameter
type TfIdsecCCEAWSAddOrganizationServices struct {
	// ID is the organization's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"Organization's onboarding ID"`
	// Services is the list of services to add with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add with their resource configurations"`
}

// TfIdsecCCEAWSDeleteOrganizationServices is the input for deleting services from an AWS organization.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for DELETE /api/aws/programmatic/organization/{id}/services
type TfIdsecCCEAWSDeleteOrganizationServices struct {
	// ID is the organization's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"Organization's onboarding ID"`
	// ServiceNames is the list of service names to remove (e.g., ["dpa", "sca"]).
	ServiceNames []string `json:"serviceNames" mapstructure:"service_names" validate:"required,min=1" desc:"List of service names to remove (e.g., dpa, sca)"`
}

// TfIdsecCCEAWSOrganizationDatasource represents the details of an AWS organization with services information.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GetAwsOrganizationDetailsOutput
type TfIdsecCCEAWSOrganizationDatasource struct {
	TfIdsecCCEAWSOrganization `mapstructure:",squash"`
	// Services is the list of onboarded service names (e.g., ["dpa", "sca"]) from the API
	Services []string `json:"services" mapstructure:"services" desc:"List of onboarded service names (e.g., dpa, sca)"`
	// ServicesData contains detailed information about each onboarded service
	ServicesData []ccemodels.IdsecCCEOnboardedService `json:"servicesData" mapstructure:"services_data" desc:"Detailed information about each onboarded service"`
}
