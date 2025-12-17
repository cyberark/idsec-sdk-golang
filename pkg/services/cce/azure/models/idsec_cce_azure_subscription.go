package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEAzureAddSubscription is the input for adding an Azure Subscription manually.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AzureProgrammaticGeneralOnboardInput
type TfIdsecCCEAzureAddSubscription struct {
	EntraID          string                           `json:"entraId" mapstructure:"entra_id" validate:"required,uuid" desc:"Microsoft Entra tenant ID (UUID format)"`
	EntraTenantName  string                           `json:"entraTenantName" mapstructure:"entra_tenant_name" validate:"required" desc:"Microsoft Entra tenant name"`
	SubscriptionID   string                           `json:"id" mapstructure:"subscription_id" validate:"required" desc:"Azure Subscription ID"`
	SubscriptionName string                           `json:"subscriptionName" mapstructure:"subscription_name" validate:"required" desc:"Azure Subscription name"`
	Services         []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
}

// TfIdsecCCEAzureSubscription represents the details of an Azure Subscription.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AzureGetSubscriptionDetailsOutput
type TfIdsecCCEAzureSubscription struct {
	ID                  string                            `json:"id" mapstructure:"id" desc:"CCE onboarding ID"`
	OnboardingType      string                            `json:"onboardingType" mapstructure:"onboarding_type" desc:"Onboarding type: standard (UI), programmatic (API), or terraform_provider" choices:"standard,programmatic,terraform_provider"`
	Region              string                            `json:"region" mapstructure:"region" desc:"Deployment region where CCE resources were created"`
	DisplayName         string                            `json:"displayName,omitempty" mapstructure:"display_name,omitempty" desc:"Human-readable display name shown in CCE UI"`
	Parameters          map[string]map[string]interface{} `json:"parameters,omitempty" mapstructure:"parameters,omitempty" desc:"Service-specific configuration parameters, keyed by service name"`
	Status              string                            `json:"status" mapstructure:"status" desc:"Overall onboarding status (e.g., Completely added, Partially added, Failed to add)"`
	ConsentData         []map[string]interface{}          `json:"consentData,omitempty" mapstructure:"consent_data,omitempty" desc:"Consent data for service applications"`
	SubscriptionID      string                            `json:"subscriptionId" mapstructure:"subscription_id" desc:"Azure Subscription ID"`
	EntraID             string                            `json:"entraId,omitempty" mapstructure:"entra_id,omitempty" desc:"Microsoft Entra tenant ID"`
	EntraName           string                            `json:"entraName,omitempty" mapstructure:"entra_name,omitempty" desc:"Microsoft Entra tenant name"`
	ManagementGroupId   string                            `json:"managementGroupId,omitempty" mapstructure:"management_group_id,omitempty" desc:"Azure Management Group ID"`
	ManagementGroupName string                            `json:"managementGroupName,omitempty" mapstructure:"management_group_name,omitempty" desc:"Azure Management Group name"`
}

// TfIdsecCCEAzureGetSubscription is the input for getting Azure Subscription details.
// OPENAPI-CORRELATION: Input for GET /api/azure/manual/subscription/{id}
type TfIdsecCCEAzureGetSubscription struct {
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the Subscription"`
}

// TfIdsecCCEAzureUpdateSubscription is the input for updating an Azure Subscription's services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Custom input combining multiple endpoints
type TfIdsecCCEAzureUpdateSubscription struct {
	// ID is the Subscription's onboarding ID.
	ID string `json:"id,omitempty" mapstructure:"id,omitempty" desc:"Subscription's onboarding ID"`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
}

// TfIdsecCCEAzureDeleteSubscription is the input for deleting an Azure Subscription.
// OPENAPI-CORRELATION: Input for DELETE /api/azure/manual/{id}
type TfIdsecCCEAzureDeleteSubscription struct {
	// ID is the Subscription's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the Subscription to delete"`
}
