package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEAzureAddEntra is the input for adding an Azure Entra tenant manually.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AzureProgrammaticGeneralOnboardInput
type TfIdsecCCEAzureAddEntra struct {
	EntraID         string                           `json:"entraId" mapstructure:"entra_id" validate:"required,uuid" desc:"Microsoft Entra tenant ID (UUID format)"`
	Services        []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
	CCEResources    map[string]interface{}           `json:"cceResources" mapstructure:"cce_resources" validate:"required" desc:"CCE resources configuration"`
}

// TfIdsecCCEAzureEntra represents the details of an Azure Entra tenant.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: AzureGetEntraDetailsOutput
type TfIdsecCCEAzureEntra struct {
	ID             string                            `json:"id" mapstructure:"id" desc:"CCE onboarding ID"`
	OnboardingType string                            `json:"onboardingType" mapstructure:"onboarding_type" desc:"Onboarding type: standard (UI), programmatic (API), or terraform_provider" choices:"standard,programmatic,terraform_provider"`
	Region         string                            `json:"region" mapstructure:"region" desc:"Deployment region where CCE resources were created"`
	DisplayName    string                            `json:"displayName,omitempty" mapstructure:"display_name,omitempty" desc:"Human-readable display name shown in CCE UI"`
	Parameters     map[string]map[string]interface{} `json:"parameters,omitempty" mapstructure:"parameters,omitempty" desc:"Service-specific configuration parameters, keyed by service name"`
	Status         string                            `json:"status" mapstructure:"status" desc:"Overall onboarding status (e.g., Completely added, Partially added, Failed to add)"`
	ConsentData    []map[string]interface{}          `json:"consentData,omitempty" mapstructure:"consent_data,omitempty" desc:"Consent data for service applications"`
	EntraID        string                            `json:"entraId" mapstructure:"entra_id" desc:"Microsoft Entra tenant ID"`
}

// TfIdsecCCEAzureGetEntra is the input for getting Azure Entra tenant details.
// OPENAPI-CORRELATION: Input for GET /api/azure/manual/entra/{id}
type TfIdsecCCEAzureGetEntra struct {
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the Entra tenant"`
}

// TfIdsecCCEAzureUpdateEntra is the input for updating an Azure Entra tenant's services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Custom input combining multiple endpoints
type TfIdsecCCEAzureUpdateEntra struct {
	// ID is the Entra tenant's onboarding ID.
	ID string `json:"id,omitempty" mapstructure:"id,omitempty" desc:"Entra tenant's onboarding ID"`
	// Services is the list of services to onboard (e.g., DPA, SCA, SecretsHub, CDS) with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard (DPA, SCA, SecretsHub, CDS) with their resource configurations"`
}

// TfIdsecCCEAzureDeleteEntra is the input for deleting an Azure Entra tenant.
// OPENAPI-CORRELATION: Input for DELETE /api/azure/manual/{id}
type TfIdsecCCEAzureDeleteEntra struct {
	// ID is the Entra tenant's onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID of the Entra tenant to delete"`
}
