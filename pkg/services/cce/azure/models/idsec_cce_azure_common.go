package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// IdsecCCEAzureAddManualServices is the input for adding services to an Azure manual onboarding.
// OPENAPI-CORRELATION: AzureProgrammaticAddServicesBodyInput + path parameter
type IdsecCCEAzureAddManualServices struct {
	// ID is the onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID."`
	// Services is the list of services to add with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to add (SIA, SCA, SecretsHub, CDS) and their associated resources."`
}

// IdsecCCEAzureDeleteManualServices is the input for deleting services from an Azure manual onboarding.
// OPENAPI-CORRELATION: Input for DELETE /api/azure/manual/{id}/services
type IdsecCCEAzureDeleteManualServices struct {
	// ID is the onboarding ID.
	ID string `json:"id" mapstructure:"id" validate:"required" desc:"CCE onboarding ID"`
	// ServiceNames is the list of service names to remove (e.g., ["dpa", "sca"]).
	ServiceNames []string `json:"serviceNames" mapstructure:"service_names" validate:"required,min=1" desc:"List of services to remove (SIA, SCA, SecretsHub, CDS)."`
}
