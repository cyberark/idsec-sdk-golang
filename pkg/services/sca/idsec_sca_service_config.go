package sca

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scaactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/actions"
)

// ServiceConfig defines the service configuration for the standalone SCA service.
//
// ServiceName: "sca" (distinct from the UAP SCA service "uap-sca").
// RequiredAuthenticatorNames: Only "isp" is required to perform discovery operations.
// ActionsConfigurations: Exposes only a Terraform Data Source action for SCA discovery.
// No CLI or resource CRUD actions are registered for the standalone service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sca",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeTerraformDataSource: {
			scaactions.TerraformActionSCADiscoveryDataSource,
		},
	},
}

// ServiceGenerator returns a new IdsecSCAService instance. Provided for consistency with other service configs.
var ServiceGenerator = NewIdsecSCAService

// init registers the standalone SCA service configuration at package load time.
func init() {
	if err := services.Register(ServiceConfig, false); err != nil {
		panic(err)
	}
}
