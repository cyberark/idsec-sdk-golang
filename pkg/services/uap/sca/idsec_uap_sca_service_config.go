package sca

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uapscaactions "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sca/actions"
)

// ServiceConfig defines the service configuration for IdsecUAPSCAService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy-cloud-access",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			uapscaactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			uapscaactions.TerraformActionSCAResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			uapscaactions.TerraformActionSCADataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecUAPSCAService.
var ServiceGenerator = NewIdsecUAPSCAService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
