package access

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siaaccessactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/actions"
)

// ServiceConfig is the configuration for the IdsecSIAAccessService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-access",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siaaccessactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siaaccessactions.TerraformActionAccessConnectorResource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA Access service.
var ServiceGenerator = NewIdsecSIAAccessService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
