package configuration

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubconfigurationactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/configuration/actions"
)

// ServiceConfig is the configuration for the Secrets Hub Configuration service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-configuration",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			sechubconfigurationactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SecHub Configuration service.
var ServiceGenerator = NewIdsecSecHubConfigurationService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
