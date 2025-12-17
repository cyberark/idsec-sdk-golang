package shortenedconnectionstring

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siashortenedconnectionstringactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring/actions"
)

// ServiceConfig is the configuration for the IdsecSIAShortenedConnectionStringService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-shortened-connection-string",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siashortenedconnectionstringactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA Shortened Connection String service.
var ServiceGenerator = NewIdsecSIAShortenedConnectionStringService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
