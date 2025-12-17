package filters

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubfiltersactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/filters/actions"
)

// ServiceConfig is the configuration for the Secrets Hub filters service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-filters",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			sechubfiltersactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SecHub filters service.
var ServiceGenerator = NewIdsecSecHubFiltersService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
