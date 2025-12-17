package secretstores

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubsecretstoresactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/actions"
)

// ServiceConfig is the configuration for the Secrets Hub Secret Stores service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-secretstores",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			sechubsecretstoresactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SecHub Secret Stores service.
var ServiceGenerator = NewIdsecSecHubSecretStoresService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
