package secrets

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubsecretsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secrets/actions"
)

// ServiceConfig is the configuration for the Secrets Hub secrets service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-secrets",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			sechubsecretsactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SecHub secrets service.
var ServiceGenerator = NewIdsecSecHubSecretsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
