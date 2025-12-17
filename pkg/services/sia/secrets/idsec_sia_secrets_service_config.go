package secrets

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siasecretsdbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/actions"
	siasecretsvmactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/actions"
)

// CLIAction is a struct that defines the SIA Secrets action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "secrets",
		ActionDescription: "SIA Secrets Actions",
		ActionVersion:     1,
	},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		siasecretsvmactions.CLIAction,
		siasecretsdbactions.CLIAction,
	},
}

// ServiceConfig is the configuration for the sia secrets services.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-secrets",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			CLIAction,
		},
	},
}

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
