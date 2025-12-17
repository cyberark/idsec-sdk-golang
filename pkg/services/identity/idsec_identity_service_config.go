package identity

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitydirectoriesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/actions"
	identityrolesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/actions"
	identityusersactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/actions"
)

// CLIAction is a struct that defines the identity action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "identity",
		ActionDescription: "Identity provides a single centralized interface for provisioning users and setting up the authentication for users of the Shared Services platform.",
		ActionVersion:     1,
	},
	ActionAliases: []string{"idaptive", "id"},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		identitydirectoriesactions.CLIAction,
		identityrolesactions.CLIAction,
		identityusersactions.CLIAction,
	},
}

// ServiceConfig is the configuration for the identity service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity",
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
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
