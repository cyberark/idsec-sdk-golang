package workspaces

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siaworkspacesdbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/actions"
	siaworkspacestargetsetsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/targetsets/actions"
)

// CLIAction is a struct that defines the SIA Workspaces action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "workspaces",
		ActionDescription: "SIA Workspaces Actions",
		ActionVersion:     1,
	},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		siaworkspacestargetsetsactions.CLIAction,
		siaworkspacesdbactions.CLIAction,
	},
}

// ServiceConfig is the configuration for the sia workspaces services.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-workspaces",
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
