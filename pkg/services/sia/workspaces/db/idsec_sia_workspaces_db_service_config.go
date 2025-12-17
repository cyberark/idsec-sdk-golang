package db

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siaworkspacesdbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/actions"
)

// ServiceConfig is the configuration for the SIA db workspace service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-workspaces-db",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siaworkspacesdbactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siaworkspacesdbactions.TerraformActionWorkspacesDBResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			siaworkspacesdbactions.TerraformActionWorkspacesDBDataSource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA Workspaces DB service.
var ServiceGenerator = NewIdsecSIAWorkspacesDBService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
