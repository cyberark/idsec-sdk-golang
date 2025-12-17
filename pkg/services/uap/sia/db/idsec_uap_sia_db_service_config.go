package db

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uapsiadbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/actions"
)

// ServiceConfig defines the service configuration for IdsecUAPSIADBService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "uap-db",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			uapsiadbactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			uapsiadbactions.TerraformActionDBResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			uapsiadbactions.TerraformActionDBDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecUAPSIADBService.
var ServiceGenerator = NewIdsecUAPSIADBService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
