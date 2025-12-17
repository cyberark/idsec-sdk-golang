package db

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siadbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/db/actions"
)

// ServiceConfig is the configuration for the IdsecSIADBService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-db",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siadbactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA DB service.
var ServiceGenerator = NewIdsecSIADBService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
