package uap

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uapactions "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/actions"
)

// ServiceConfig is the configuration for the uap service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "uap",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			uapactions.CLIAction,
		},
	},
}

// ServiceGenerator is the default service generator for the uap service.
var ServiceGenerator = NewIdsecUAPService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
