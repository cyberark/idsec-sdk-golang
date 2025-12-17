package sso

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siassoactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/actions"
)

// ServiceConfig is the configuration for the SSO service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-sso",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siassoactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA SSO service.
var ServiceGenerator = NewIdsecSIASSOService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
