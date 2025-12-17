package sm

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	smactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/actions"
)

// ServiceConfig is the configuration for the Session Monitoring service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sm",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			smactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the Session Monitoring service.
var ServiceGenerator = NewIdsecSMService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
