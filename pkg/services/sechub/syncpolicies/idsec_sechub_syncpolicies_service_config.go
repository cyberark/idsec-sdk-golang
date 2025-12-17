package syncpolicies

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubsyncpoliciesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/actions"
)

// ServiceConfig is the configuration for the Secrets Hub Sync Policies service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-syncpolicies",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			sechubsyncpoliciesactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SecHub Sync Policies service.
var ServiceGenerator = NewIdsecSecHubSyncPoliciesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
