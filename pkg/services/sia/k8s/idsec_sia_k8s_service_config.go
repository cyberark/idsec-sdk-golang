package k8s

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siak8sactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/k8s/actions"
)

// ServiceConfig is the configuration for the IdsecSIAK8SService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-k8s",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siak8sactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA K8S service.
var ServiceGenerator = NewIdsecSIAK8SService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
