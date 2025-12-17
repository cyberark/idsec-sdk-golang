package directories

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitydirectoriesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/actions"
)

// ServiceConfig is the configuration for the identity users service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-directories",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			identitydirectoriesactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityDirectoriesService.
var ServiceGenerator = NewIdsecIdentityDirectoriesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
