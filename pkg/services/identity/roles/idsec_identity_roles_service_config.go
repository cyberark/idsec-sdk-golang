package roles

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identityrolesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/actions"
)

// ServiceConfig is the configuration for the identity users service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-roles",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			identityrolesactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityRolesService.
var ServiceGenerator = NewIdsecIdentityRolesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
