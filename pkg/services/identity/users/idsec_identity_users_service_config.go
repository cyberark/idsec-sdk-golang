package users

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identityusersactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/actions"
)

// ServiceConfig is the configuration for the identity users service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-users",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			identityusersactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityUsersService.
var ServiceGenerator = NewIdsecIdentityUsersService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
