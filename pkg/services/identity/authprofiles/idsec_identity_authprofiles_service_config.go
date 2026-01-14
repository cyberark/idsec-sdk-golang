package authprofiles

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	authprofilesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/actions"
)

// ServiceConfig is the configuration for the identity users service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-auth-profiles",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			authprofilesactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			authprofilesactions.TerraformActionAuthProfileResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			authprofilesactions.TerraformActionAuthProfileDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityAuthProfilesService.
var ServiceGenerator = NewIdsecIdentityAuthProfilesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
