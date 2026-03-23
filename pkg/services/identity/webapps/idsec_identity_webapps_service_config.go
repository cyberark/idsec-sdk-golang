package webapps

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitywebappssactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/actions"
)

// ServiceConfig is the configuration for the identity webapps service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-webapps",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeTerraformResource: {
			identitywebappssactions.TerraformActionWebappResource,
			identitywebappssactions.TerraformActionWebappPermissionResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			identitywebappssactions.TerraformActionWebappDataSource,
			identitywebappssactions.TerraformActionWebappPermissionDataSource,
			identitywebappssactions.TerraformActionWebappPermissionsDataSource,
			identitywebappssactions.TerraformActionWebappTemplateDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityWebappsService.
var ServiceGenerator = NewIdsecIdentityWebappsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
