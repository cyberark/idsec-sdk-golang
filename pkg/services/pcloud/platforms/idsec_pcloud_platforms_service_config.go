package platforms

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pcloudplatformsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/actions"
)

// ServiceConfig is the configuration for the pcloud platforms service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud-platforms",
	RequiredAuthenticatorNames: []string{},
	OptionalAuthenticatorNames: []string{"isp"},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			pcloudplatformsactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			pcloudplatformsactions.TerraformActionTargetPlatformResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			pcloudplatformsactions.TerraformActionTargetPlatformDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecPCloudPlatformsService.
var ServiceGenerator = NewIdsecPCloudPlatformsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
