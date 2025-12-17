package safes

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pcloudsafesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/actions"
)

// ServiceConfig is the configuration for the pcloud safes service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud-safes",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			pcloudsafesactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			pcloudsafesactions.TerraformActionSafeResource,
			pcloudsafesactions.TerraformActionSafeMemberResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			pcloudsafesactions.TerraformActionSafeDataSource,
			pcloudsafesactions.TerraformActionSafeMemberDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecPCloudSafesService.
var ServiceGenerator = NewIdsecPCloudSafesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
