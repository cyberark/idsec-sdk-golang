package cmgr

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	cmgractions "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/actions"
)

// ServiceConfig is the configuration for the connector management service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cmgr",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			cmgractions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			cmgractions.TerraformActionNetworkResource,
			cmgractions.TerraformActionPoolResource,
			cmgractions.TerraformActionPoolIdentifierResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			cmgractions.TerraformActionNetworkDataSource,
			cmgractions.TerraformActionPoolDataSource,
			cmgractions.TerraformActionPoolIdentifierDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecCmgrService.
var ServiceGenerator = NewIdsecCmgrService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
