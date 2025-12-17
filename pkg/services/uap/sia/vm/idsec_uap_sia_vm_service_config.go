package vm

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uapsiavmactions "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/actions"
)

// ServiceConfig defines the service configuration for IdsecUAPSIAVMService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "uap-vm",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			uapsiavmactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			uapsiavmactions.TerraformActionVMResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			uapsiavmactions.TerraformActionVMDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the UAP SIA VM service.
var ServiceGenerator = NewIdsecUAPSIAVMService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
