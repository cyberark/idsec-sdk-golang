package vm

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	policyvmactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/actions"
)

// ServiceConfig defines the service configuration for IdsecPolicyVMService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy-vm",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			policyvmactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			policyvmactions.TerraformActionVMResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			policyvmactions.TerraformActionVMDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the Policy VM service.
var ServiceGenerator = NewIdsecPolicyVMService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
