package cloudaccess

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	cloudaccessactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/actions"
)

// ServiceConfig defines the service configuration for IdsecPolicyCloudAccessService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy-cloud-access",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			cloudaccessactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			cloudaccessactions.TerraformActionCloudAccessResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			cloudaccessactions.TerraformActionCloudAccessDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecPolicyCloudAccessService.
var ServiceGenerator = NewIdsecPolicyCloudAccessService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
