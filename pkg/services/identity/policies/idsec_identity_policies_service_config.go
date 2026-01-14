package policies

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	policiesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies/actions"
)

// ServiceConfig is the configuration for the identity policies service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-policies",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			policiesactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			policiesactions.TerraformActionPolicyResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			policiesactions.TerraformActionPolicyDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityPoliciesService.
var ServiceGenerator = NewIdsecIdentityPoliciesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
