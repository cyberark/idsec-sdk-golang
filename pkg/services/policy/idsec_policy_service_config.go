package policy

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	policyactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/actions"
)

// ServiceConfig is the configuration for the policy service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			policyactions.CLIAction,
		},
	},
}

// ServiceGenerator is the default service generator for the policy service.
var ServiceGenerator = NewIdsecPolicyService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
