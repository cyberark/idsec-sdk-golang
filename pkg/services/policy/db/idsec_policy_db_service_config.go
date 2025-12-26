package db

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	policydbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/actions"
)

// ServiceConfig defines the service configuration for IdsecPolicyDBService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy-db",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			policydbactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			policydbactions.TerraformActionDBResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			policydbactions.TerraformActionDBDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecPolicyDBService.
var ServiceGenerator = NewIdsecPolicyDBService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
