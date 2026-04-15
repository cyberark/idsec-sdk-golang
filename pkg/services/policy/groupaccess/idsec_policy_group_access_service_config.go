package groupaccess

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/actions"
)

// ServiceConfig defines the service configuration for IdsecPolicyGroupAccessService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy-group-access",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecPolicyGroupAccessService.
var ServiceGenerator = NewIdsecPolicyGroupAccessService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
