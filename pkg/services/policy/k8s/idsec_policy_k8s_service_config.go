package k8s

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// ServiceConfig registers the policy-k8s backend used for K8s cluster policies.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "policy-k8s",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              map[string]interface{}{},
}

// ServiceGenerator is the function that generates a new instance of IdsecPolicyK8sService.
var ServiceGenerator = NewIdsecPolicyK8sService

func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
