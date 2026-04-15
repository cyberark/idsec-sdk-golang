package k8s

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/actions"
)

// ServiceConfig defines the service configuration for the SCA K8s service.
//
// ServiceName: "sca-k8s"
// RequiredAuthenticatorNames: Only "isp" is required for listing clusters.
// CLI actions are defined in the idsec-cli-golang repository.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sca-k8s",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator returns a new IdsecSCAK8sService instance. Provided for consistency with other service configs.
var ServiceGenerator = NewIdsecSCAK8sService

// init registers the SCA K8s service configuration at package load time.
func init() {
	if err := services.Register(ServiceConfig, false); err != nil {
		panic(err)
	}
}
