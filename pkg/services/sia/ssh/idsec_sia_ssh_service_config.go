package ssh

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/ssh/actions"
)

// ServiceConfig is the configuration for the IdsecSIASSHService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-ssh",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that creates a new instance of the SIA SSH service.
var ServiceGenerator = NewIdsecSIASSHService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
