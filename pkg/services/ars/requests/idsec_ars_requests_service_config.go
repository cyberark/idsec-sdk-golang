package requests

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/actions"
)

// ServiceConfig is the configuration for the ARS requests service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "ars-requests",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecARSRequestsService.
var ServiceGenerator = NewIdsecARSRequestsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
