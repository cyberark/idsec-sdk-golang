package poolidentifiers

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolidentifiers/actions"
)

// ServiceConfig is the configuration for the CMGR pool identifiers service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cmgr-pool-identifiers",
	RequiredAuthenticatorNames: []string{},
	OptionalAuthenticatorNames: []string{"isp"},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecCmgrPoolIdentifiersService.
var ServiceGenerator = NewIdsecCmgrPoolIdentifiersService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
