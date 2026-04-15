package networks

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/networks/actions"
)

// ServiceConfig is the configuration for the CMGR networks service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cmgr-networks",
	RequiredAuthenticatorNames: []string{},
	OptionalAuthenticatorNames: []string{"isp"},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecCmgrNetworksService.
var ServiceGenerator = NewIdsecCmgrNetworksService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
