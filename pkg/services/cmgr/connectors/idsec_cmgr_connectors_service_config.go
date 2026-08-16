package connectors

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	connectorsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/connectors/actions"
)

// ServiceConfig is the configuration for the CMGR connector management service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cmgr-connectors",
	RequiredAuthenticatorNames: []string{},
	OptionalAuthenticatorNames: []string{"isp"},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              connectorsactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of IdsecCmgrConnectorsService.
var ServiceGenerator = NewIdsecCmgrConnectorsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
