package discovery

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/discovery/actions"
)

// ServiceConfig defines the service configuration for the SCA discovery service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sca-discovery",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator returns a new IdsecSCADiscoveryService instance.
var ServiceGenerator = NewIdsecSCADiscoveryService

// init registers the SCA discovery service configuration at package load time.
func init() {
	if err := services.Register(ServiceConfig, false); err != nil {
		panic(err)
	}
}
