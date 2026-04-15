package serviceinfo

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/serviceinfo/actions"
)

// ServiceConfig is the configuration for the Secrets Hub Service Info service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-serviceinfo",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that creates a new instance of the SecHub Service Info service.
var ServiceGenerator = NewIdsecSecHubServiceInfoService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
