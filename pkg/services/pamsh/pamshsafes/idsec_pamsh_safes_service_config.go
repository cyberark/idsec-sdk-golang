package pamshsafes

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/actions"
)

// ServiceConfig is the configuration for the pamsh safes service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pamsh-safes",
	RequiredAuthenticatorNames: []string{"pvwa"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
	Enabled:                    enabled(false),
}

// ServiceGenerator constructs IdsecPamshSafesService instances for the SDK registry.
var ServiceGenerator = NewIdsecPamshSafesService

func init() {
	if err := services.Register(ServiceConfig, false); err != nil {
		panic(err)
	}
}

func enabled(b bool) *bool {
	return &b
}
