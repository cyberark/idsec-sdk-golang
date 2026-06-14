package pamshaccounts

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/actions"
)

// ServiceConfig is the configuration for the pamsh accounts service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pamsh-accounts",
	RequiredAuthenticatorNames: []string{"pvwa"},
	OptionalAuthenticatorNames: []string{},
	Enabled:                    enabled(false),
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator constructs IdsecPamshAccountsService instances for the SDK registry.
var ServiceGenerator = NewIdsecPamshAccountsService

func init() {
	if err := services.Register(ServiceConfig, false); err != nil {
		panic(err)
	}
}

func enabled(b bool) *bool {
	return &b
}
