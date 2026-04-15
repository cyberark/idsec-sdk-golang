package dbstrongaccounts

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/dbstrongaccounts/actions"
)

// ServiceConfig is the configuration for the SIA DB strong accounts service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-db-strong-accounts",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that creates a new instance of the SIA DB strong accounts service.
var ServiceGenerator = NewIdsecSIADBStrongAccountsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
