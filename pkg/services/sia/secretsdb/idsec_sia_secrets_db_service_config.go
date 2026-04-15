package dbsecrets

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsdb/actions"
)

// ServiceConfig is the configuration for the SIA DB secrets service.
// Note: This service uses the legacy secrets API. For strong accounts, use the sia-db-strong-accounts service instead.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-secrets-db",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that creates a new instance of the SIA DB secrets service.
var ServiceGenerator = NewIdsecSIASecretsDBService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
