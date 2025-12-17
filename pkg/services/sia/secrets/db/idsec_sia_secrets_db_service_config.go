package dbsecrets

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siasecretsdbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/actions"
)

// ServiceConfig is the configuration for the SIA DB secrets service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-secrets-db",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siasecretsdbactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siasecretsdbactions.TerraformActionDBStrongAccountResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			siasecretsdbactions.TerraformActionDBStrongAccountDataSource,
		},
	},
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
