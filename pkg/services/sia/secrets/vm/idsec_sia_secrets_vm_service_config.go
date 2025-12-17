package vmsecrets

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siasecretsvmactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/actions"
)

// ServiceConfig is the configuration for the SIA VM secrets service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-secrets-vm",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siasecretsvmactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siasecretsvmactions.TerraformActionSecretsVMResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			siasecretsvmactions.TerraformActionSecretsVMDataSource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA VM secrets service.
var ServiceGenerator = NewIdsecSIASecretsVMService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
