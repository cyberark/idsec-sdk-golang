package sshca

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siasshcaactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/actions"
)

// ServiceConfig is the configuration for the IdsecSIASSHCAService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-ssh-ca",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siasshcaactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siasshcaactions.TerraformActionSSHPublicKeyResource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA SSH CA service.
var ServiceGenerator = NewIdsecSIASSHCAService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
