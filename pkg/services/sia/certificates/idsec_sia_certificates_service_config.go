package certificates

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siacertificatesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/actions"
)

// ServiceConfig is the configuration for the IdsecSIASSHCAService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-certificates",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siacertificatesactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siacertificatesactions.TerraformActionCertificateResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			siacertificatesactions.TerraformActionCertificateDataSource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA Certificates service.
var ServiceGenerator = NewIdsecSIACertificatesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
