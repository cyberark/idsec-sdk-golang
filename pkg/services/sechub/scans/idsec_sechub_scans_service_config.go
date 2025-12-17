package scans

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubsscansactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/scans/actions"
)

// ServiceConfig is the configuration for the Secrets Hub scans service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-scans",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			sechubsscansactions.CLIAction,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SecHub scans service.
var ServiceGenerator = NewIdsecSecHubScansService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
