package sechub

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubconfigurationactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/configuration/actions"
	sechubfiltersactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/filters/actions"
	sechubsscansactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/scans/actions"
	sechubsecretsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secrets/actions"
	sechubsecretstoresactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/actions"
	sechubserviceinfoactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/serviceinfo/actions"
	sechubsyncpoliciesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/actions"
)

// CLIAction is a struct that defines the main SecHub action for the Idsec service CLI, encompassing all subactions.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "sechub",
		ActionDescription: "Secrets Hub is a CyberArk SaaS solution that simplifies managing and consuming secrets in the Cloud Service Providers’ native secret managers.",
		ActionVersion:     1,
	},
	ActionAliases: []string{"secretshub", "sh"},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		sechubconfigurationactions.CLIAction,
		sechubfiltersactions.CLIAction,
		sechubsscansactions.CLIAction,
		sechubsecretsactions.CLIAction,
		sechubsecretstoresactions.CLIAction,
		sechubserviceinfoactions.CLIAction,
		sechubsyncpoliciesactions.CLIAction,
	},
}

// ServiceConfig is the configuration for the main SecHub service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			CLIAction,
		},
	},
}

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
