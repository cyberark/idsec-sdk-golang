package pcloud

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pcloudaccountsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/actions"
	pcloudplatformsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/actions"
	pcloudsafesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/actions"
)

// CLIAction is the CLI action definition for the identity service.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "pcloud",
		ActionDescription: "CyberArk Privilege Cloud is a SaaS solution that enables organizations to securely store, rotate and isolate credentials (for both human and non-human users), monitor sessions, and deliver scalable risk reduction to the business.",
		ActionVersion:     1,
	},
	ActionAliases: []string{"privilegecloud", "pc"},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		pcloudaccountsactions.CLIAction,
		pcloudsafesactions.CLIAction,
		pcloudplatformsactions.CLIAction,
	},
}

// ServiceConfig is the configuration for the identity service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud",
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
