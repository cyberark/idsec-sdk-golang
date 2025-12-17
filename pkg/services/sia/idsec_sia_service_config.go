package sia

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siaaccessactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/actions"
	siacertificatesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/actions"
	siadbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/db/actions"
	siak8sactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/k8s/actions"
	siasecretsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets"
	siasettingsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/actions"
	siashortenedconnectionstringactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring/actions"
	siasshcaactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/actions"
	siassoactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/actions"
	siaworkspacesactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces"
)

// CLIAction is a struct that defines the SIA action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "sia",
		ActionDescription: "Secure infrastructure access provides a seamless, agentless SaaS solution for session management, ideal for securing privileged access to targets spread across hybrid and cloud environments. Session management with SIA allows access with Zero Standing Privileges (ZSP) or vaulted credentials",
		ActionVersion:     1,
	},
	ActionAliases: []string{"dpa"},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		siassoactions.CLIAction,
		siak8sactions.CLIAction,
		siaworkspacesactions.CLIAction,
		siasecretsactions.CLIAction,
		siaaccessactions.CLIAction,
		siasshcaactions.CLIAction,
		siadbactions.CLIAction,
		siashortenedconnectionstringactions.CLIAction,
		siasettingsactions.CLIAction,
		siacertificatesactions.CLIAction,
	},
}

// ServiceConfig is the configuration for the sia service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia",
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
