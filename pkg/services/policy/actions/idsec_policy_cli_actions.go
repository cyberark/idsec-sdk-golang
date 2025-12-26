package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	policycloudaccessactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/actions"
	policydb "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/actions"
	policyvm "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/actions"
)

// CLIAction is a struct that defines the policy action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "policy",
		ActionDescription: "Access policies define when specified users may access particular assets and for how long. You may use access policies for cloud workspaces, virtual machines, and databases.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
	ActionAliases: []string{"accesspolicies", "acp"},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		policycloudaccessactions.CLIAction,
		policyvm.CLIAction,
		policydb.CLIAction,
	},
}
