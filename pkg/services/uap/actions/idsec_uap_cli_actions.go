package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	uapsiadbactions "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/actions"
	uapsiavmactions "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/actions"
)

// CLIAction is a struct that defines the uap action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "uap",
		ActionDescription: "Access policies define when specified users may access particular assets and for how long. You can define access policies to cloud services, virtual machines, and databases.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
	ActionAliases: []string{"useraccesspolicies"},
	Subactions: []*actions.IdsecServiceCLIActionDefinition{
		uapsiadbactions.CLIAction,
		uapsiavmactions.CLIAction,
	},
}
