package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the Directories action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "directories",
		ActionDescription: "Identity management of directories.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
