package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the uap sia vm action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "vm",
		ActionDescription: "UAP SIA VM Policies Management.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
