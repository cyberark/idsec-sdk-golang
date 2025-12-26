package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the infrastructure vm action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "vm",
		ActionDescription: "Infrastructure Virtual Machine (VM) policies management.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
