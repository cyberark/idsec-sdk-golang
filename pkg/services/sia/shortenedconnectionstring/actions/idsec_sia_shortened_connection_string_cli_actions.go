package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA shortened connection string action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "shortened-connection-string",
		ActionDescription: "The SIA shortened connection string actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
