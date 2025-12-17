package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA shortened connection string action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "shortened-connection-string",
		ActionDescription: "SIA Shortened Connection String Actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
