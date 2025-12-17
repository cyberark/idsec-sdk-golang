package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the secret stores action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "secret-stores",
		ActionDescription: "Sechub Secret Stores.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
