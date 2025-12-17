package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the configuration action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "configuration",
		ActionDescription: "Sechub Configuration.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
