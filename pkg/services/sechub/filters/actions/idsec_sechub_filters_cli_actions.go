package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the filters action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "filters",
		ActionDescription: "Sechub Filters.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
