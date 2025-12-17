package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the scans action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "scans",
		ActionDescription: "Sechub Scans.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
