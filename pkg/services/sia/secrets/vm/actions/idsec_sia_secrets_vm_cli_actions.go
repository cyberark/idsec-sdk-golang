package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA Secrets VM action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "vm",
		ActionDescription: "SIA Secrets VM Actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
