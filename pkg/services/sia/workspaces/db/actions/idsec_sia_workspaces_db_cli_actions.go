package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA Workspaces DB action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "db",
		ActionDescription: "The SIA workspaces database actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
