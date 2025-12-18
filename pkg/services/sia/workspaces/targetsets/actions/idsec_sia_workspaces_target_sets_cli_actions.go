package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA Workspace Target Sets action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "target-sets",
		ActionDescription: "The SIA workspaces target sets actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
