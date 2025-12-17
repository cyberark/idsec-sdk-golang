package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA ListSettings action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "settings",
		ActionDescription: "SIA ListSettings Actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
