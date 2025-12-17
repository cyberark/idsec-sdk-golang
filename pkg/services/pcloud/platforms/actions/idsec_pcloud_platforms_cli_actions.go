package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the platforms action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "platforms",
		ActionDescription: "PCloud Platforms Management.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
