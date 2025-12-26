package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the infrastructure db action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "db",
		ActionDescription: "Infrastructure database policies management.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
