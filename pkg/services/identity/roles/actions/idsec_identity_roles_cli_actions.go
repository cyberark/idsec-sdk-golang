package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the roles action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "roles",
		ActionDescription: "Identity management of roles.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
