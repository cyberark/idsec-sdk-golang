package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the webapps action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "webapps",
		ActionDescription: "Identity management of webapps.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
