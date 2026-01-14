package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the auth profiles action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "auth-profiles",
		ActionDescription: "Identity management of auth profiles.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
