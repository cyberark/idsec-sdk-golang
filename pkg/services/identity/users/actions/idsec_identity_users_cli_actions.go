package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the roles action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "users",
		ActionDescription: "Identity management of users.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMapIdentityUsers,
	},
}
