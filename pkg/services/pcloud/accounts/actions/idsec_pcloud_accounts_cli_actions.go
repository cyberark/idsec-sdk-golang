package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the accounts action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "accounts",
		ActionDescription: "PCloud Accounts Management.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
