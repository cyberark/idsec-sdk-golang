package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the policies action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "policies",
		ActionDescription: "Identity management of policies.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
