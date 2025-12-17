package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the secrets action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "secrets",
		ActionDescription: "Sechub Secrets.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
