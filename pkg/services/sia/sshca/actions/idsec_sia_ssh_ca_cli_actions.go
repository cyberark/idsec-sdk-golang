package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA SSH CA action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "ssh-ca",
		ActionDescription: "The SIA SSH CA actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
