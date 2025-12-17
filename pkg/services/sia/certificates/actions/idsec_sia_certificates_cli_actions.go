package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA certificates action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "certificates",
		ActionDescription: "SIA Certificates.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
