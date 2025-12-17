package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the service info action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "service-info",
		ActionDescription: "Sechub Service Info.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
