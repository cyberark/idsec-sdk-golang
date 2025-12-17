package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
)

// CLIAction is a struct that defines the SIA Secrets DB action for the Idsec service for the CLI.
// It uses ActionToSchemaMap which includes both secrets and strong account actions.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "db",
		ActionDescription: "SIA Secrets DB Actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
