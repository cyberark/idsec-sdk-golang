package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SM action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "sm",
		ActionDescription: "The CyberArk Audit space centralizes session monitoring across all CyberArk services on the Shared Services platform to provide a comprehensive display of all sessions as a unified view. This enables enhanced auditing as well as incident-response investigation.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
	ActionAliases: []string{"sessionmonitoring"},
}
