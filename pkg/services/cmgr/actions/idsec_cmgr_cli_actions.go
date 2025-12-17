package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the CMGR action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "cmgr",
		ActionDescription: "Connector Management mediates ISPSS services and is used by IT administrators to manage CyberArk components, communication tunnels and manage networks and pools.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
	ActionAliases: []string{"connectormanager", "cm"},
}
