package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the CMGR action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "cmgr",
		ActionDescription: "The Connector Management service mediates Identity Security Platform Shared Services (ISPSS) and is used by IT administrators to manage CyberArk components, communication tunnels, networks, and connector pools.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
	ActionAliases: []string{"connectormanager", "cm"},
}
