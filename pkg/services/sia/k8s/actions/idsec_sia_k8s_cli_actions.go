package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the SIA K8S action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "k8s",
		ActionDescription: "The SIA Kubernetes (K8s) actions.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
