package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction is a struct that defines the uap sca action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "sca",
		ActionDescription: "Cloud console access policy resource<br>Enables creating, viewing,editing, and deleting access policies to cloud services. <br>For more information about the schema parameters, see the <a href='https://api-docs.cyberark.com/uap-schema-api/docs/access-control-policies-api' target='_blank'>Access Control Policies API</a> documentation.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
