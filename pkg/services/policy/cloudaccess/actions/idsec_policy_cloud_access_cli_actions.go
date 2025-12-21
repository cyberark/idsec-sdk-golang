package actions

import "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

// CLIAction defines the Cloud Access policy command group for the Idsec CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "cloud-access",
		ActionDescription: "Cloud console access policy resource<br>Enables creating, viewing,editing, and deleting access policies to cloud services. <br>For more information about the schema parameters, see the <a href='https://api-docs.cyberark.com/uap-schema-api/docs/access-control-policies-api' target='_blank'>Access Control Policies API</a> documentation.",
		ActionVersion:     1,
		Schemas:           ActionToSchemaMap,
	},
}
