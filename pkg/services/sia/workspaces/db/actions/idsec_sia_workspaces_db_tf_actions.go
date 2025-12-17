package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
)

// TerraformActionWorkspacesDBResource is a struct that defines the SIA workspaces db resource action for the Idsec service for Terraform.
var TerraformActionWorkspacesDBResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-workspaces-db",
			ActionDescription: "SIA Workspaces DB resource, manages DB workspaces information and metadata, along with association to relevant secret.",
			ActionVersion:     1,
			Schemas:           TargetActionToTargetSchemaMap,
		},
		StateSchema: &workspacesdbmodels.IdsecSIADBDatabaseTarget{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-database-target",
		actions.ReadOperation:   "database-target",
		actions.UpdateOperation: "update-database-target",
		actions.DeleteOperation: "delete-database-target",
	},
}

// TerraformActionWorkspacesDBDataSource is a struct that defines the sia workspaces db data source action for the Idsec service for Terraform.
var TerraformActionWorkspacesDBDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-workspaces-db",
			ActionDescription: "SIA Workspaces DB data source, reads DB information and metadata, based on the id of the database.",
			ActionVersion:     1,
			Schemas:           TargetActionToTargetSchemaMap,
		},
		StateSchema: &workspacesdbmodels.IdsecSIADBDatabaseTarget{},
	},
	DataSourceAction: "database-target",
}
