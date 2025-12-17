package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	targetsetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/targetsets/models"
)

// TerraformActionWorkspacesTargetSetsResource is a struct that defines the SIA workspaces target sets resource action for the Idsec service for Terraform.
var TerraformActionWorkspacesTargetSetsResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-workspaces-target-set",
			ActionDescription: "SIA Workspaces Target Set resource, manages target set information about one or more targets and how they are represented, along with association to relevant secret.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &targetsetsmodels.IdsecSIATargetSet{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-target-set",
		actions.ReadOperation:   "target-set",
		actions.UpdateOperation: "update-target-set",
		actions.DeleteOperation: "delete-target-set",
	},
}

// TerraformActionWorkspacesTargetSetsDataSource is a struct that defines the sia workspaces target sets data source action for the Idsec service for Terraform.
var TerraformActionWorkspacesTargetSetsDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-workspaces-target-set",
			ActionDescription: "SIA Workspaces Target Set data source, reads target set information and metadata, based on the id of the target set.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &targetsetsmodels.IdsecSIATargetSet{},
		ExtraRequiredAttributes: []string{
			"id",
		},
	},
	DataSourceAction: "target-set",
}
