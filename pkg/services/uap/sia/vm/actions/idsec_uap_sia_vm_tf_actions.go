package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	uapsiavmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/models"
)

// TerraformActionVMResource is a struct that defines the UAP SIA VM resource action for the Idsec service for Terraform.
var TerraformActionVMResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "uap-vm",
			ActionDescription: "SIA Virtual Machine (VM) policy resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{},
		ComputedAsSetAttributes: []string{
			"days_of_the_week",
		},
	},
	ReadSchemaPath:   "metadata",
	DeleteSchemaPath: "metadata",
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-policy",
		actions.ReadOperation:   "policy",
		actions.UpdateOperation: "update-policy",
		actions.DeleteOperation: "delete-policy",
	},
}

// TerraformActionVMDataSource is a struct that defines the UAP SIA VM data source action for the Idsec service for Terraform.
var TerraformActionVMDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "uap-vm",
			ActionDescription: "SIA Virtual Machine (VM) policy data source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{},
	},
	DataSourceAction: "policy",
}
