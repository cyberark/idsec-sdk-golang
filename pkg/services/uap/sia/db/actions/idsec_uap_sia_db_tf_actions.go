package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	uapsiadbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/models"
)

// TerraformActionDBResource is a struct that defines the UAP SIA DB resource action for the Idsec service for Terraform.
var TerraformActionDBResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "uap-db",
			ActionDescription: "The SIA database policy resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &uapsiadbmodels.IdsecUAPSIADBAccessPolicy{},
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

// TerraformActionDBDataSource is a struct that defines the UAP SIA DB data source action for the Idsec service for Terraform.
var TerraformActionDBDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "uap-db",
			ActionDescription: "The SIA database policy data source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &uapsiadbmodels.IdsecUAPSIADBAccessPolicy{},
	},
	DataSourceAction: "policy",
}
