package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	policydbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/models"
)

// TerraformActionDBResource is a struct that defines the Infrastructure DB resource action for the Idsec service for Terraform.
var TerraformActionDBResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "policy-db",
			ActionDescription: "The infrastructure database policy resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &policydbmodels.IdsecPolicyDBAccessPolicy{},
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

// TerraformActionDBDataSource is a struct that defines the Infrastructure DB data source action for the Idsec service for Terraform.
var TerraformActionDBDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "policy-db",
			ActionDescription: "The infrastructure database policy data source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &policydbmodels.IdsecPolicyDBAccessPolicy{},
	},
	DataSourceAction: "policy",
}
