package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
)

// TerraformActionCloudAccessResource defines the Cloud Access policy resource for Terraform.
var TerraformActionCloudAccessResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "policy-cloud-access",
			ActionDescription: "Cloud Access Policy resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{},
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

// TerraformActionCloudAccessDataSource defines the Cloud Access policy data source for Terraform.
var TerraformActionCloudAccessDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "policy-cloud-access",
			ActionDescription: "Cloud Access Policy data source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{},
	},
	DataSourceAction: "policy",
}
