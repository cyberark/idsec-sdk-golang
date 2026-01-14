package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	policiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies/models"
)

// TerraformActionPolicyResource is a struct that defines the Policy action for the Idsec service for Terraform.
var TerraformActionPolicyResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-policy",
			ActionDescription: "The Identity service policy resource that is used to manage policies.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &policiesmodels.IdsecIdentityPolicy{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "create-policy",
		actions.ReadOperation:   "policy",
		actions.UpdateOperation: "update-policy",
		actions.DeleteOperation: "delete-policy",
	},
}

// TerraformActionPolicyDataSource is a struct that defines the Policy action for the Idsec service for Terraform.
var TerraformActionPolicyDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-policy",
			ActionDescription: "The Identity service policy data source. It reads the policy information and metadata and is based on the ID of the policy.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &policiesmodels.IdsecIdentityPolicy{},
	},
	DataSourceAction: "policy",
}
