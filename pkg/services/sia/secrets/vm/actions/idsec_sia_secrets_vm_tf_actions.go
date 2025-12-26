package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	secretsvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"
)

// TerraformActionSecretsVMResource is a struct that defines the SIA secrets vm resource action for the Idsec service for Terraform.
var TerraformActionSecretsVMResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-secrets-vm",
			ActionDescription: "The SIA Secrets VM resource, manages VM Secrets information and metadata, based on the type of Secret.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		SensitiveAttributes: []string{
			"provisioner_password",
			"secret_data",
		},
		StateSchema: &secretsvmmodels.IdsecSIAVMSecret{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-secret",
		actions.ReadOperation:   "secret",
		actions.UpdateOperation: "change-secret",
		actions.DeleteOperation: "delete-secret",
	},
}

// TerraformActionSecretsVMDataSource is a struct that defines the sia secrets vm data source action for the Idsec service for Terraform.
var TerraformActionSecretsVMDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-secrets-vm",
			ActionDescription: "The SIA Secrets VM data source, reads VM Secrets information and metadata, based on the ID of the Secret.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &secretsvmmodels.IdsecSIAVMSecret{},
	},
	DataSourceAction: "secret",
}
