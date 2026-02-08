package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
)

// TerraformActionAccountResource is a struct that defines the Privilege Cloud account resource action for the Idsec service for Terraform.
var TerraformActionAccountResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-account",
			ActionDescription: "Manage Privilege Cloud account information, metadata, and credentials",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{},
		ComputedAttributes: []string{
			"status",
			"created_time",
			"category_modification_time",
			"secret_management.last_modified_time",
		},
		StateSchema: &accountsmodels.IdsecPCloudAccount{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-account",
		actions.ReadOperation:   "account",
		actions.UpdateOperation: "update-account",
		actions.DeleteOperation: "delete-account",
	},
}

// TerraformActionAccountDataSource is a struct that defines the Privilege Cloud account data source action for the Idsec service for Terraform.
var TerraformActionAccountDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-account",
			ActionDescription: "Privilege Cloud account data source, reads account information and metadata, based on the account ID.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"account_id",
		},
		StateSchema: &accountsmodels.IdsecPCloudAccount{},
	},
	DataSourceAction: "account",
}

// TerraformActionAccountCredentialsDataSource is a struct that defines the Privilege Cloud account credentials data source action for the Idsec service for Terraform.
var TerraformActionAccountCredentialsDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-account-credentials",
			ActionDescription: "Privilege Cloud account credentials data source, reads account credentials from vault, based on the account ID.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"account_id",
		},
		StateSchema: &accountsmodels.IdsecPCloudAccountCredentials{},
	},
	DataSourceAction: "account-credentials",
}
