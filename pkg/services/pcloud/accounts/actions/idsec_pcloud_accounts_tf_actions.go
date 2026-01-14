package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
)

// TerraformActionAccountResource is a struct that defines the pCloud account resource action for the Idsec service for Terraform.
var TerraformActionAccountResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-account",
			ActionDescription: "pCloud account resource, manages pCloud accounts information / metadata and credentials.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{},
		StateSchema:             &accountsmodels.IdsecPCloudAccount{},
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

// TerraformActionAccountDataSource is a struct that defines the pCloud account data source action for the Idsec service for Terraform.
var TerraformActionAccountDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-account",
			ActionDescription: "PCloud Account data source, reads account information and metadata, based on the id of the account.",
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
