package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	secretsdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/models"
)

// TerraformActionDBStrongAccountResource is a struct that defines the SIA DB strong account resource action for the Idsec service for Terraform.
// This resource supports only DB strong accounts, not secrets.
var TerraformActionDBStrongAccountResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-strong-accounts",
			ActionDescription: "The SIA strong accounts resource, manages strong account information and metadata.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		SensitiveAttributes: []string{
			"password",
			"secret_access_key",
		},
		StateSchema: &secretsdbmodels.IdsecSIADBSecretMetadata{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-strong-account",
		actions.ReadOperation:   "strong-account",
		actions.UpdateOperation: "update-strong-account",
		actions.DeleteOperation: "delete-strong-account",
	},
}

// TerraformActionDBStrongAccountDataSource is a struct that defines the SIA DB strong account data source action for the Idsec service for Terraform.
// This data source supports only DB strong accounts, not secrets.
var TerraformActionDBStrongAccountDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-strong-accounts",
			ActionDescription: "The SIA strong accounts data source, reads strong account information and metadata, based on the ID of the account.",
			ActionVersion:     1,
			Schemas:           StrongAccountActionToSchemaMap,
		},
		SensitiveAttributes: []string{
			"password",
			"secret_access_key",
		},
		StateSchema: &secretsdbmodels.IdsecSIADBDatabaseStrongAccount{},
	},
	DataSourceAction: "strong-account",
}
