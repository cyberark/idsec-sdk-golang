package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"
)

// TerraformActionUserResource is a struct that defines the Users action for the Idsec service for Terraform.
var TerraformActionUserResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		SensitiveAttributes: []string{
			"password",
		},
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-user",
			ActionDescription: "The Identity service user resource that is used to manage users.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &usersmodels.IdsecIdentityUser{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "create-user",
		actions.ReadOperation:   "user",
		actions.UpdateOperation: "update-user",
		actions.DeleteOperation: "delete-user",
	},
}

// TerraformActionUserDataSource is a struct that defines the User action for the Idsec service for Terraform.
var TerraformActionUserDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-user",
			ActionDescription: "The Identity service user data source. It reads the user information and metadata and is based on the ID of the user.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &usersmodels.IdsecIdentityUser{},
	},
	DataSourceAction: "user",
}
