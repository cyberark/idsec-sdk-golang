package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
)

// TerraformActionAuthProfileResource is a struct that defines the Auth Profiles action for the Idsec service for Terraform.
var TerraformActionAuthProfileResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-auth-profile",
			ActionDescription: "The Identity service auth profile resource that is used to manage auth profiles.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &authprofilesmodels.IdsecIdentityAuthProfile{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "create-auth-profile",
		actions.ReadOperation:   "auth-profile",
		actions.UpdateOperation: "update-auth-profile",
		actions.DeleteOperation: "delete-auth-profile",
	},
}

// TerraformActionAuthProfileDataSource is a struct that defines the AuthProfile action for the Idsec service for Terraform.
var TerraformActionAuthProfileDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-auth-profile",
			ActionDescription: "The Identity service auth profile data source. It reads the auth profile information and metadata and is based on the ID of the auth profile.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &authprofilesmodels.IdsecIdentityAuthProfile{},
	},
	DataSourceAction: "auth-profile",
}
