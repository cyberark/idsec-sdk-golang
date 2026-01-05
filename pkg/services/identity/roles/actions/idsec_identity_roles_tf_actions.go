package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

// TerraformActionRoleResource is a struct that defines the Roles action for the Idsec service for Terraform.
var TerraformActionRoleResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-role",
			ActionDescription: "The Identity service role resource that is used to manage roles.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &rolesmodels.IdsecIdentityRole{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "create-role",
		actions.ReadOperation:   "role",
		actions.UpdateOperation: "update-role",
		actions.DeleteOperation: "delete-role",
	},
}

// TerraformActionRoleMemberResource is a struct that defines the RoleMember action for the Idsec service for Terraform.
var TerraformActionRoleMemberResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-role-member",
			ActionDescription: "The Identity service role member resource that is used to manage role members.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &rolesmodels.IdsecIdentityRoleMember{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-member-to-role",
		actions.ReadOperation:   "role-member",
		actions.DeleteOperation: "remove-member-from-role",
	},
}

// TerraformActionRoleDataSource is a struct that defines the Role action for the Idsec service for Terraform.
var TerraformActionRoleDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-role",
			ActionDescription: "The Identity service role data source. It reads the role information and metadata and is based on the ID of the role.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &rolesmodels.IdsecIdentityRole{},
	},
	DataSourceAction: "role",
}

// TerraformActionRoleMemberDataSource is a struct that defines the RoleMember action for the Idsec service for Terraform.
var TerraformActionRoleMemberDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-role-member",
			ActionDescription: "The Identity service role member data source. It reads the role member information and metadata and is based on the ID of the role member.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &rolesmodels.IdsecIdentityRoleMember{},
	},
	DataSourceAction: "role-member",
}
