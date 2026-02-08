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
		ComputedAttributes: []string{
			"user_attributes",
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

// TerraformActionUserAttributesSchemaResource is a struct that defines the Users Attributes Schema action for the Idsec service for Terraform.
var TerraformActionUserAttributesSchemaResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-user-attributes-schema",
			ActionDescription: "The Identity service user attributes schema resource that is used to manage user attributes schema.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &usersmodels.IdsecIdentityUserAttributesSchema{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "upsert-user-attributes-schema",
		actions.ReadOperation:   "user-attributes-schema",
		actions.UpdateOperation: "upsert-user-attributes-schema",
		actions.DeleteOperation: "delete-user-attributes-schema",
	},
}

// TerraformActionUserAttributesResource is a struct that defines the Users Attributes action for the Idsec service for Terraform.
var TerraformActionUserAttributesResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-user-attributes",
			ActionDescription: "The Identity service user attributes resource that is used to manage user attributes.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &usersmodels.IdsecIdentityUserAttributes{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "upsert-user-attributes",
		actions.ReadOperation:   "user-attributes",
		actions.UpdateOperation: "upsert-user-attributes",
		actions.DeleteOperation: "delete-user-attributes",
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

// TerraformActionUserAttributesSchemaDataSource is a struct that defines the User Attributes Schema action for the Idsec service for Terraform.
var TerraformActionUserAttributesSchemaDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-user-attributes-schema",
			ActionDescription: "The Identity service user attributes schema data source. It reads the user attributes schema information and metadata and is based on the ID of the user attributes schema.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &usersmodels.IdsecIdentityUserAttributesSchema{},
	},
	DataSourceAction: "user-attributes-schema",
}

// TerraformActionUserAttributesDataSource is a struct that defines the User Attributes action for the Idsec service for Terraform.
var TerraformActionUserAttributesDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-user-attributes",
			ActionDescription: "The Identity service user attributes data source. It reads the user attributes information and metadata and is based on the ID of the user attributes.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &usersmodels.IdsecIdentityUserAttributes{},
	},
	DataSourceAction: "user-attributes",
}
