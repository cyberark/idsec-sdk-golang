package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	webappsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/models"
)

// TerraformActionWebappResource is a struct that defines the Webapps action for the Idsec service for Terraform.
var TerraformActionWebappResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp",
			ActionDescription: "The Identity service webapp resource that is used to manage webapps.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebapp{},
		ComputedAttributes: []string{
			"generic",
			"webapp_type",
			"state",
			"app_type_display_name",
			"category",
		},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "import-webapp",
		actions.ReadOperation:   "webapp",
		actions.UpdateOperation: "update-webapp",
		actions.DeleteOperation: "delete-webapp",
	},
}

// TerraformActionWebappPermissionResource is a struct that defines the Webapps action for the Idsec service for Terraform.
var TerraformActionWebappPermissionResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp-permission",
			ActionDescription: "The Identity service webapp permission resource that is used to manage webapp permissions.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebappPermission{},
		ComputedAsSetAttributes: []string{
			"rights",
		},
		ComputedAttributes: []string{
			"principal_id",
		},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-webapp-permissions",
		actions.ReadOperation:   "webapp-permissions",
		actions.UpdateOperation: "set-webapp-permissions",
	},
}

// TerraformActionWebappDataSource is a struct that defines the Webapp action for the Idsec service for Terraform.
var TerraformActionWebappDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp",
			ActionDescription: "The Identity service webapp data source. It reads the webapp information and metadata and is based on the ID of the webapp or its name.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebapp{},
	},
	DataSourceAction: "webapp",
}

// TerraformActionWebappPermissionsDataSource is a struct that defines the Webapp permissions action for the Idsec service for Terraform.
var TerraformActionWebappPermissionsDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp-permissions",
			ActionDescription: "The Identity service webapp permissions data source. It reads the webapp permissions information and metadata and is based on the ID of the webapp or its name.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebappPermissions{},
		ComputedAsSetAttributes: []string{
			"grants",
		},
	},
	DataSourceAction: "webapp-permissions",
}

// TerraformActionWebappPermissionDataSource is a struct that defines the Webapp permission action for the Idsec service for Terraform.
var TerraformActionWebappPermissionDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp-permission",
			ActionDescription: "The Identity service webapp permission data source. It reads the webapp permission information and metadata and is based on the ID of the webapp or its name.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebappPermission{},
		ComputedAsSetAttributes: []string{
			"rights",
		},
	},
	DataSourceAction: "webapp-permission",
}

// TerraformActionWebappTemplateDataSource is a struct that defines the Webapp template action for the Idsec service for Terraform.
var TerraformActionWebappTemplateDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp-template",
			ActionDescription: "The Identity service webapp template data source. It reads the webapp template information and metadata and is based on the ID of the webapp template or its name.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebappTemplate{},
	},
	DataSourceAction: "webapp-template",
}

// TerraformActionWebappCustomTemplateDataSource is a struct that defines the Webapp custom template action for the Idsec service for Terraform.
var TerraformActionWebappCustomTemplateDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-webapp-custom-template",
			ActionDescription: "The Identity service webapp custom template data source. It reads the webapp custom template information and metadata and is based on the ID of the webapp custom template or its name.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &webappsmodels.IdsecIdentityWebappTemplate{},
	},
	DataSourceAction: "webapp-custom-template",
}
