package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"
)

// TerraformActionApplicationResource is a struct that defines the pCloud application resource action for the Idsec service for Terraform.
var TerraformActionApplicationResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-application",
			ActionDescription: "pCloud application resource, manages pCloud applications information / metadata and credentials.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{},
		ComputedAttributes:      []string{},
		StateSchema:             &applicationsmodels.IdsecPCloudApplication{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "create-application",
		actions.ReadOperation:   "application",
		actions.DeleteOperation: "delete-application",
	},
}

// TerraformActionApplicationAuthMethodResource is a struct that defines the pCloud application auth method resource action for the Idsec service for Terraform.
var TerraformActionApplicationAuthMethodResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-application-auth-method",
			ActionDescription: "pCloud application auth method resource, manages pCloud application authentication methods information / metadata and credentials.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{},
		ComputedAttributes:      []string{},
		StateSchema:             &applicationsmodels.IdsecPCloudApplicationAuthMethod{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "create-application-auth-method",
		actions.ReadOperation:   "application-auth-method",
		actions.DeleteOperation: "delete-application-auth-method",
	},
}

// TerraformActionApplicationDataSource is a struct that defines the pCloud application data source action for the Idsec service for Terraform.
var TerraformActionApplicationDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-application",
			ActionDescription: "PCloud Application data source, reads application information and metadata, based on the id of the application.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{},
		StateSchema:             &applicationsmodels.IdsecPCloudApplication{},
	},
	DataSourceAction: "application",
}

// TerraformActionApplicationAuthMethodDataSource is a struct that defines the pCloud application auth method data source action for the Idsec service for Terraform.
var TerraformActionApplicationAuthMethodDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-application-auth-method",
			ActionDescription: "PCloud Application auth method data source, reads application authentication method information and metadata, based on the id of the application auth method.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{},
		StateSchema:             &applicationsmodels.IdsecPCloudApplicationAuthMethod{},
	},
	DataSourceAction: "application-auth-method",
}
