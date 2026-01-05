package actions

// import (
// 	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
// 	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
// )

// // TerraformActionEntraDataSource is a struct that defines the CCE Azure Entra data source action for the Idsec service for Terraform.
// var TerraformActionEntraDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-entra",
// 			ActionDescription: "CCE Azure Entra data source, reads Entra tenant details based on the onboarding ID.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureEntra{},
// 	},
// 	DataSourceAction: "tf-entra",
// }

// // TerraformActionEntraResource is a struct that defines the CCE Azure Entra resource action for the Idsec service for Terraform.
// var TerraformActionEntraResource = &actions.IdsecServiceTerraformResourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-entra",
// 			ActionDescription: "CCE Azure Entra resource, manages Azure Entra tenant onboarding manually.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureEntra{},
// 	},
// 	RawStateInference: true,
// 	SupportedOperations: []actions.IdsecServiceActionOperation{
// 		actions.CreateOperation,
// 		actions.ReadOperation,
// 		actions.UpdateOperation,
// 		actions.DeleteOperation,
// 		actions.StateOperation,
// 	},
// 	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
// 		actions.CreateOperation: "tf-add-entra",
// 		actions.ReadOperation:   "tf-entra",
// 		actions.UpdateOperation: "tf-update-entra",
// 		actions.DeleteOperation: "tf-delete-entra",
// 	},
// }

// // TerraformActionManagementGroupDataSource is a struct that defines the CCE Azure Management Group data source action for the Idsec service for Terraform.
// var TerraformActionManagementGroupDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-management-group",
// 			ActionDescription: "CCE Azure Management Group data source, reads Management Group details based on the onboarding ID.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureManagementGroup{},
// 	},
// 	DataSourceAction: "tf-management-group",
// }

// // TerraformActionManagementGroupResource is a struct that defines the CCE Azure Management Group resource action for the Idsec service for Terraform.
// var TerraformActionManagementGroupResource = &actions.IdsecServiceTerraformResourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-management-group",
// 			ActionDescription: "CCE Azure Management Group resource, manages Azure Management Group onboarding manually.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureManagementGroup{},
// 	},
// 	RawStateInference: true,
// 	SupportedOperations: []actions.IdsecServiceActionOperation{
// 		actions.CreateOperation,
// 		actions.ReadOperation,
// 		actions.UpdateOperation,
// 		actions.DeleteOperation,
// 		actions.StateOperation,
// 	},
// 	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
// 		actions.CreateOperation: "tf-add-management-group",
// 		actions.ReadOperation:   "tf-management-group",
// 		actions.UpdateOperation: "tf-update-management-group",
// 		actions.DeleteOperation: "tf-delete-management-group",
// 	},
// }

// // TerraformActionSubscriptionDataSource is a struct that defines the CCE Azure Subscription data source action for the Idsec service for Terraform.
// var TerraformActionSubscriptionDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-subscription",
// 			ActionDescription: "CCE Azure Subscription data source, reads Subscription details based on the onboarding ID.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureSubscription{},
// 	},
// 	DataSourceAction: "tf-subscription",
// }

// // TerraformActionSubscriptionResource is a struct that defines the CCE Azure Subscription resource action for the Idsec service for Terraform.
// var TerraformActionSubscriptionResource = &actions.IdsecServiceTerraformResourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-subscription",
// 			ActionDescription: "CCE Azure Subscription resource, manages Azure Subscription onboarding manually.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureSubscription{},
// 	},
// 	RawStateInference: true,
// 	SupportedOperations: []actions.IdsecServiceActionOperation{
// 		actions.CreateOperation,
// 		actions.ReadOperation,
// 		actions.UpdateOperation,
// 		actions.DeleteOperation,
// 		actions.StateOperation,
// 	},
// 	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
// 		actions.CreateOperation: "tf-add-subscription",
// 		actions.ReadOperation:   "tf-subscription",
// 		actions.UpdateOperation: "tf-update-subscription",
// 		actions.DeleteOperation: "tf-delete-subscription",
// 	},
// }

// // TerraformActionWorkspacesDataSource is a struct that defines the CCE Azure Workspaces data source action for the Idsec service for Terraform.
// var TerraformActionWorkspacesDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-workspaces",
// 			ActionDescription: "CCE Azure Workspaces data source, retrieves Azure workspaces with optional filtering.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureWorkspaces{},
// 	},
// 	DataSourceAction: "tf-workspaces",
// }

// // TerraformActionIdentityParamsDataSource is a struct that defines the CCE Azure Identity Params data source action for the Idsec service for Terraform.
// var TerraformActionIdentityParamsDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-azure-identity-params",
// 			ActionDescription: "CCE Azure Identity Params data source, retrieves Azure identity federation parameters for active services.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &azuremodels.TfIdsecCCEAzureIdentityParams{},
// 	},
// 	DataSourceAction: "tf-identity-params",
// }
