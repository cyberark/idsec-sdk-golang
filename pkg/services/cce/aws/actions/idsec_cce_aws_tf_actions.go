package actions

// import (
// 	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
// 	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
// )

// // TerraformActionOrganizationDataSource is a struct that defines the CCE AWS organization data source action for the Idsec service for Terraform.
// var TerraformActionOrganizationDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-organization",
// 			ActionDescription: "CCE AWS Organization datasource, reads organization details with services information based on the management account ID.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{
// 			"id",
// 		},
// 		StateSchema: &awsmodels.TfIdsecCCEAWSOrganizationDatasource{},
// 	},
// 	DataSourceAction: "tf-organization-datasource",
// }

// // TerraformActionOrganizationResource is a struct that defines the CCE AWS organization resource action for the Idsec service for Terraform.
// var TerraformActionOrganizationResource = &actions.IdsecServiceTerraformResourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-organization",
// 			ActionDescription: "CCE AWS Organization resource, manages AWS organization onboarding programmatically.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{
// 			"organization_root_id",
// 			"management_account_id",
// 			"organization_id",
// 			"services",
// 			"scan_organization_role_arn",
// 			"cross_account_role_external_id",
// 		},
// 		StateSchema: &awsmodels.TfIdsecCCEAWSOrganization{},
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
// 		actions.CreateOperation: "tf-add-organization",
// 		actions.ReadOperation:   "tf-organization",
// 		actions.UpdateOperation: "tf-update-organization",
// 		actions.DeleteOperation: "tf-delete-organization",
// 	},
// }

// // TerraformActionWorkspacesDataSource is a struct that defines the CCE AWS workspaces data source action for the Idsec service for Terraform.
// var TerraformActionWorkspacesDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-workspaces",
// 			ActionDescription: "CCE AWS Workspaces data source, retrieves AWS organizations and accounts with filtering.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &awsmodels.TfIdsecCCEAWSWorkspaces{},
// 	},
// 	DataSourceAction: "tf-workspaces",
// }

// // TerraformActionAccountResource is a struct that defines the CCE AWS account resource action for the Idsec service for Terraform.
// var TerraformActionAccountResource = &actions.IdsecServiceTerraformResourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-account",
// 			ActionDescription: "CCE AWS Account resource, manages AWS account onboarding programmatically.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{
// 			"account_id",
// 			"services",
// 		},
// 		StateSchema: &awsmodels.TfIdsecCCEAWSAccount{},
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
// 		actions.CreateOperation: "tf-add-account",
// 		actions.ReadOperation:   "tf-account",
// 		actions.UpdateOperation: "tf-update-account",
// 		actions.DeleteOperation: "tf-delete-account",
// 	},
// }

// var TerraformActionAccountDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-account",
// 			ActionDescription: "CCE AWS Account data source, reads account details based on the onboarding ID.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{
// 			"id",
// 		},
// 		StateSchema: &awsmodels.TfIdsecCCEAWSAccount{},
// 	},
// 	DataSourceAction: "tf-account",
// }

// // TerraformActionOrganizationAccountResource is a struct that defines the CCE AWS organization account resource action for the Idsec service for Terraform.
// var TerraformActionOrganizationAccountResource = &actions.IdsecServiceTerraformResourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-organization-account",
// 			ActionDescription: "CCE AWS Organization Account resource, adds AWS accounts to an organization.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{
// 			"parent_organization_id",
// 			"account_id",
// 			"services",
// 		},
// 		StateSchema: &awsmodels.TfIdsecCCEAWSAccount{},
// 	},
// 	RawStateInference: true,
// 	SupportedOperations: []actions.IdsecServiceActionOperation{
// 		actions.CreateOperation,
// 		actions.ReadOperation,
// 		actions.StateOperation,
// 	},
// 	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
// 		actions.CreateOperation: "tf-add-organization-account-sync",
// 		actions.ReadOperation:   "tf-account",
// 	},
// }

// // TerraformActionTenantServiceDetailsDataSource is a struct that defines the CCE AWS tenant service details data source action for the Idsec service for Terraform.
// var TerraformActionTenantServiceDetailsDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
// 	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
// 		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
// 			ActionName:        "cce-aws-tenant-service-details",
// 			ActionDescription: "CCE AWS Tenant Service Details data source, retrieves tenant service details.",
// 			ActionVersion:     1,
// 			Schemas:           ActionToSchemaMap,
// 		},
// 		ExtraRequiredAttributes: []string{},
// 		StateSchema:             &awsmodels.TfIdsecCCEAWSTenantServiceDetails{},
// 	},
// 	DataSourceAction: "tf-tenant-service-details",
// }
