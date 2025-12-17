package actions

import (
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
)

// ActionToSchemaMap is a map that defines the mapping between CCE AWS action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{

	"tf-organization":                  &awsmodels.TfIdsecCCEAWSGetOrganization{},
	"tf-organization-datasource":       &awsmodels.TfIdsecCCEAWSGetOrganization{},
	"tf-add-organization":              &awsmodels.TfIdsecCCEAWSAddOrganization{},
	"tf-update-organization":           &awsmodels.TfIdsecCCEAWSUpdateOrganization{},
	"tf-delete-organization":           &awsmodels.TfIdsecCCEAWSGetOrganization{},
	"tf-workspaces":                    &awsmodels.TfIdsecCCEAWSGetWorkspacesTerraform{},
	"tf-add-account":                   &awsmodels.TfIdsecCCEAWSAddAccount{},
	"tf-update-account":                &awsmodels.TfIdsecCCEAWSUpdateAccount{},
	"tf-account":                       &awsmodels.TfIdsecCCEAWSGetAccount{},
	"tf-delete-account":                &awsmodels.TfIdsecCCEAWSDeleteAccount{},
	"tf-add-organization-account-sync": &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{},
	"tf-tenant-service-details":        &awsmodels.TfIdsecCCEAWSGetTenantServiceDetails{},
}
