package actions

import (
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
)

// ActionToSchemaMap is a map that defines the mapping between CCE Azure action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	// Entra actions
	"tf-add-entra":    &azuremodels.TfIdsecCCEAzureAddEntra{},
	"tf-entra":        &azuremodels.TfIdsecCCEAzureGetEntra{},
	"tf-update-entra": &azuremodels.TfIdsecCCEAzureUpdateEntra{},
	"tf-delete-entra": &azuremodels.TfIdsecCCEAzureDeleteEntra{},

	// Management Group actions
	"tf-add-management-group":    &azuremodels.TfIdsecCCEAzureAddManagementGroup{},
	"tf-management-group":        &azuremodels.TfIdsecCCEAzureGetManagementGroup{},
	"tf-update-management-group": &azuremodels.TfIdsecCCEAzureUpdateManagementGroup{},
	"tf-delete-management-group": &azuremodels.TfIdsecCCEAzureDeleteManagementGroup{},

	// Subscription actions
	"tf-add-subscription":    &azuremodels.TfIdsecCCEAzureAddSubscription{},
	"tf-subscription":        &azuremodels.TfIdsecCCEAzureGetSubscription{},
	"tf-update-subscription": &azuremodels.TfIdsecCCEAzureUpdateSubscription{},
	"tf-delete-subscription": &azuremodels.TfIdsecCCEAzureDeleteSubscription{},

	// Workspaces data source
	"tf-workspaces": &azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform{},

	// Identity Params data source
	"tf-identity-params": &azuremodels.TfIdsecCCEAzureGetIdentityParams{},
}
