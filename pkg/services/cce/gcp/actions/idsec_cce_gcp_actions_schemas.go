package actions

import (
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
)

// ActionToSchemaMap is a map that defines the mapping between CCE GCP action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	// Identity Params data source
	"tf-identity-params": &gcpmodels.TfIdsecCCEGCPGetIdentityParams{},
	// Workspaces data source
	"tf-workspaces": &gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{},
	// Project actions
	"tf-project":        &gcpmodels.TfIdsecCCEGCPGetProject{},
	"tf-add-project":    &gcpmodels.TfIdsecCCEGCPAddProject{},
	"tf-update-project": &gcpmodels.TfIdsecCCEGCPUpdateProject{},
	"tf-delete-project": &gcpmodels.TfIdsecCCEGCPDeleteProject{},
	// Organization actions
	"tf-add-organization":    &gcpmodels.TfIdsecCCEGCPAddOrganization{},
	"tf-organization":        &gcpmodels.TfIdsecCCEGCPGetOrganization{},
	"tf-update-organization": &gcpmodels.TfIdsecCCEGCPUpdateOrganization{},
	"tf-delete-organization": &gcpmodels.TfIdsecCCEGCPDeleteOrganization{},
}
