package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEAzureGetWorkspacesTerraform is the input for retrieving Azure workspaces for Terraform.
// This struct does not include pagination parameters as pagination is handled automatically.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/azure/workspaces
type TfIdsecCCEAzureGetWorkspacesTerraform struct {
	// ParentID filters workspaces to only those under the specified parent CCE onboarding ID.
	ParentID string `json:"parent_id,omitempty" mapstructure:"parent_id,omitempty" desc:"Filter by parent CCE onboarding ID"`
	// Services filters workspaces to only those deployed with the specified services, comma-separated (e.g., "dpa,sca").
	Services string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"Filter by services, comma-separated (e.g., dpa,sca)"`
	// WorkspaceStatus filters workspaces by their onboarding status, comma-separated (e.g., "Completely added,Failed to add,Partially added").
	WorkspaceStatus string `json:"workspace_status,omitempty" mapstructure:"workspace_status,omitempty" desc:"Filter by status, comma-separated (e.g., Completely added,Failed to add)"`
	// WorkspaceType filters workspaces by their type (e.g., "azure_organization", "azure_entra", "azure_management_group", "azure_subscription").
	WorkspaceType string `json:"workspace_type,omitempty" mapstructure:"workspace_type,omitempty" desc:"Filter by type (e.g., azure_organization, azure_entra, azure_management_group, azure_subscription)"`
}

// TfIdsecCCEAzureGetWorkspaces is the input for retrieving Azure workspaces with pagination.
// This is used internally for paginated API calls.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/azure/workspaces
type TfIdsecCCEAzureGetWorkspaces struct {
	// Page is the page number to fetch (1-minimum, default: 1).
	Page int `json:"page,omitempty" mapstructure:"page,omitempty" desc:"Page number to fetch (minimum: 1, default: 1)"`
	// PageSize is the number of items per page (default: 1000).
	PageSize int `json:"page_size,omitempty" mapstructure:"page_size,omitempty" desc:"Number of items per page (default: 1000)"`
	// ParentID filters workspaces to only those under the specified parent CCE onboarding ID.
	ParentID string `json:"parent_id,omitempty" mapstructure:"parent_id,omitempty" desc:"Filter by parent CCE onboarding ID"`
	// Services filters workspaces to only those deployed with the specified services, comma-separated (e.g., "dpa,sca").
	Services string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"Filter by services, comma-separated (e.g., dpa,sca)"`
	// WorkspaceStatus filters workspaces by their onboarding status, comma-separated (e.g., "Completely added,Failed to add,Partially added").
	WorkspaceStatus string `json:"workspace_status,omitempty" mapstructure:"workspace_status,omitempty" desc:"Filter by status, comma-separated (e.g., Completely added,Failed to add)"`
	// WorkspaceType filters workspaces by their type (e.g., "azure_organization", "azure_entra", "azure_management_group", "azure_subscription").
	WorkspaceType string `json:"workspace_type,omitempty" mapstructure:"workspace_type,omitempty" desc:"Filter by type (e.g., azure_organization, azure_entra, azure_management_group, azure_subscription)"`
}

// TfIdsecCCEAzureWorkspaces represents the output of retrieving Azure workspaces.
// Note: This struct does NOT include a Page field as all workspaces are returned in a single collection.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GetWorkspacesOutput
type TfIdsecCCEAzureWorkspaces struct {
	// Workspaces is the list of all workspaces retrieved across all pages.
	Workspaces []ccemodels.TfIdsecCCEWorkspace `json:"workspaces" mapstructure:"workspaces" desc:"List of all retrieved workspaces"`
}
