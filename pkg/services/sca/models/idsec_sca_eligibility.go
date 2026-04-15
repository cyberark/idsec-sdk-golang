// Package models provides shared request/input structures for SCA eligibility operations.
// Response and target types are defined in the respective sub-service model packages:
//   - cloud-console types: pkg/services/sca/cloudconsole/models
//   - entragroups types:   pkg/services/sca/entragroups/models
package models

// IdsecSCAListTargetsRequest is the shared input for listing eligible targets.
// It is used by both the cloud-console and entragroups sub-services.
//
// The CSP is passed as a URL path parameter, not a query param.
// WorkspaceID is an optional filter; when provided the API returns only targets
// matching that workspace.
// Use Limit and NextToken for paginating through results (up to 50 per page).
//
// Fields:
//   - CSP:         Cloud service provider — AWS | AZURE | GCP (required).
//   - WorkspaceID: Optional workspace ID to filter eligible targets.
//   - Limit:       Maximum number of targets to return; up to 50.
//   - NextToken:   Pagination token from the previous response.
type IdsecSCAListTargetsRequest struct {
	CSP         string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"The cloud provider to list eligible targets for (AWS | AZURE | GCP)"`
	WorkspaceID string `json:"workspace_id,omitempty" mapstructure:"workspace_id,omitempty" flag:"workspace-id" desc:"Optional workspace ID to filter eligible targets"`
	Limit       int    `json:"limit,omitempty" mapstructure:"limit,omitempty" flag:"limit" desc:"The maximum number of targets to return in the response (up to 50)"`
	NextToken   string `json:"next_token,omitempty" mapstructure:"next_token,omitempty" flag:"next-token" desc:"The pagination token from the previous API response"`
}
