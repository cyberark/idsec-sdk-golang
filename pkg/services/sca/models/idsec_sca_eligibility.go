// Package models provides shared request/input structures for SCA eligibility operations.
// Response and target types are defined in the respective sub-service model packages:
//   - cloudaccess types:   pkg/services/sca/cloudaccess/models
//   - groupaccess types:   pkg/services/sca/groupaccess/models
package models

import "encoding/json"

// Supported cloud provider identifiers (uppercase API / wire form).
const (
	CSPAWS   = "AWS"
	CSPAzure = "AZURE"
	CSPGCP   = "GCP"
)

// ValidCloudAccessCSPs are the CSPs supported by the cloudaccess list-targets
// and all-CSPs aggregation paths. GCP is supported here but not in k8s list-targets.
var ValidCloudAccessCSPs = []string{CSPAWS, CSPAzure, CSPGCP}

// IdsecSCAListTargetsRequest is the shared input for listing eligible targets.
// It is used by both the cloudaccess and groupaccess sub-services.
//
// The CSP is passed as a URL path parameter, not a query param.
// WorkspaceID is an optional filter; when provided the API returns only targets
// matching that workspace.
// Use Limit and NextToken for paginating through results (up to 50 per page).
//
// Fields:
//   - CSP:         Cloud service provider — AWS | AZURE | GCP. When omitted, AWS, AZURE and GCP are queried.
//   - All:         When true, queries AWS, AZURE and GCP regardless of CSP.
//   - WorkspaceID: Optional workspace ID to filter eligible targets.
//   - Limit:       Maximum number of targets to return; up to 50.
//   - NextToken:   Pagination token from the previous response.
type IdsecSCAListTargetsRequest struct {
	CSP         string `json:"csp" mapstructure:"csp" flag:"csp" desc:"The cloud provider to list eligible targets for (AWS | AZURE | GCP). Omit to list AWS, AZURE and GCP targets."`
	All         bool   `json:"all,omitempty" mapstructure:"all,omitempty" flag:"all" desc:"List targets for all default CSPs (AWS, AZURE and GCP)."`
	WorkspaceID string `json:"workspace_id,omitempty" mapstructure:"workspace_id,omitempty" flag:"workspace-id" desc:"Optional workspace ID to filter eligible targets"`
	Limit       int    `json:"limit,omitempty" mapstructure:"limit,omitempty" flag:"limit" desc:"The maximum number of targets to return in the response (up to 50)"`
	NextToken   string `json:"next_token,omitempty" mapstructure:"next_token,omitempty" flag:"next-token" desc:"The pagination token from the previous API response"`
}

// IdsecSCAListTargetsErrors maps lowercase CSP name to the error returned while
// listing that provider.
type IdsecSCAListTargetsErrors map[string]string

// MarshalListTargetsAllCSPsJSON flattens per-CSP responses and errors into the
// top-level JSON shape returned by list-all operations.
func MarshalListTargetsAllCSPsJSON[T any](responses map[string]T, errors IdsecSCAListTargetsErrors) ([]byte, error) {
	result := make(map[string]interface{}, len(responses)+len(errors))
	for csp, response := range responses {
		result[csp] = response
	}
	for csp, err := range errors {
		result[csp] = err
	}
	return json.Marshal(result)
}
