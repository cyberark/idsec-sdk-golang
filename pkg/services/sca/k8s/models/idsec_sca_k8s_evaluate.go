// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAK8sEvaluateTarget is a single target in the evaluate request payload.
//
// Either FQDN or Name must be provided; when both are present, the API uses FQDN.
// FQDN is unique per CSP; Name may match multiple clusters.
type IdsecSCAK8sEvaluateTarget struct {
	FQDN string `json:"fqdn,omitempty"`
	Name string `json:"name,omitempty"`
}

// IdsecSCAK8sEvaluateRequest is the POST body for the eligibility evaluation API.
//
// If Targets is empty the API returns all eligible clusters (paginated).
type IdsecSCAK8sEvaluateRequest struct {
	Targets []IdsecSCAK8sEvaluateTarget `json:"targets"`
}

// IdsecSCAK8sEvaluateResult is a single entry in the evaluate response.
//
// It extends the standard eligible-target shape (role, target, workspace) with
// ConnectionMethod which determines how the CLI connects to the cluster.
type IdsecSCAK8sEvaluateResult struct {
	OrganizationID *string                       `json:"organizationId"`
	WorkspaceID    string                        `json:"workspaceId"`
	WorkspaceName  string                        `json:"workspaceName"`
	WorkspaceType  string                        `json:"workspaceType"`
	Role           IdsecSCAk8sListClustersRole   `json:"role"`
	Target         IdsecSCAk8sListClustersTarget `json:"target"`

	// ConnectionMethod indicates how the user should connect: "direct" or "proxy".
	ConnectionMethod string `json:"connectionMethod"`
}

// IdsecSCAK8sEvaluateResponse is the top-level evaluate API reply.
type IdsecSCAK8sEvaluateResponse struct {
	Response  []IdsecSCAK8sEvaluateResult `json:"response"`
	Total     int                         `json:"total"`
	NextToken *string                     `json:"nextToken"`
}
