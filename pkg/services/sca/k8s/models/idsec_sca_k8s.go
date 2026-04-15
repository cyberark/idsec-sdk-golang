// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAk8sListClustersRequest is the request schema for the list-clusters CLI action.
type IdsecSCAk8sListClustersRequest struct {
	CSP         string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"The cloud provider that hosts the workspace to discover (AWS | AZURE | GCP)"`
	WorkspaceID string `json:"workspace_id,omitempty" mapstructure:"workspace_id,omitempty" flag:"workspace-id" desc:"The ID of the workspace to discover (AWS - The AWS organization ID | AZURE: Microsoft Entra ID Directory (Tenant) ID | GCP: Google Cloud organization ID)"`
	Limit       int    `json:"limit,omitempty" mapstructure:"limit,omitempty" flag:"limit" desc:"Limit the number of clusters to list"`
	NextToken   string `json:"next_token,omitempty" mapstructure:"next_token,omitempty" flag:"next-token" desc:"The token to use to get the next page of clusters"`
}

// IdsecSCAk8sListClustersTarget represents the target details within an eligible workspace.
// IdsecSCAk8sListClustersRole represents the role object in the eligible target response.
type IdsecSCAk8sListClustersRole struct {
	ID          string  `json:"id" mapstructure:"id" desc:"IAM role ID (e.g., ARN) for this eligible target."`
	Name        string  `json:"name" mapstructure:"name" desc:"Role name for this eligible target."`
	Description *string `json:"description" mapstructure:"description" desc:"Optional description of the role."`
}

// IdsecSCAk8sListClustersTarget represents the target object, which describes the eligible K8s cluster.
type IdsecSCAk8sListClustersTarget struct {
	Scope       string  `json:"scope" mapstructure:"scope" desc:"Scope of the target (e.g., cluster)."`
	Region      string  `json:"region" mapstructure:"region" desc:"Cloud region (e.g., us-east-1)."`
	ClusterID   string  `json:"clusterId" mapstructure:"clusterId" desc:"ARN or ID of the cluster."`
	NamespaceID *string `json:"namespaceId" mapstructure:"namespaceId" desc:"Optional namespace ID when scope is namespace."`
	FQDN        *string `json:"fqdn" mapstructure:"fqdn" desc:"Fully qualified domain name of the cluster."`
}

// IdsecSCAk8sListClustersEligibleTarget represents an eligible workspace target in the response.
type IdsecSCAk8sListClustersEligibleTarget struct {
	OrganizationID *string                       `json:"organizationId" mapstructure:"organizationId" desc:"Optional organization ID (e.g., AWS org ID)."`
	WorkspaceID    string                        `json:"workspaceId" mapstructure:"workspaceId" desc:"The unique ID of the workspace."`
	WorkspaceName  string                        `json:"workspaceName" mapstructure:"workspaceName" desc:"The display name of the workspace."`
	WorkspaceType  string                        `json:"workspaceType" mapstructure:"workspaceType" desc:"Type of the workspace (e.g., account)."`
	Role           IdsecSCAk8sListClustersRole   `json:"role" mapstructure:"role" desc:"Role object for this eligible target."`
	Target         IdsecSCAk8sListClustersTarget `json:"target" mapstructure:"target" desc:"Target object describing the eligible K8s cluster."`
}

// IdsecSCAk8sListClustersResponse is the response for the list-clusters API.
type IdsecSCAk8sListClustersResponse struct {
	Response  []IdsecSCAk8sListClustersEligibleTarget `json:"response" mapstructure:"response" desc:"Array of eligible workspace targets."`
	NextToken *string                                 `json:"nextToken" mapstructure:"nextToken" desc:"Token for the next page of results (null when no more pages)."`
	Total     int                                     `json:"total" mapstructure:"total" desc:"The total number of targets you're eligible to access."`
}
