// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAK8sElevateTarget describes a single cluster-role target in the Elevate API
// POST body (one element of targets[]).
type IdsecSCAK8sElevateTarget struct {
	RoleID      string `json:"roleId,omitempty"`
	FQDN        string `json:"fqdn,omitempty"`
	NamespaceID string `json:"namespace,omitempty"` // optional; Azure namespace-scoped targets (CLI: --namespaceId)
}

// IdsecSCAK8sElevateRequest is the POST body sent to api/access/elevate/clusters.
//
// OrganizationID is the Azure Entra Directory (tenant) ID or AWS organization
// ID; required for Azure and AWS organization targets.
type IdsecSCAK8sElevateRequest struct {
	CSP            string                     `json:"csp"`
	Targets        []IdsecSCAK8sElevateTarget `json:"targets"`
	OrganizationID string                     `json:"organizationId,omitempty"`
}

// IdsecSCAK8sAWSAccessCredentials holds the short-lived AWS STS credentials
// returned inside the JSON-encoded accessCredentials string.
//
// The Elevate API returns accessCredentials as a JSON-encoded string, so a
// second json.Unmarshal call is required to extract these fields.
type IdsecSCAK8sAWSAccessCredentials struct {
	AWSAccessKey       string `json:"aws_access_key"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
	AWSSessionToken    string `json:"aws_session_token"`
}

// IdsecSCAK8sElevateResult represents one result entry inside the Elevate response.
//
// AccessCredentials is a JSON-encoded string (double-encoded). For AWS it contains
// IdsecSCAK8sAWSAccessCredentials. For Azure the field is empty or absent — elevation
// only grants permission in SCA; no cloud credentials are returned.
//
// TargetID is the cloud-provider cluster identifier returned by the API (e.g. an EKS
// cluster ARN for AWS). For AWS, parse it with ParseEKSARN to extract region and cluster name.
//
// SessionExpTime is the SCA elevation session expiry (RFC3339/RFC3339Nano). Azure
// responses include this; the kubectl-login cache uses it with a refresh buffer
// instead of a fixed TTL. AWS may omit it — fallback TTL applies via ElevateTTL().
type IdsecSCAK8sElevateResult struct {
	WorkspaceID       string `json:"workspaceId"`
	RoleID            string `json:"roleId,omitempty"`
	RoleName          string `json:"roleName,omitempty"`
	SessionID         string `json:"sessionId"`
	SessionExpTime    string `json:"sessionExpTime,omitempty"`
	AccessCredentials string `json:"accessCredentials,omitempty"`
	TargetID          string `json:"targetId,omitempty"` // e.g. "arn:aws:eks:us-east-1:123:cluster/name"
}

// IdsecSCAK8sElevateResponseBody is the inner "response" object in the Elevate API reply.
type IdsecSCAK8sElevateResponseBody struct {
	OrganizationID string                     `json:"organizationId"`
	CSP            string                     `json:"csp"`
	Results        []IdsecSCAK8sElevateResult `json:"results"`
}

// IdsecSCAK8sElevateResponse is the top-level Elevate API reply.
type IdsecSCAK8sElevateResponse struct {
	Response IdsecSCAK8sElevateResponseBody `json:"response"`
}

// IdsecSCAK8sElevateKubectlRequest is the input for both the SDK Elevate() function
// and the CLI schema (`idsec exec sca k8s elevate`).
//
// Registered in ActionToSchemaMap so the schema framework generates cobra flags automatically.
// Elevate() accepts this flat struct and internally constructs the nested API body
// (IdsecSCAK8sElevateRequest) before calling the backend.
//
// Required for all CSPs: CSP, FQDN, RoleID.
// Azure and AWS organization targets additionally use OrganizationID. Azure
// also supports optional NamespaceID.
//
// AWS region and cluster name are derived from targetId in the Elevate API response.
type IdsecSCAK8sElevateKubectlRequest struct {
	CSP            string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (AWS | AZURE)"`
	RoleID         string `json:"role_id,omitempty" mapstructure:"role_id,omitempty" flag:"role-id" desc:"Cloud role ID to elevate (AWS IAM role ARN or Azure role definition resource ID)"`
	FQDN           string `json:"fqdn,omitempty" mapstructure:"fqdn,omitempty" flag:"fqdn" desc:"Cluster API endpoint FQDN (always used in kubeconfig)"`
	OrganizationID string `json:"organization_id,omitempty" mapstructure:"organization_id,omitempty" flag:"organization-id" desc:"Azure Entra Directory ID (tenant) or AWS organization ID"`
	NamespaceID    string `json:"namespace_id,omitempty" mapstructure:"namespace_id,omitempty" flag:"namespace-id" desc:"Optional Kubernetes namespace identifier (Azure)"`
}
