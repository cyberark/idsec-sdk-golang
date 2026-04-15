// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAK8sElevateTarget describes a single cluster-role target for elevation.
//
// Either FQDN alone OR (WorkspaceID + TargetID) must be provided.
// Exactly one of RoleID or RoleName must be provided.
type IdsecSCAK8sElevateTarget struct {
	WorkspaceID string `json:"workspaceId,omitempty"`
	RoleID      string `json:"roleId,omitempty"`
	RoleName    string `json:"roleName,omitempty"`
	TargetID    string `json:"targetId,omitempty"` // EKS cluster ARN; used with WorkspaceID
	FQDN        string `json:"fqdn,omitempty"`     // cluster endpoint; alternative to WorkspaceID+TargetID
}

// IdsecSCAK8sElevateRequest is the POST body sent to api/access/elevate/clusters.
//
// OrganizationID is optional and not relevant for AWS IAM; omit it for standard use.
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
// No ExpirationTime field is present; TTL is managed per-CSP via IdsecSCAK8sTokenProvider.ElevateTTL.
type IdsecSCAK8sElevateResult struct {
	WorkspaceID       string `json:"workspaceId"`
	RoleID            string `json:"roleId,omitempty"`
	RoleName          string `json:"roleName,omitempty"`
	SessionID         string `json:"sessionId"`
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
// Field mapping to kubeconfig args (AWS kubeconfig always uses --fqdn):
//
//	--csp           → CSP (required)
//	--role-id       → RoleID (IAM role ARN; one of role-id or role-name required)
//	--role-name     → RoleName (human-readable name; alternative to role-id)
//	--fqdn          → FQDN (cluster API endpoint; always used in kubeconfig)
//	--target-id     → TargetID (EKS cluster ARN; alternative cluster identifier with --workspace-id)
//	--workspace-id  → WorkspaceID (optional; only needed with --target-id)
//	--tenant-id     → TenantID (Azure Entra tenant ID for future AKS/kubelogin support)
//
// Region and cluster name are derived from the targetId field in the elevate API response.
type IdsecSCAK8sElevateKubectlRequest struct {
	CSP         string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (AWS | AZURE)"`
	RoleID      string `json:"role_id,omitempty" mapstructure:"role_id,omitempty" flag:"role-id" desc:"IAM role ARN (AWS); provide either --role-id or --role-name"`
	RoleName    string `json:"role_name,omitempty" mapstructure:"role_name,omitempty" flag:"role-name" desc:"IAM role name; provide either --role-id or --role-name"`
	FQDN        string `json:"fqdn,omitempty" mapstructure:"fqdn,omitempty" flag:"fqdn" desc:"Cluster API endpoint FQDN (always used in kubeconfig; alternative to --target-id + --workspace-id)"`
	TargetID    string `json:"target_id,omitempty" mapstructure:"target_id,omitempty" flag:"target-id" desc:"EKS cluster ARN; alternative cluster identifier used with --workspace-id"`
	WorkspaceID string `json:"workspace_id,omitempty" mapstructure:"workspace_id,omitempty" flag:"workspace-id" desc:"AWS account ID or Azure subscription ID (optional when --fqdn is provided)"`
	TenantID    string `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" flag:"tenant-id" desc:"Azure Entra tenant ID (for future AKS support via kubelogin)"`
}
