// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAK8sElevateTarget describes a single cluster-role target in the Elevate API
// POST body (one element of targets[]).
type IdsecSCAK8sElevateTarget struct {
	RoleID    string `json:"roleId,omitempty"`
	FQDN      string `json:"fqdn,omitempty"`
	Namespace string `json:"namespace,omitempty"` // optional; Azure namespace-scoped targets (CLI: --namespace)
}

// IdsecSCAK8sElevateRequest is the POST body sent to api/access/elevate/clusters.
//
// OrganizationID is the Azure Entra Directory (tenant) ID or AWS organization
// ID; required for Azure and AWS organization targets.
//
// SessionID is the server-assigned refresh token (UUID) from a prior Elevate
// response. When set, the server returns a fresh EKS bearer token for the same
// session without starting a new one. Sent at the top-level of the body, not
// inside targets[]. Omitted (omitempty) for brand-new sessions.
type IdsecSCAK8sElevateRequest struct {
	CSP            string                     `json:"csp"`
	Targets        []IdsecSCAK8sElevateTarget `json:"targets"`
	OrganizationID string                     `json:"organizationId,omitempty"`
	SessionID      string                     `json:"sessionId,omitempty"`
}

// IdsecSCAK8sAWSAccessCredentials holds the short-lived AWS STS credentials
// returned inside the JSON-encoded accessCredentials string.
//
// The Elevate API returns accessCredentials as a JSON-encoded string, so a
// second json.Unmarshal call is required to extract these fields.
type IdsecSCAK8sAWSAccessCredentials struct {
	AWSAccessKey       string `json:"aws_access_key"`
	AWSSecretAccessKey string `json:"aws_secret_access_key" secret:"true"`
	AWSSessionToken    string `json:"aws_session_token" secret:"true"`
}

// IdsecSCAK8sElevateClientDetails carries AWS IAM Identity Center OIDC client
// metadata returned by the Elevate API for permission-set targets.
type IdsecSCAK8sElevateClientDetails struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret" secret:"true"`
	StartURL     string `json:"startUrl"`
	SSORegion    string `json:"ssoRegion"`
}

// IdsecSCAK8sElevateResult represents one result entry inside the Elevate response.
//
// AccessCredentials is a JSON-encoded string (double-encoded). For AWS IAM roles it contains
// IdsecSCAK8sAWSAccessCredentials. For Azure the field is empty or absent — elevation
// only grants permission in SCA; no cloud credentials are returned.
//
// EKSToken is a ready-to-use EKS bearer token (k8s-aws-v1.<base64url>) returned by the
// server for the AWS IAM direct flow. When present the CLI uses it directly without a
// client-side STS presign round-trip. The token embeds its own expiry via X-Amz-Date
// and X-Amz-Expires in the presigned URL.
//
// TargetID is the cloud-provider cluster identifier returned by the API (e.g. an EKS
// cluster ARN for AWS). For AWS, parse it with ParseEKSARN to extract region and cluster name.
//
// SessionID is a server-assigned refresh token (UUID). Pass it back in the next Elevate
// request to obtain a fresh EKS token without starting a new session.
//
// SessionExpTime is the SCA elevation session expiry (RFC3339/RFC3339Nano). The CLI uses
// this to decide when to drop the cached sessionId and start a brand-new session.
//
// OrganizationID mirrors the organizationId field from the Elevate response body for
// per-result convenience (same value as IdsecSCAK8sElevateResponseBody.OrganizationID).
type IdsecSCAK8sElevateResult struct {
	WorkspaceID       string                           `json:"workspaceId"`
	RoleID            string                           `json:"roleId,omitempty"`
	RoleName          string                           `json:"roleName,omitempty"`
	SessionID         string                           `json:"sessionId"`
	SessionExpTime    string                           `json:"sessionExpTime,omitempty"`
	AccessCredentials string                           `json:"accessCredentials,omitempty"`
	EKSToken          string                           `json:"eksToken,omitempty"`       // server-provided EKS bearer token (AWS IAM direct)
	OrganizationID    string                           `json:"organizationId,omitempty"` // mirrored from response body
	TargetID          string                           `json:"targetId,omitempty"`       // e.g. "arn:aws:eks:us-east-1:123:cluster/name"
	ClientDetails     *IdsecSCAK8sElevateClientDetails `json:"clientDetails,omitempty"`
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

// IdsecSCAK8sElevateKubectlRequest is the flat public input to Elevate() and the
// CLI schema (`idsec exec sca k8s elevate`). It is registered in ActionToSchemaMap
// so the schema framework generates cobra flags automatically.
//
// Relationship with IdsecSCAK8sElevateRequest: this struct is flat (one level) because
// the cobra/schema framework requires flat structs for flag generation. Elevate()
// translates it internally into the nested IdsecSCAK8sElevateRequest wire format
// (targets[] array + top-level sessionId) before sending it to the backend API.
// The two structs are intentionally separate — one is the public SDK surface, the
// other is the API wire contract.
//
// Required for all CSPs: CSP, FQDN, RoleID.
// Azure and AWS organization targets additionally use OrganizationID. Azure
// also supports optional Namespace.
//
// AWS region and cluster name are derived from targetId in the Elevate API response.
//
// SessionID is the server-assigned session refresh token from a prior Elevate response.
// When set, Elevate() forwards it to the API so the server can return a fresh EKS bearer
// token without starting a new session. Leave empty to start a brand-new session.
type IdsecSCAK8sElevateKubectlRequest struct {
	CSP            string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (AWS | AZURE)"`
	RoleID         string `json:"role_id,omitempty" mapstructure:"role_id,omitempty" flag:"role-id" desc:"Cloud role ID to elevate (AWS IAM role ARN or Azure role definition resource ID)"`
	FQDN           string `json:"fqdn,omitempty" mapstructure:"fqdn,omitempty" flag:"fqdn" desc:"Cluster API endpoint FQDN (always used in kubeconfig)"`
	OrganizationID string `json:"organization_id,omitempty" mapstructure:"organization_id,omitempty" flag:"organization-id" desc:"Azure Entra Directory ID (tenant) or AWS organization ID"`
	Namespace      string `json:"namespace,omitempty" mapstructure:"namespace,omitempty" flag:"namespace" desc:"Optional Kubernetes namespace (Azure)"`
	SessionID      string `json:"session_id,omitempty" mapstructure:"session_id,omitempty"`
}
