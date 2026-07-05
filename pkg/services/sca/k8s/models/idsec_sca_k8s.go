// Package models provides data structures for the SCA k8s service.
package models

import (
	"encoding/json"

	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// Supported cloud provider identifiers (uppercase API / wire form).
const (
	CSPAWS   = "AWS"
	CSPAzure = "AZURE"
)

// IdsecSCAK8sDpaSsoAcquireResponse is the JSON body from POST /api/adb/sso/acquire
// for DPA-K8S short-lived client certificates (SCA proxy flow).
type IdsecSCAK8sDpaSsoAcquireResponse struct {
	Token    IdsecSCAK8sDpaSsoAcquireToken    `json:"token" mapstructure:"token" desc:"Short-lived client certificate material issued by DPA SSO acquire."`
	Metadata IdsecSCAK8sDpaSsoAcquireMetadata `json:"metadata" mapstructure:"metadata" desc:"Session and tenant metadata for the acquired certificate."`
}

// IdsecSCAK8sDpaSsoAcquireToken holds the certificate and key returned in the acquire response token object.
type IdsecSCAK8sDpaSsoAcquireToken struct {
	ClientCertificate string `json:"client_certificate" mapstructure:"client_certificate" desc:"PEM-encoded client certificate for the DPA K8s proxy."`
	PrivateKey        string `json:"private_key" mapstructure:"private_key" desc:"PEM-encoded private key matching client_certificate."`
}

// IdsecSCAK8sDpaSsoAcquireMetadata holds DPA SSO session metadata from the acquire response.
// Proxy credential caching uses expires_at; other fields are retained for future use.
type IdsecSCAK8sDpaSsoAcquireMetadata struct {
	Username            string  `json:"username" mapstructure:"username" desc:"Identity that requested the short-lived certificate."`
	Service             string  `json:"service" mapstructure:"service" desc:"DPA service identifier (e.g. DPA-K8S)."`
	TokenType           string  `json:"token_type" mapstructure:"token_type" desc:"Token type issued by acquire (e.g. client_certificate)."`
	ClientIP            string  `json:"client_ip" mapstructure:"client_ip" desc:"Client IP address recorded for the SSO session."`
	SessionID           *string `json:"session_id" mapstructure:"session_id" desc:"DPA SSO session identifier, when present."`
	TenantID            string  `json:"tenant_id" mapstructure:"tenant_id" desc:"CyberArk tenant identifier."`
	TenantIdentityURL   string  `json:"tenant_identity_url" mapstructure:"tenant_identity_url" desc:"Identity service URL for the tenant."`
	TenantSubdomain     string  `json:"tenant_subdomain" mapstructure:"tenant_subdomain" desc:"Tenant subdomain (e.g. uapcce)."`
	CreatedAt           string  `json:"created_at,omitempty" mapstructure:"created_at" desc:"Certificate session creation time (API format, UTC implied when zone omitted)."`
	ExpiresAt           string  `json:"expires_at" mapstructure:"expires_at" desc:"Certificate session expiry time; used for proxy ExecCredential and keyring cache TTL."`
	CurrentUsageCount   int     `json:"current_usage_count" mapstructure:"current_usage_count" desc:"Current usage count for the issued token."`
	MaxUsageCount       int     `json:"max_usage_count" mapstructure:"max_usage_count" desc:"Maximum allowed usage count for the issued token."`
	ClientIPEnforced    bool    `json:"client_ip_enforced" mapstructure:"client_ip_enforced" desc:"Whether client IP binding is enforced for this session."`
	TrustedToken        bool    `json:"trusted_token" mapstructure:"trusted_token" desc:"Whether the acquire request used a trusted token path."`
	TrustedIP           *string `json:"trusted_ip" mapstructure:"trusted_ip" desc:"Trusted IP associated with the session, when present."`
	TokenDifferentiator *string `json:"token_differentiator" mapstructure:"token_differentiator" desc:"Optional token differentiator from the acquire request."`
}

// IdsecSCAk8sListClustersRequest is the request schema for the list-clusters CLI action.
type IdsecSCAk8sListClustersRequest struct {
	CSP         string `json:"csp" mapstructure:"csp" flag:"csp" desc:"The cloud provider that hosts the workspace to discover (AWS | AZURE). Omit to list AWS and AZURE targets."`
	All         bool   `json:"all,omitempty" mapstructure:"all,omitempty" flag:"all" desc:"List targets for all default CSPs (AWS and AZURE)."`
	WorkspaceID string `json:"workspace_id,omitempty" mapstructure:"workspace_id,omitempty" flag:"workspace-id" desc:"The ID of the workspace to discover (AWS - The AWS organization ID | AZURE: Microsoft Entra ID Directory (Tenant) ID)"`
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
	Response  []IdsecSCAk8sListClustersEligibleTarget    `json:"response" mapstructure:"response" desc:"Array of eligible workspace targets."`
	Responses map[string]IdsecSCAk8sListClustersResponse `json:"-" mapstructure:"responses" desc:"Targets grouped by CSP when listing all cloud providers."`
	NextToken *string                                    `json:"nextToken" mapstructure:"nextToken" desc:"Token for the next page of results (null when no more pages)."`
	Total     int                                        `json:"total" mapstructure:"total" desc:"The total number of targets you're eligible to access."`
	Errors    scamodels.IdsecSCAListTargetsErrors        `json:"-" mapstructure:"errors" desc:"Per-CSP errors returned when listing all cloud providers."`
}

func (r IdsecSCAk8sListClustersResponse) MarshalJSON() ([]byte, error) {
	if len(r.Responses) == 0 && len(r.Errors) == 0 {
		type alias IdsecSCAk8sListClustersResponse
		return json.Marshal(alias(r))
	}

	return scamodels.MarshalListTargetsAllCSPsJSON(r.Responses, r.Errors)
}
