package models

import "errors"

// Azure workspace type constants define supported Azure scopes for K8s policy targets.
const (
	AzureWSTypeDirectory       = "directory"
	AzureWSTypeSubscription    = "subscription"
	AzureWSTypeResourceGroup   = "resource_group"
	AzureWSTypeResource        = "resource"
	AzureWSTypeManagementGroup = "management_group"
)

// IdsecPolicyK8sAzureTarget represents an Azure K8s cluster policy target (AKS-by-resource-id uses the full ARM resource ID in cluster_id).
type IdsecPolicyK8sAzureTarget struct {
	IdsecPolicyK8sSharedTarget `mapstructure:",squash"`
	RoleID                     string `json:"role_id" validate:"required" mapstructure:"role_id" flag:"role-id" desc:"The identifier of the Azure resource role (Azure resource ID) assigned to the policy members."`
	WorkspaceID                string `json:"workspace_id" validate:"required" mapstructure:"workspace_id" flag:"workspace-id" desc:"The unique identifier created for the AKS cluster (Azure resource) in Idira when it was connected."`
	RoleName                   string `json:"role_name,omitempty" mapstructure:"role_name,omitempty" flag:"role-name" desc:"The display name of the Azure resource role."`
	WorkspaceName              string `json:"workspace_name,omitempty" mapstructure:"workspace_name,omitempty" flag:"workspace-name" desc:"The display name of the AKS cluster in Idira."`
	OrgID                      string `json:"org_id" validate:"required" mapstructure:"org_id" flag:"org-id" desc:"Azure directory ID (UUID)."`
	WorkspaceType              string `json:"workspace_type" validate:"required" mapstructure:"workspace_type" flag:"workspace-type" desc:"The scope level at which the Microsoft Entra tenant was connected to Idira. For AKS clusters access policies, this value must be set to resource." choices:"directory,subscription,resource_group,resource,management_group"`
	ClusterID                  string `json:"cluster_id" validate:"required" mapstructure:"cluster_id" flag:"cluster-id" desc:"The unique identifier of the AKS cluster (Azure resource ID)."`
	ClusterName                string `json:"cluster_name,omitempty" mapstructure:"cluster_name,omitempty" flag:"cluster-name" desc:"The display name of the AKS cluster."`
	RoleType                   int    `json:"role_type,omitempty" mapstructure:"role_type,omitempty" flag:"role-type" desc:"Indicates whether the role is a built-in role ('0') or a custom role ('1')"`
}

// Serialize converts an Azure K8s policy target into the API request payload shape.
func (s *IdsecPolicyK8sAzureTarget) Serialize() (map[string]interface{}, error) {
	if err := validateAzureK8sTargetCore(s); err != nil {
		return nil, err
	}
	result := map[string]interface{}{
		"roleId":        s.RoleID,
		"workspaceId":   s.WorkspaceID,
		"orgId":         s.OrgID,
		"workspaceType": s.WorkspaceType,
		"clusterId":     s.ClusterID,
	}
	if s.RoleName != "" {
		result["roleName"] = s.RoleName
	}
	if s.WorkspaceName != "" {
		result["workspaceName"] = s.WorkspaceName
	}
	if s.ClusterName != "" {
		result["clusterName"] = s.ClusterName
	}
	if s.RoleType != 0 {
		result["roleType"] = s.RoleType
	}
	s.appendSharedTo(result)
	return result, nil
}

// Deserialize populates an Azure K8s policy target from serialized API data.
func (s *IdsecPolicyK8sAzureTarget) Deserialize(data map[string]interface{}) error {
	deserializeK8sSharedTarget(data, &s.IdsecPolicyK8sSharedTarget)
	s.RoleID = k8sTargetStringField(data, "role_id", "roleId")
	s.WorkspaceID = k8sTargetStringField(data, "workspace_id", "workspaceId")
	s.RoleName = k8sTargetStringField(data, "role_name", "roleName")
	s.WorkspaceName = k8sTargetStringField(data, "workspace_name", "workspaceName")
	s.OrgID = k8sTargetStringField(data, "org_id", "orgId")
	s.WorkspaceType = k8sTargetStringField(data, "workspace_type", "workspaceType")
	s.ClusterID = k8sTargetStringField(data, "cluster_id", "clusterId")
	s.ClusterName = k8sTargetStringField(data, "cluster_name", "clusterName")
	s.RoleType = k8sTargetIntField(data, "role_type", "roleType")
	return nil
}

// validateAzureK8sTargetCore enforces mandatory scope and cluster_id (AKS-by-resource-id uses full ARM resource ID in cluster_id).
func validateAzureK8sTargetCore(t *IdsecPolicyK8sAzureTarget) error {
	if t == nil {
		return errors.New("azure target is nil")
	}
	if t.Scope == "" {
		return errors.New("scope is required for Azure K8s targets")
	}
	if t.ClusterID == "" {
		return errors.New("cluster_id is required and must be the full Azure Resource Manager resource ID of the AKS cluster")
	}
	return nil
}
