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

// IdsecPolicyK8sTarget contains fields shared by K8s policy targets.
type IdsecPolicyK8sTarget struct {
	RoleID        string `json:"role_id" validate:"required" mapstructure:"role_id" flag:"role-id" desc:"The unique identifier assigned to the role"`
	WorkspaceID   string `json:"workspace_id" validate:"required" mapstructure:"workspace_id" flag:"workspace-id" desc:"The unique identifier assigned to the workspace when it was onboarded to the platform"`
	RoleName      string `json:"role_name,omitempty" mapstructure:"role_name,omitempty" flag:"role-name" desc:"The role name for the eligible cluster target"`
	WorkspaceName string `json:"workspace_name,omitempty" mapstructure:"workspace_name,omitempty" flag:"workspace-name" desc:"The workspace name of the target"`
	Scope         string `json:"scope" validate:"required" mapstructure:"scope" flag:"scope" desc:"K8s target scope, for example cluster"`
	ClusterID     string `json:"cluster_id" validate:"required" mapstructure:"cluster_id" flag:"cluster-id" desc:"K8s cluster identifier"`
	NamespaceID   string `json:"namespace_id,omitempty" mapstructure:"namespace_id,omitempty" flag:"namespace-id" desc:"K8s namespace identifier"`
	FQDN          string `json:"fqdn,omitempty" mapstructure:"fqdn,omitempty" flag:"fqdn" desc:"K8s cluster endpoint"`
}

// AppendTo adds K8s fields to a serialized policy target.
func (s IdsecPolicyK8sTarget) AppendTo(result map[string]interface{}) {
	result["scope"] = s.Scope
	result["clusterId"] = s.ClusterID
	if s.NamespaceID != "" {
		result["namespaceId"] = s.NamespaceID
	}
	if s.FQDN != "" {
		result["fqdn"] = s.FQDN
	}
}

// IdsecPolicyK8sAWSAccountTarget represents an AWS K8s cluster policy target.
type IdsecPolicyK8sAWSAccountTarget struct {
	IdsecPolicyK8sTarget `mapstructure:",squash" desc:"AWS account target with IAM role ARN and account workspace ID"`
}

// Serialize converts an AWS K8s policy target into the API request payload shape.
func (s *IdsecPolicyK8sAWSAccountTarget) Serialize() (map[string]interface{}, error) {
	result := map[string]interface{}{
		"roleId":      s.RoleID,
		"workspaceId": s.WorkspaceID,
	}
	if s.RoleName != "" {
		result["roleName"] = s.RoleName
	}
	if s.WorkspaceName != "" {
		result["workspaceName"] = s.WorkspaceName
	}
	s.AppendTo(result)
	return result, nil
}

// Deserialize populates an AWS K8s policy target from serialized API data.
func (s *IdsecPolicyK8sAWSAccountTarget) Deserialize(data map[string]interface{}) error {
	deserializeK8sTarget(data, &s.IdsecPolicyK8sTarget)
	return nil
}

// IdsecPolicyK8sAzureTarget represents an Azure K8s cluster policy target.
type IdsecPolicyK8sAzureTarget struct {
	IdsecPolicyK8sTarget `mapstructure:",squash"`
	OrgID                string `json:"org_id" validate:"required" mapstructure:"org_id" flag:"org-id" desc:"The Azure directory ID (UUID) - required for Azure targets"`
	WorkspaceType        string `json:"workspace_type" validate:"required" mapstructure:"workspace_type" flag:"workspace-type" desc:"The level at which the Microsoft Entra ID workspace was onboarded to Idira" choices:"directory,subscription,resource_group,resource,management_group"`
	RoleType             int    `json:"role_type,omitempty" mapstructure:"role_type,omitempty" flag:"role-type" desc:"The type of the role in Azure"`
}

// Serialize converts an Azure K8s policy target into the API request payload shape.
func (s *IdsecPolicyK8sAzureTarget) Serialize() (map[string]interface{}, error) {
	result := map[string]interface{}{
		"roleId":        s.RoleID,
		"workspaceId":   s.WorkspaceID,
		"orgId":         s.OrgID,
		"workspaceType": s.WorkspaceType,
	}
	if s.RoleName != "" {
		result["roleName"] = s.RoleName
	}
	if s.WorkspaceName != "" {
		result["workspaceName"] = s.WorkspaceName
	}
	s.AppendTo(result)
	return result, nil
}

// Deserialize populates an Azure K8s policy target from serialized API data.
func (s *IdsecPolicyK8sAzureTarget) Deserialize(data map[string]interface{}) error {
	deserializeK8sTarget(data, &s.IdsecPolicyK8sTarget)
	if orgID, ok := data["org_id"].(string); ok {
		s.OrgID = orgID
	}
	if workspaceType, ok := data["workspace_type"].(string); ok {
		s.WorkspaceType = workspaceType
	}
	if roleType, ok := data["role_type"].(int); ok {
		s.RoleType = roleType
	}
	return nil
}

// IdsecPolicyK8sTargets contains the supported K8s cluster policy targets.
type IdsecPolicyK8sTargets struct {
	AwsAccountTargets []IdsecPolicyK8sAWSAccountTarget `json:"aws_account_targets,omitempty" mapstructure:"aws_account_targets,omitempty" flag:"aws-account-targets" desc:"AWS K8s cluster target details"`
	AzureTargets      []IdsecPolicyK8sAzureTarget      `json:"azure_targets,omitempty" mapstructure:"azure_targets,omitempty" flag:"azure-targets" desc:"Azure K8s cluster target details"`
}

// SerializeTargets converts all configured K8s policy targets into the API payload shape.
func (s *IdsecPolicyK8sTargets) SerializeTargets() (map[string]interface{}, error) {
	targets := make([]interface{}, 0)
	for _, target := range s.AwsAccountTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}
	for _, target := range s.AzureTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}
	return map[string]interface{}{"targets": targets}, nil
}

// DeserializeTargets populates K8s policy targets from serialized API data.
func (s *IdsecPolicyK8sTargets) DeserializeTargets(data map[string]interface{}) error {
	targetsData, ok := data["targets"].([]interface{})
	if !ok {
		return errors.New("invalid targets data format")
	}
	for _, targetData := range targetsData {
		targetMap, ok := targetData.(map[string]interface{})
		if !ok {
			return errors.New("invalid target data format")
		}
		if workspaceType, ok := targetMap["workspace_type"].(string); ok {
			switch workspaceType {
			case AzureWSTypeDirectory, AzureWSTypeSubscription, AzureWSTypeResourceGroup, AzureWSTypeResource, AzureWSTypeManagementGroup:
				var target IdsecPolicyK8sAzureTarget
				if err := target.Deserialize(targetMap); err != nil {
					return err
				}
				s.AzureTargets = append(s.AzureTargets, target)
			default:
				return errors.New("unknown workspace type in k8s targets")
			}
		} else if _, ok := targetMap["workspace_id"]; ok {
			var target IdsecPolicyK8sAWSAccountTarget
			if err := target.Deserialize(targetMap); err != nil {
				return err
			}
			s.AwsAccountTargets = append(s.AwsAccountTargets, target)
		} else {
			return errors.New("unknown target type in k8s targets")
		}
	}
	return nil
}

// ClearTargetsFromData removes K8s target fields from a serialized policy payload.
func (s *IdsecPolicyK8sTargets) ClearTargetsFromData(data map[string]interface{}) {
	delete(data, "aws_account_targets")
	delete(data, "awsAccountTargets")
	delete(data, "azure_targets")
	delete(data, "azureTargets")
}

func deserializeK8sTarget(data map[string]interface{}, target *IdsecPolicyK8sTarget) {
	if roleID, ok := data["role_id"].(string); ok {
		target.RoleID = roleID
	}
	if workspaceID, ok := data["workspace_id"].(string); ok {
		target.WorkspaceID = workspaceID
	}
	if roleName, ok := data["role_name"].(string); ok {
		target.RoleName = roleName
	}
	if workspaceName, ok := data["workspace_name"].(string); ok {
		target.WorkspaceName = workspaceName
	}
	if scope, ok := data["scope"].(string); ok {
		target.Scope = scope
	}
	if clusterID, ok := data["cluster_id"].(string); ok {
		target.ClusterID = clusterID
	}
	if namespaceID, ok := data["namespace_id"].(string); ok {
		target.NamespaceID = namespaceID
	}
	if fqdn, ok := data["fqdn"].(string); ok {
		target.FQDN = fqdn
	}
}
